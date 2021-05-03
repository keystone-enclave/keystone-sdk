//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Enclave.hpp"
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>
extern "C" {
#include "./keystone_user.h"
#include "common/sha3.h"
}
#include "ElfFile.hpp"
#include "hash_util.hpp"
#include <edge_call.h>

namespace Keystone {

Enclave::Enclave() {
  runtimeFile = NULL;
  enclaveFile = NULL;
}

Enclave::~Enclave() {
  if (runtimeFile) delete runtimeFile;
  if (enclaveFile) delete enclaveFile;
  destroy();
}

uint64_t
calculate_required_pages(uint64_t eapp_sz, uint64_t rt_sz) {
  uint64_t req_pages = 0;

  req_pages += ceil(eapp_sz / PAGE_SIZE);
  req_pages += ceil(rt_sz / PAGE_SIZE);

  /* FIXME: calculate the required number of pages for the page table.
   * We actually don't know how many page tables the enclave might need,
   * because the SDK never knows how its memory will be aligned.
   * Ideally, this should be managed by the driver.
   * For now, we naively allocate enough pages so that we can temporarily get
   * away from this problem.
   * 15 pages will be more than sufficient to cover several hundreds of
   * megabytes of enclave/runtime. */
  req_pages += 15;
  return req_pages;
}

/* This function will be deprecated when we implement freemem */
bool
Enclave::initStack(uintptr_t start, size_t size, bool is_rt, bool is_fork) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };
  uintptr_t high_addr    = ROUND_UP(start, PAGE_BITS);
  uintptr_t va_start_stk = ROUND_DOWN((high_addr - size), PAGE_BITS);
  int stk_pages          = (high_addr - va_start_stk) / PAGE_SIZE;

  for (int i = 0; i < stk_pages; i++) {
    if (!pMemory->allocPage(
            va_start_stk, (uintptr_t)nullpage,
            (is_rt ? RT_NOEXEC : USER_NOEXEC), is_fork))
      return false;

    va_start_stk += PAGE_SIZE;
  }

  return true;
}

bool
Enclave::mapElf(ElfFile* elf) {
  uintptr_t va;

  assert(elf);

  size_t num_pages =
      ROUND_DOWN(elf->getTotalMemorySize(), PAGE_BITS) / PAGE_SIZE;
  va = elf->getMinVaddr();

  if (pMemory->epmAllocVspace(va, num_pages) != num_pages) {
    ERROR("failed to allocate vspace\n");
    return false;
  }

  return true;
}

Error
Enclave::loadElf(ElfFile* elf, bool is_fork) {
  static char nullpage[PAGE_SIZE] = {
      0,
  };

  unsigned int mode = elf->getPageMode();
  for (unsigned int i = 0; i < elf->getNumProgramHeaders(); i++) {
    if (elf->getProgramHeaderType(i) != PT_LOAD) {
      continue;
    }

    uintptr_t start      = elf->getProgramHeaderVaddr(i);
    uintptr_t file_end   = start + elf->getProgramHeaderFileSize(i);
    uintptr_t memory_end = start + elf->getProgramHeaderMemorySize(i);
    char* src            = reinterpret_cast<char*>(elf->getProgramSegment(i));
    uintptr_t va         = start;

    /* FIXME: This is a temporary fix for loading iozone binary
     * which has a page-misaligned program header. */
    if (!IS_ALIGNED(va, PAGE_SIZE)) {
      size_t offset = va - PAGE_DOWN(va);
      size_t length = PAGE_UP(va) - va;
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page + offset, (const void*)src, length);
      if (!pMemory->allocPage(PAGE_DOWN(va), (uintptr_t)page, mode, is_fork))
        return Error::PageAllocationFailure;
      va += length;
      src += length;
    }

    /* first load all pages that do not include .bss segment */
    while (va + PAGE_SIZE <= file_end) {
      if (!pMemory->allocPage(va, (uintptr_t)src, mode, is_fork))
        return Error::PageAllocationFailure;

      src += PAGE_SIZE;
      va += PAGE_SIZE;
    }

    /* next, load the page that has both initialized and uninitialized segments
     */
    if (va < file_end) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*)src, (size_t)(file_end - va));
      if (!pMemory->allocPage(va, (uintptr_t)page, mode, is_fork))
        return Error::PageAllocationFailure;
      va += PAGE_SIZE;
    }

    /* finally, load the remaining .bss segments */
    while (va < memory_end) {
      if (!pMemory->allocPage(va, (uintptr_t)nullpage, mode, is_fork))
        return Error::PageAllocationFailure;
      va += PAGE_SIZE;
    }
  }

  return Error::Success;
}

Error
Enclave::validate_and_hash_enclave(struct runtime_params_t args) {
  hash_ctx_t hash_ctx;
  int ptlevel = RISCV_PGLEVEL_TOP;

  hash_init(&hash_ctx);

  // hash the runtime parameters
  hash_extend(&hash_ctx, &args, sizeof(struct runtime_params_t));

  uintptr_t runtime_max_seen = 0;
  uintptr_t user_max_seen    = 0;

  // hash the epm contents including the virtual addresses
  int valid = pMemory->validateAndHashEpm(
      &hash_ctx, ptlevel, reinterpret_cast<pte*>(pMemory->getRootPageTable()),
      0, 0, &runtime_max_seen, &user_max_seen);

  if (valid == -1) {
    return Error::InvalidEnclave;
  }

  hash_finalize(hash, &hash_ctx);

  return Error::Success;
}

bool
Enclave::initFiles(const char* eapppath, const char* runtimepath) {
  if (runtimeFile || enclaveFile) {
    ERROR("ELF files already initialized");
    return false;
  }

  runtimeFile = new ElfFile(runtimepath);
  enclaveFile = new ElfFile(eapppath);

  if (!runtimeFile->initialize(true)) {
    ERROR("Invalid runtime ELF\n");
    destroy();
    return false;
  }

  if (!enclaveFile->initialize(false)) {
    ERROR("Invalid enclave ELF\n");
    destroy();
    return false;
  }

  if (!runtimeFile->isValid()) {
    ERROR("runtime file is not valid");
    destroy();
    return false;
  }
  if (!enclaveFile->isValid()) {
    ERROR("enclave file is not valid");
    destroy();
    return false;
  }

  return true;
}

bool
Enclave::prepareEnclave(uintptr_t alternatePhysAddr) {
  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE;
  minPages += calculate_required_pages(
      enclaveFile->getTotalMemorySize(), runtimeFile->getTotalMemorySize());

  if (params.isSimulated()) {
    pMemory->init(0, 0, minPages);
    return true;
  }

  /* Call Enclave Driver */
  if (pDevice->create(minPages, 0) != Error::Success) {
    return false;
  }

  /* We switch out the phys addr as needed */
  uintptr_t physAddr;
  if (alternatePhysAddr) {
    physAddr = alternatePhysAddr;
  } else {
    physAddr = pDevice->getPhysAddr();
  }

  pMemory->init(pDevice, physAddr, minPages);
  return true;
}

Error
Enclave::init(const char* eapppath, const char* runtimepath, Params _params) {
  return this->init(eapppath, runtimepath, _params, (uintptr_t)0);
}

const char*
Enclave::getHash() {
  return this->hash;
}

Error
Enclave::init(
    const char* eapppath, const char* runtimepath, Params _params,
    uintptr_t alternatePhysAddr) {
  params = _params;

  if (params.isSimulated()) {
    pMemory = new SimulatedEnclaveMemory();
    pDevice = new MockKeystoneDevice();
  } else {
    pMemory = new PhysicalEnclaveMemory();
    pDevice = new KeystoneDevice();
  }

  if (!initFiles(eapppath, runtimepath)) {
    return Error::FileInitFailure;
  }

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  if (!prepareEnclave(alternatePhysAddr)) {
    destroy();
    return Error::DeviceError;
  }

  if (!mapElf(runtimeFile)) {
    destroy();
    return Error::VSpaceAllocationFailure;
  }

  pMemory->startRuntimeMem();

  if (loadElf(runtimeFile, false) != Error::Success) {
    ERROR("failed to load runtime ELF");
    destroy();
    return Error::ELFLoadFailure;
  }

  if (!mapElf(enclaveFile)) {
    destroy();
    return Error::VSpaceAllocationFailure;
  }

  pMemory->startEappMem();


  if (loadElf(enclaveFile, params.getFork()) != Error::Success) {
      ERROR("failed to load enclave ELF");
      destroy();
      return Error::ELFLoadFailure;
  }

/* initialize stack. If not using freemem */
#ifndef USE_FREEMEM
  if (!initStack(DEFAULT_STACK_START, DEFAULT_STACK_SIZE, 0, params.getFork())) {
    ERROR("failed to init static stack");
    destroy();
    return Error::PageAllocationFailure;
  }
#endif /* USE_FREEMEM */

  uintptr_t utm_free;
  utm_free = pMemory->allocUtm(params.getUntrustedSize());

  if (!utm_free) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  struct runtime_params_t runtimeParams;
  runtimeParams.runtime_entry =
      reinterpret_cast<uintptr_t>(runtimeFile->getEntryPoint());
  runtimeParams.user_entry =
      reinterpret_cast<uintptr_t>(enclaveFile->getEntryPoint());
  runtimeParams.untrusted_ptr = reinterpret_cast<uintptr_t>(utm_free);
  runtimeParams.untrusted_size =
      reinterpret_cast<uintptr_t>(params.getUntrustedSize());
  memcpy(&runtimeParams.regs, (void *) params.getRegs(), sizeof(struct regs));

  pMemory->startFreeMem();

  /* TODO: This should be invoked with some other function e.g., measure() */
  if (params.isSimulated()) {
    validate_and_hash_enclave(runtimeParams);
  }

  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), runtimeParams) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return Error::DeviceMemoryMapError;
  }
  //}

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  enclaveFile = NULL;
  runtimeFile = NULL;
  return Error::Success;
}

bool
Enclave::mapUntrusted(size_t size) {
  if (size == 0) {
    return true;
  }

  shared_buffer = pDevice->map(0, size);

  if (shared_buffer == NULL) {
    return false;
  }

  shared_buffer_size = size;

  return true;
}

Error
Enclave::destroy() {
  if (enclaveFile) {
    delete enclaveFile;
    enclaveFile = NULL;
  }

  if (runtimeFile) {
    delete runtimeFile;
    runtimeFile = NULL;
  }


  Error ret = pDevice->destroy();
  deleteSnapshots();

  return ret;
}

/* */
struct proc_snapshot *
handle_fork(void* buffer){
  struct edge_call* edge_call = (struct edge_call*)buffer;

  uintptr_t call_args;
  unsigned long ret_val;
  size_t args_len;

  if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
    return NULL;
  }

  call_args = edge_call_data_ptr();

  struct proc_snapshot *ret = (struct proc_snapshot *) malloc(sizeof(struct proc_snapshot) + PAGE_SIZE);
  memcpy(ret, (void *) call_args, sizeof(struct proc_snapshot) + PAGE_SIZE);

  return ret;
}

Error
Enclave::run(uintptr_t* retval) {
  if (params.isSimulated()) {
    return Error::Success;
  }

  Error ret = pDevice->run(retval);

  while (true)
  {
    switch (ret) {
      case Error::Success:
        return Error::Success;
      case Error::EnclaveInterrupted:
        break;
      case Error::EdgeCallHost:
        {
          if (oFuncDispatch) {
            oFuncDispatch(getSharedBuffer());
          }
          break;
        }
      case Error::EnclaveSnapshot:
        {
          int eid = pDevice->getEID();
          addSnapshot(eid);

          //printf("[clone] %d\n", eid);


          // Create new
          pDevice->create(minPages, 1);
          uintptr_t utm_free = pMemory->allocUtm(params.getUntrustedSize());
          pMemory->init(pDevice, pDevice->getPhysAddr(), minPages);

          // printf("Enclave root PT: %p\n", pMemory->getRootPageTable());

          if (!mapUntrusted(params.getUntrustedSize())) {
            ERROR(
                "failed to finalize enclave - cannot obtain the untrusted buffer "
                "pointer \n");
          }

          struct keystone_ioctl_create_enclave_snapshot encl;
          encl.snapshot_eid = eid;
          encl.epm_paddr    = pDevice->getPhysAddr();
          encl.epm_size     = PAGE_SIZE * minPages;
          encl.utm_paddr    = utm_free;
          encl.utm_size     = params.getUntrustedSize();

          pDevice->clone_enclave(encl);

          break;
        }
      case Error::EnclaveForkRequested:
      {
          int pid;
          int parent_fds[2];
          int child_fds[2];

          //Create bi-directional pipelines
          pipe(parent_fds);
          pipe(child_fds);

          pid = fork();

          if(pid == 0){
            close(parent_fds[0]);
            close(child_fds[1]);

            int comm[2];
            comm[0] = child_fds[0];
            comm[1] = parent_fds[1];

            struct proc_snapshot *snapshot = handle_fork(getSharedBuffer());
            if(!snapshot){
              //Snapshot was invalid
              return Error::DeviceError;
            }

            size_t untrusted_size = 2 * 1024 * 1024;
            size_t freemem_size   = 450 * 1024 * 1024;
            uintptr_t utm_ptr     = (uintptr_t)DEFAULT_UNTRUSTED_PTR;

            Keystone::Enclave enclave;
            Keystone::Params params;

            params.setFork();
            params.setForkComm(comm);
            params.setFreeMemSize(freemem_size);
            params.setUntrustedMem(utm_ptr, untrusted_size);

            //Set user register state
            // params.setRegs(&snapshot->ctx.regs);

            enclave.init("hello", "eyrie-rt", params);

            int child_eid = enclave.pDevice->getEID();

            //First signal sent to parent
            write(parent_fds[1], &child_eid, sizeof(int));

            edge_call_init_internals((uintptr_t)enclave.getSharedBuffer(), enclave.getSharedBufferSize());
            enclave.placeSnapshot(snapshot);

            // Place register state into the enclave
            // Should include signature
            uintptr_t encl_ret;
            enclave.run(&encl_ret);

            printf("%ld\n", encl_ret);
            //Last write signal sent to parent
            write(parent_fds[1], &encl_ret, sizeof(int));

            //Send eid to the parent enclave
            //Exit the child enclave
            exit(0);

          } else {
            close(child_fds[0]);
            close(parent_fds[1]);

            int dummy_result;
            int child_eid;
            // printf("wait for child\n");
            //Parent enclave blocks until child process receives eid
            size_t result = read(parent_fds[0], &child_eid, sizeof(int));
            // printf("[parent sdk] Parent received child_eid: %d, message size: %d\n", child_eid, result);

            //Parent blocks until it can send the payload;
            read(parent_fds[0], &dummy_result, sizeof(int));

            // printf("[parent sdk] dummy_result: %d\n", dummy_result);

            struct edge_call* edge_call = (struct edge_call*)shared_buffer;
            uintptr_t call_args;
            size_t args_len;

            Error err;
            while(Error::EnclaveForkRequestDone != (err = pDevice->resume(retval))){

                if(err != Error::EnclaveForkRequestedMore){
                  continue;
                }

                //Signal to child process that payload is sent
                // printf("[sdk parent] Received signal from enclave to send to child\n");

                if (edge_call_args_ptr(edge_call, &call_args, &args_len) != 0) {
                    //Error with getting payload
                    edge_call->return_data.call_status = CALL_STATUS_BAD_OFFSET;
                    return Error::DeviceError;
                }
                // printf("[sdk parent] payload: size: %d\n", args_len);
                write(child_fds[1], &args_len, sizeof(size_t));

                call_args = edge_call_data_ptr();
                size_t bytes_written = 0;
                size_t bytes_written_iter = 0;

                while(bytes_written < args_len){
                  bytes_written_iter = write(child_fds[1], (void *) call_args + bytes_written, args_len - bytes_written);
                  bytes_written += bytes_written_iter;
                }

                // printf("[sdk parent] sent write_byte: %d\n", bytes_written);

                //Block until child processes the payload
                read(child_fds[0], &dummy_result, sizeof(int));
            }


            // printf("[sdk parent] Done with payload sent!\n");


            if(result == -1){
              ERROR("failed to receive child enclave id when forking");
              destroy();
              return Error::DeviceError;
            }

            //printf("child_eid: %d\n", child_eid);

            read(parent_fds[0], &dummy_result, sizeof(int));

            //printf("[parent] Child is done\n");

            ret = pDevice->resume_fork(retval, child_eid);
            continue;
          }

          break;

      }
      case Error::EnclaveForkRequestedMore:
      {
        // printf("[sdk] In request more \n");
        struct edge_call* edge_call = (struct edge_call*) shared_buffer;
        edge_call->call_id = 1337;
        uintptr_t buffer_data_start = edge_call_data_ptr();

        int x = 133;
        //Signal parent enclave to send more data
        //2nd messsage child sends
        write(params.getParentWriteFD(), &x, sizeof(int));
        //Place payload snapshot

        size_t payload_size = 0;
        //Get incoming payload size
        read(params.getParentReadFD(), &payload_size, sizeof(size_t));
        // printf("[child sdk] received payload size from parent: %d\n", payload_size);

        //Block until parent sends data
        size_t bytes_read = 0;
        size_t bytes_read_iter = 0;
        while(bytes_read < payload_size) {
          bytes_read_iter = read(params.getParentReadFD(), (void *) buffer_data_start + bytes_read, payload_size - bytes_read);
          bytes_read += bytes_read_iter;
          // printf("[child sdk] receieved from parent: %d, bytes_read_iter: %d\n", bytes_read, bytes_read_iter);
        }
        // printf("child sdk before setup call\n");
        if(edge_call_setup_call(edge_call, (void*)buffer_data_start, bytes_read) != 0){
            return Error::DeviceError;
        }
        // printf("[child sdk] DONE child bytes_read: %d / %d\n", bytes_read, payload_size);
        break;
      }
      default:
        {
          ERROR("failed to run enclave - error code: %ld", ret);
          destroy();
          return Error::DeviceError;
        }
    } /* switch */
    ret = pDevice->resume(retval);
  } /* while */

  return Error::Success;
}

void*
Enclave::getSharedBuffer() {
  return shared_buffer;
}

size_t
Enclave::getSharedBufferSize() {
  return shared_buffer_size;
}

Error
Enclave::registerOcallDispatch(OcallFunc func) {
  oFuncDispatch = func;
  return Error::Success;
}


void
Enclave::addSnapshot(int snapshot_eid){
    snapshot_lst.push_front(snapshot_eid);
}

void
Enclave::deleteSnapshots(){

  while(!snapshot_lst.empty()){
    pDevice->destroySnapshot(snapshot_lst.front());
    snapshot_lst.pop_front();
  }
}

Error
Enclave::deleteSnapshot(int snapshot_eid){
  for (const auto& eid : snapshot_lst) {
    if(snapshot_eid == eid){
      pDevice->destroySnapshot(eid);
      return Error::Success;
    }
  }
  return Error::SnapshotInvalid;
}

Error
Enclave::placeSnapshot(struct proc_snapshot *snapshot){
   /* For now we assume by convention that the start of the buffer is
   * the right place to put calls */
  struct edge_call* edge_call = (struct edge_call*) shared_buffer;

  /* We encode the call id, copy the argument data into the shared
   * region, calculate the offsets to the argument data, and then
   * dispatch the ocall to host */

  edge_call->call_id = 1337;

  uintptr_t buffer_data_start = edge_call_data_ptr();
  if((sizeof(struct proc_snapshot)  + PAGE_SIZE) > (shared_buffer_size - (buffer_data_start - (uintptr_t) shared_buffer))){
    goto ocall_error;
  }
  memcpy((void*)buffer_data_start, (void*)snapshot, PAGE_SIZE + sizeof(struct proc_snapshot));
  // printf("[sdk placeSnapshot] snapshot->size: %d\n", snapshot->size);

  if(edge_call_setup_call(edge_call, (void*)buffer_data_start, PAGE_SIZE + sizeof(struct proc_snapshot)) != 0){
    goto ocall_error;
  }

  return Error::SnapshotInvalid;

  ocall_error:
    return Error::Success;
}

}  // namespace Keystone
