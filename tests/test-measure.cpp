//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <iostream>
#include <cstdio>
#include <string>
#include "keystone.h"
#include "edge_wrapper.h"
#include "report.h"
#include "test_dev_key.h"

const char* longstr = "hellohellohellohellohellohellohellohellohellohello";

unsigned long print_buffer(char* str){
  printf("Enclave said: %s",str);
  return strlen(str);
}

void print_value(unsigned long val){
  printf("Enclave said value: %u\n",val);
  return;
}

const char* get_host_string(){
  return longstr;
}

static struct report_t report;

void print_hex(void* buffer, size_t len)
{
  int i;
  for(i = 0; i < len; i+=sizeof(uintptr_t))
  {
    printf("%.16lx ", *((uintptr_t*) ((uintptr_t)buffer + i)));
  }
  printf("\n");
}

void copy_report(void* buffer)
{
  Report report;

  report.fromBytes((unsigned char*)buffer);

  if (report.checkSignaturesOnly(_sanctum_dev_public_key))
  {
    printf("Attestation report SIGNATURE is valid\n");
  }
  else
  {
    printf("Attestation report is invalid\n");
  }
}

int main(int argc, char** argv)
{
  if(argc < 3)
  {
    printf("Usage: %s <eapp> <runtime>\n", argv[0]);
    return 0;
  }

  Keystone enclave;
  Params params;

  bool has_utm_ptr = false;
  bool has_utm_sz = false;
  bool enable_time = false;
  long long utm_ptr;
  long long utm_sz;
  long long int hash_time = 0;
  clock_t start, end;
  double time;

  //Set parameters
  if(argc > 3)
  {

    long long arg;
    for(int i = 3; i < argc/2 * 2; i+=2){
      if(std::string(argv[i]) == std::string("-rss")){
        printf("Change RT stk\n");
        arg = std::stoll(argv[i+1]);
        printf("%llu\n", arg);
        params.setRuntimeStack((uint64_t) arg);
      }
      if(std::string(argv[i]) == std::string("-ess")){
        printf("Change enclave stk!\n");
        arg = std::stoll(argv[i+1]);
        printf("%llu\n", arg);
        params.setEnclaveStack((uint64_t) arg);
      }
      if(std::string(argv[i]) == std::string("-uts")){
        has_utm_sz = true;
        utm_sz = std::stoll(argv[i+1]);
      }
      if(std::string(argv[i]) == std::string("-utptr")){
        has_utm_ptr = true;
        utm_ptr = std::stoll(argv[i+1]);
      }
    }

    for(int i = 3; i < argc; i+=1){
      if(std::string(argv[i]) == std::string("-t")){
        enable_time = true;
      }
    }
  }

  if(has_utm_ptr && has_utm_sz){
    params.setUntrustedMem(utm_ptr, utm_sz);
  } else if(!has_utm_ptr && !has_utm_sz){
    //Do nothing when utm_ptr and utm_sz is undefined
  } else{
    printf("UTM requires both an entry point and a size\n");
    return 0;
  }

//  enclave.init(argv[1], argv[2], params);

//  edge_init(&enclave);
  if(enable_time) {
    start = clock();
  }
  enclave.measure(argv[1], argv[2], params);

  if(enable_time) {
    time = (double) (clock()-start) / CLOCKS_PER_SEC * 1000.0;
  }

  printf("User calculated hash: ");
  print_hex(enclave.hash, 64);
  if(enable_time)
    printf("Time taken to hash: %lf ms\n", time);
  return 0;
}

