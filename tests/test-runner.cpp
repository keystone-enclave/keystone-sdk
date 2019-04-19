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

#define HASH_SIZE 64
const char* longstr = "hellohellohellohellohellohellohellohellohellohello";
byte *hash;

unsigned long print_buffer(char* str){
  printf("Enclave said: %s",str);
  return strlen(str);
}

void print_value(unsigned long val){
  printf("Enclave said value: %u\n",val);
  return;
}

bool is_hex_notation(std::string const& s)
{
  return s.compare(0, 2, "0x") == 0
         && s.size() > 2
         && s.find_first_not_of("0123456789abcdefABCDEF", 2) == std::string::npos;
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
  hash = (byte *) malloc(sizeof(byte)*HASH_SIZE);
  strncpy((char *) hash, (char *) report.getEnclaveHash(), HASH_SIZE);

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
  long long utm_ptr;
  long long utm_sz;

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
        printf("hex: %d\n", is_hex_notation(std::string(argv[i+1])));
        if(is_hex_notation(std::string(argv[i+1])))
          utm_sz = std::stoll(argv[i+1], NULL, 16);
        else
          utm_sz = std::stoll(argv[i+1]);
      }
      if(std::string(argv[i]) == std::string("-utptr")){
        has_utm_ptr = true;
        printf("hex: %d\n", is_hex_notation(std::string(argv[i+1])));
        if(is_hex_notation(std::string(argv[i+1])))
          utm_ptr = std::stoll(argv[i+1], NULL, 16);
        else
          utm_ptr = std::stoll(argv[i+1]);
        printf("utm_ptr: %p, str: %s\n", (void *) utm_ptr, argv[i+1]);
      }
    }
  }

  if(has_utm_ptr && has_utm_sz){
    params.setUntrustedMem(utm_ptr, utm_sz);
  } else if(has_utm_ptr || has_utm_sz){
    printf("UTM requires both an entry point and a size\n");
    return 0;
  }

  enclave.init(argv[1], argv[2], params);

  edge_init(&enclave);

  enclave.measure(argv[1], argv[2], params);

  enclave.run();

  if(hash){
    if(strncmp((char*) hash, (char *) enclave.hash, HASH_SIZE)){
      printf("Hash values don't match!\n");
      printf("User hash: \n");
      print_hex(enclave.hash, HASH_SIZE);
      printf("SM hash: \n");
      print_hex(hash, HASH_SIZE);
      return 0;
    }
    printf("User hash: \n");
    print_hex(enclave.hash, HASH_SIZE);
    printf("SM hash: \n");
    print_hex(hash, HASH_SIZE);
  }

  free(hash);
  return 0;
}

