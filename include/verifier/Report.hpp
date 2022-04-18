//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <iostream>
#include <string>
#include "Keys.hpp"
#include "common/sha256.h"
#include "ed25519/ed25519.h"
#include "verifier/json11.h"

struct enclave_report_t {
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
  byte signature[SIGNATURE_SIZE];
};

struct sm_report_t {
  byte hash[MDSIZE]; //32
  byte public_key[PUBLIC_KEY_SIZE]; //32
  byte signature[SIGNATURE_SIZE]; //64
};

struct report_t {
  struct enclave_report_t enclave;
  struct sm_report_t sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

class Report {
 private:
  struct report_t report;

 public:
  std::string BytesToHex(const byte* bytes, size_t len);
  void HexToBytes(byte* bytes, size_t len, std::string hexstr);
  void fromJson(std::string json);
  void fromBytes(byte* bin);
  std::string stringfy();
  void printJson();
  void printPretty();
  int verify(
      const byte* expected_enclave_hash, const byte* expected_sm_hash,
      const byte* dev_public_key);
  int checkSignaturesOnly(const byte* dev_public_key);
  void* getDataSection();
  size_t getDataSize();
  byte* getEnclaveHash();
  byte* getSmHash();
};
