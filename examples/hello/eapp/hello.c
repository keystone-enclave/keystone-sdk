#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "sqlite3.h"

#define SYSCALL_SNAPSHOT 1005

#define SYSCALL(which, arg0, arg1, arg2, arg3, arg4)           \
  ({                                                           \
    register uintptr_t a0 asm("a0") = (uintptr_t)(arg0);       \
    register uintptr_t a1 asm("a1") = (uintptr_t)(arg1);       \
    register uintptr_t a2 asm("a2") = (uintptr_t)(arg2);       \
    register uintptr_t a3 asm("a3") = (uintptr_t)(arg3);       \
    register uintptr_t a4 asm("a4") = (uintptr_t)(arg4);       \
    register uintptr_t a7 asm("a7") = (uintptr_t)(which);      \
    asm volatile("ecall"                                       \
                 : "+r"(a0)                                    \
                 : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7) \
                 : "memory");                                  \
    a0;                                                        \
  })

#define SYSCALL_0(which) SYSCALL(which, 0, 0, 0, 0, 0)
#define SYSCALL_1(which, arg0) SYSCALL(which, arg0, 0, 0, 0, 0)
#define SYSCALL_2(which, arg0, arg1) SYSCALL(which, arg0, arg1, 0, 0, 0)
#define SYSCALL_3(which, arg0, arg1, arg2) \
  SYSCALL(which, arg0, arg1, arg2, 0, 0)
#define SYSCALL_4(which, arg0, arg1, arg2, arg3) \
  SYSCALL(which, arg0, arg1, arg2, arg3, 0)
#define SYSCALL_5(which, arg0, arg1, arg2, arg3, arg4) \
  SYSCALL(which, arg0, arg1, arg2, arg3, arg4)

int
sbi_enclave_snapshot() {
  return SYSCALL_0(SYSCALL_SNAPSHOT);
}

int
callback(void* NotUsed, int argc, char** argv, char** azColName) {
  NotUsed = 0;

  for (int i = 0; i < argc; i++) {
    printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
  }

  printf("\n");

  return 0;
}

int
main() {
  unsigned long cycle_start, cycle_end;

  sqlite3 *fromFile, *inMemory;
  char* err_msg = 0;
  int rc;

  rc = sqlite3_open("./chinook.db", &fromFile);
  printf("Opened db from file: %d\r\n", rc);
  if (rc != SQLITE_OK) {
    printf("Cannot open database: %s\n", sqlite3_errmsg(fromFile));
    sqlite3_close(fromFile);
    return 1;
  }

  rc = sqlite3_open(":memory:", &inMemory);
  printf("Opened in-memory db: %d\r\n", rc);
  if (rc != SQLITE_OK) {
    printf("Cannot open database: %s\n", sqlite3_errmsg(inMemory));
    sqlite3_close(fromFile);
    sqlite3_close(inMemory);
    return 1;
  }

  sqlite3_backup* backup =
      sqlite3_backup_init(inMemory, "main", fromFile, "main");
  if (backup == NULL) {
    printf("Failed to init backup %s\n", sqlite3_errmsg(inMemory));
    sqlite3_close(fromFile);
    sqlite3_close(inMemory);
    return 1;
  }

  sqlite3_backup_step(backup, -1);
  sqlite3_backup_finish(backup);
  // rc = sqlite3_backup_step(backup, -1);
  // if (rc != SQLITE_DONE) {
  //   printf("Failed to backup: %s\n", sqlite3_errmsg(inMemory));
  //   sqlite3_close(fromFile);
  //   sqlite3_close(inMemory);
  //   return 1;
  // }
  
  // rc = sqlite3_backup_finish(backup);
  // if (rc != SQLITE_DONE) {
  //   printf("Failed to finish backup: %s\n", sqlite3_errmsg(inMemory));
  //   sqlite3_close(fromFile);
  //   sqlite3_close(inMemory);
  //   return 1;
  // }

  sqlite3_close(fromFile);

  sbi_enclave_snapshot();
  char* query = "SELECT * from employees LIMIT 5";

  asm volatile("rdcycle %0" : "=r"(cycle_start));
  rc = sqlite3_exec(inMemory, query, callback, 0, &err_msg);
  asm volatile("rdcycle %0" : "=r"(cycle_end));
  if (rc != SQLITE_OK) {
    printf("SQL error: %s\n", err_msg);

    sqlite3_free(err_msg);
    sqlite3_close(inMemory);

    return 1;
  }

  printf(
      "I need something really long so I can see it Cycles: %ld\n",
      cycle_end - cycle_start);

  sqlite3_close(inMemory);

  return 0;
}
