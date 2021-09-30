#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "sqlite3.h"

typedef size_t edge_data_offset;

struct edge_data {
  edge_data_offset offset;
  size_t size;
};

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
  sqlite3_backup_finish(backup); // TODO: add check here?


  sqlite3_close(fromFile);

  char* query = "SELECT * FROM employees LIMIT 1";

  while (1) {
    printf("forking...\n");

    int pid = fork();

    printf("pid : %d\n", pid);

    if (pid) {
      rc = sqlite3_exec(inMemory, query, callback, 0, &err_msg);

      if (rc != SQLITE_OK) {
        printf("SQL error: %s\n", err_msg);

        sqlite3_free(err_msg);
        sqlite3_close(inMemory);

        return 1;
      }
      return 0;
    }
  }

  sqlite3_close(inMemory);

  return 0;
}
