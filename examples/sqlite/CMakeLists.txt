set(host_bin hello-runner)
set(host_src host/host.cpp)

set(sqlite_bin sql_test)
set(sqlite_src ${CMAKE_CURRENT_SOURCE_DIR}/eapp/sqlite/sqlite_test.c ${CMAKE_CURRENT_SOURCE_DIR}/eapp/sqlite/sqlite3.c)
set(sql_package_name "sqlite_test.ke")
set(sql_package_script "./hello-runner sql_test eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup")
endif()

#sqlite eapp
add_custom_command(OUTPUT ${sqlite_bin}
  COMMAND
  riscv64-unknown-linux-musl-gcc -static -o ${CMAKE_CURRENT_BINARY_DIR}/${sqlite_bin} ${sqlite_src} -DSLITE_THREADSAFE=0)

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${sqlite_bin}-eyrie
  "v1.0.0"
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${sqlite_bin}-package
  ${sql_package_name}
  ${sql_package_script}
  ${eyrie_files_to_copy} ${sqlite_bin} ${host_bin} ${CMAKE_CURRENT_SOURCE_DIR}/eapp/sqlite/chinook.db)

add_dependencies(${sqlite_bin}-package ${sqlite_bin}-eyrie)

