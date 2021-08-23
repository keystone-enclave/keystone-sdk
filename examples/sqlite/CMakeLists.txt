set(eapp_bin sqlite)
set(eapp_src eapp/sqlite_test.c)
set(sqlite_src eapp/sqlite3.c)
set(host_bin sqlite-runner)
set(host_src host/host.cpp)
set(package_name "sqlite-test.ke")
set(package_script "./sqlite-runner sqlite eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup strace_debug rv32")
else()
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup strace_debug debug")
endif()

# eapp

add_custom_command(OUTPUT ${eapp_bin}
  COMMAND
  riscv64-unknown-linux-musl-gcc -static -o ${CMAKE_CURRENT_BINARY_DIR}/${eapp_bin} ${CMAKE_CURRENT_SOURCE_DIR}/${eapp_src} ${CMAKE_CURRENT_SOURCE_DIR}/${sqlite_src} -DSLITE_THREADSAFE=0)

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  "v1.0.0"
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin} ${CMAKE_CURRENT_SOURCE_DIR}/eapp/chinook.db)

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)

# add package to the top-level target
add_dependencies(examples ${eapp_bin}-package)

