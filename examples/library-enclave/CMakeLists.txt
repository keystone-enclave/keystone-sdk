set(host_bin library-runner)
set(host_src host/host.cpp)
set(package_name "library-enclave.ke")
set(package_script "./library-runner /home/ubuntu/keystone/riscv64/sysroot/lib/libc.so.6")

if(RISCV32)
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup rv32 debug")
else()
  set(eyrie_plugins "freemem untrusted_io_syscall linux_syscall env_setup debug")
endif()

# host

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE})

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${host_bin})

add_dependencies(${eapp_bin}-package)

# add package to the top-level target
add_dependencies(examples)
