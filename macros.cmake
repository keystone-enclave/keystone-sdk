cmake_minimum_required(VERSION 3.10)
include(ExternalProject)

macro(global_set Name Value)
    #  message("set ${Name} to " ${ARGN})
    set(${Name} "${Value}" CACHE STRING "NoDesc" FORCE)
endmacro()

macro(use_riscv_toolchain bits)
  set(cross_compile riscv${bits}-unknown-linux-gnu-)
  execute_process(
    COMMAND which ${cross_compile}gcc
    OUTPUT_VARIABLE CROSSCOMPILE
    RESULT_VARIABLE ERROR)

  if (NOT "${ERROR}" STREQUAL 0)
    message(FATAL_ERROR "RISCV Toochain is not found")
  endif()

  string(STRIP ${CROSSCOMPILE} CROSSCOMPILE)
  string(REPLACE "gcc" "" CROSSCOMPILE ${CROSSCOMPILE})

  message(STATUS "Tagret tripplet: ${CROSSCOMPILE}")

  set(CC              ${CROSSCOMPILE}gcc)
  set(CXX             ${CROSSCOMPILE}g++)
  set(LD              ${CROSSCOMPILE}ld)
  set(AR              ${CROSSCOMPILE}ar)
  set(OBJCOPY         ${CROSSCOMPILE}objcopy)
  set(OBJDUMP         ${CROSSCOMPILE}objdump)
  set(CFLAGS          "-Wall -Werror")

  global_set(CMAKE_C_COMPILER        ${CC}${EXT})
  global_set(CMAKE_ASM_COMPILER        ${CC}${EXT})
  global_set(CMAKE_CXX_COMPILER      ${CXX}${EXT})
  global_set(CMAKE_LINKER            ${LD}${EXT})
  global_set(CMAKE_AR                ${AR}${EXT})
  global_set(CMAKE_OBJCOPY           ${OBJCOPY}${EXT})
  global_set(CMAKE_OBJDUMP           ${OBJDUMP}${EXT})
  global_set(CMAKE_C_FLAGS           ${CMAKE_C_FLAGS} ${CFLAGS})

  check_compiler(${CMAKE_C_COMPILER})
  check_compiler(${CMAKE_CXX_COMPILER})

  global_set(CMAKE_C_COMPILER_WORKS      1)
  global_set(CMAKE_CXX_COMPILER_WORKS    1)

  global_set(CMAKE_SYSTEM_NAME    "Linux")

endmacro()

macro(check_compiler target)
  message(STATUS "Check for working C compiler: ${target}")
  execute_process(
    COMMAND ${target} -print-file-name=crt.o
    OUTPUT_FILE OUTPUT
    RESULT_VARIABLE ERROR)

  if ("${ERROR}" STREQUAL 0)
    message(STATUS "Check for working C compiler: ${target} -- works")
  else()
    message(FATAL_ERROR "Check for working C compiler: ${target} -- not working")
  endif()
endmacro()

macro(subdirs_list OUT_VARIABLE DIRWORK)
  file(GLOB children RELATIVE ${DIRWORK} ${DIRWORK}/*)
  set(_subdirs    "")
  foreach(child ${children})
    if (IS_DIRECTORY ${DIRWORK}/${child})
      list(APPEND _subdirs  ${child})
    endif()
  endforeach()
  set(${OUT_VARIABLE} ${_subdirs})
endmacro()

macro(add_files FILE_LIST DIRWORK)
  foreach(file ${ARGN})
    list(APPEND ${FILE_LIST} ${DIRWORK}/${file})
  endforeach()
endmacro()

# CMake macro for Eyrie runtime 
macro(add_eyrie_runtime target_name tag plugins) # the files are passed via ${ARGN}
  set(runtime_prefix runtime)
  set (eyrie_src ${CMAKE_CURRENT_BINARY_DIR}/${runtime_prefix}/src/eyrie-${target_name})

  ExternalProject_Add(eyrie-${target_name}
    PREFIX ${runtime_prefix}
    GIT_REPOSITORY https://github.com/keystone-enclave/keystone-runtime
    GIT_TAG ${tag}
    CONFIGURE_COMMAND ""
    UPDATE_COMMAND git fetch
    BUILD_COMMAND ./build.sh ${plugins}
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND "")

  add_custom_target(${target_name} DEPENDS ${ARGN})

  foreach(item IN ITEMS ${ARGN})
    add_custom_command(OUTPUT ${item} DEPENDS eyrie-${target_name} ${eyrie_src}/${item}
      COMMAND cp ${eyrie_src}/${item} ${item})
  endforeach(item)

endmacro(add_eyrie_runtime)

# CMake macro for loader
macro(add_loader target_name tag) # the files are passed via ${ARGN}
  set(loader_prefix loader)
  set (loader_src ${CMAKE_CURRENT_BINARY_DIR}/${loader_prefix}/src/loader-${target_name})

  ExternalProject_Add(loader-${target_name}
    PREFIX ${loader_prefix}
    GIT_REPOSITORY https://github.com/anayw2001/keystone-elfloader 
    GIT_TAG ${tag}
    CONFIGURE_COMMAND ""
    UPDATE_COMMAND git fetch
    BUILD_COMMAND ./build.sh
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND "")

  add_custom_target(${target_name} DEPENDS ${ARGN})

  foreach(item IN ITEMS ${ARGN})
    add_custom_command(OUTPUT ${item} DEPENDS loader-${target_name} ${loader_src}/${item}
      COMMAND cp ${loader_src}/${item} ${item})
  endforeach(item)

endmacro(add_loader)

# CMake macro for Keystone Package
macro(add_keystone_package target_name package_name package_script) # files are passed via ${ARGN}
  set(pkg_dir ${CMAKE_CURRENT_BINARY_DIR}/pkg)
  add_custom_command(OUTPUT ${pkg_dir} COMMAND mkdir ${pkg_dir})

  message(STATUS " * Configuring Keystone package (${target_name})")
  foreach(dep IN ITEMS ${ARGN})
    get_filename_component(filename ${dep} NAME)
    string(CONCAT pkg_file "${pkg_dir}/" "${filename}")
    list(APPEND pkg_files ${pkg_file})

    message(STATUS "   Adding ${filename}")
    add_custom_command(OUTPUT ${pkg_file} DEPENDS ${dep} ${pkg_dir}
      COMMAND cp ${dep} ${pkg_file})
  endforeach(dep)

  message(STATUS "   Package: ${package_name}")
  message(STATUS "   Script: ${package_script}")

  separate_arguments(package_script_raw UNIX_COMMAND ${package_script})
  add_custom_target(${target_name} DEPENDS ${pkg_files}
    COMMAND
      ${MAKESELF} --noprogress ${pkg_dir} ${package_name} \"Keystone Enclave Package\" ${package_script_raw}
    )

endmacro(add_keystone_package)
