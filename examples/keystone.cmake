# CMake macro for Eyrie runtime and Keystone Package
macro(add_eyrie_runtime target_name tag plugins) # the files are passed via ${ARGN}
  set(runtime_prefix runtime)
  set (eyrie_src ${CMAKE_CURRENT_BINARY_DIR}/${runtime_prefix}/src/eyrie-${target_name})

  ExternalProject_Add(eyrie-${target_name}
    PREFIX ${runtime_prefix}
    GIT_REPOSITORY https://github.com/keystone-enclave/keystone-runtime
    GIT_TAG ${tag}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ./build.sh ${plugins}
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND "")

  add_custom_target(${target_name} DEPENDS ${ARGN})

  foreach(item IN ITEMS ${ARGN})
    add_custom_command(OUTPUT ${item} DEPENDS eyrie-${target_name} ${eyrie_src}/${item}
      COMMAND cp ${eyrie_src}/${item} ${item})
  endforeach(item)

endmacro(add_eyrie_runtime)

macro(add_keystone_package target_name package_name package_script) # files are passed via ${ARGN}
  set(pkg_dir ${CMAKE_CURRENT_BINARY_DIR}/pkg)
  add_custom_command(OUTPUT ${pkg_dir} COMMAND mkdir ${pkg_dir})

  foreach(dep IN ITEMS ${ARGN})
    string(CONCAT pkg_file "${pkg_dir}/" "${dep}")
    list(APPEND pkg_files ${pkg_file})
  endforeach(dep)

  add_custom_target(${target_name} DEPENDS ${pkg_files}
    COMMAND
      ${MAKESELF} ${pkg_dir} ${package_name} "Keystone Enclave Package" "${PACKAGE_SCRIPT}"
    VERBATIM
    )
  message(STATUS " * Configuring Keystone package (${target_name})")
  foreach(item IN ITEMS ${ARGN})
    message(STATUS "   Adding ${item}")
    add_custom_command(OUTPUT ${pkg_dir}/${item} DEPENDS ${item} ${pkg_dir}
      COMMAND cp ${item} ${pkg_dir}/${item})
  endforeach(item)
  message(STATUS "   Package: ${package_name}")
  message(STATUS "   Script: ${package_script}")

endmacro(add_keystone_package)
