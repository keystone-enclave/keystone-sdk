include(${src_dir}/macros.cmake)

set(libmodules              app edge host verifier)
set(enabled_libmodules      app edge host verifier)

# Common
file(GLOB_RECURSE
  COMMON_SOURCE_FILES
  common/*.[c|cpp])

foreach(module ${enabled_libmodules})
    add_subdirectory(${module})
endforeach()


install(DIRECTORY ${COMMON_INCLUDE_DIRS}
  DESTINATION ${out_dir}/include)


file(GLOB_RECURSE
  CHECK_CXX_SOURCE_FILES
  host/src/*.cpp host/include/*.hpp
)

find_program(CLANG_FORMAT "clang-format")
find_program(CPPLINT "cpplint")

if(CLANG_FORMAT AND CPPLINT)
  ADD_CUSTOM_TARGET(
    format
    COMMAND
    ${CLANG_FORMAT}
    -i
    -style=file
    ${CHECK_CXX_SOURCE_FILES}
    COMMAND
    ${CPPLINT}
    ${CHECK_CXX_SOURCE_FILES}
    COMMENT "Auto-formatting"
  )
endif()
