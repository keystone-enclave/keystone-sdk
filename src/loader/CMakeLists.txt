project(keystone-elfloader C ASM)

set(CFLAGS      "-Wall -Werror -nostdlib")
set(LDFLAGS     "-t loader.lds")

set(SOURCE_FILES
    loader.S
    loader.c
    printf.c
    ../host/elf.c
    ../host/elf64.c
    ../host/elf32.c
    )

set(INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/include/loader ${CMAKE_SOURCE_DIR}/include/host)

set(CMAKE_C_FLAGS          "${CMAKE_C_FLAGS} ${CFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LDFLAGS}")

include_directories(${INCLUDE_DIRS})

add_library(${PROJECT_NAME} ${SOURCE_FILES} ${COMMON_SOURCE_FILES})

install(TARGETS ${PROJECT_NAME} DESTINATION ${out_dir}/lib)
install(DIRECTORY ${INCLUDE_DIRS} DESTINATION ${out_dir}/include)
