set(LOADER_CFLAGS      "-c")
set(LOADER_LDFLAGS     "-nostdlib -T${CMAKE_SOURCE_DIR}/loader/loader.lds")
set(LOADER_SOURCE_DIR "${CMAKE_SOURCE_DIR}/loader/src")
set(LOADER_OBJ_DIR    "${CMAKE_BINARY_DIR}/loader")

list(APPEND ASM_SOURCE_FILES
    ${LOADER_SOURCE_DIR}/loader.S
    )

list(APPEND ASM_OBJ_FILES
    ${LOADER_OBJ_DIR}/loader.S.o
    )

list(APPEND C_SOURCE_FILES
    ${LOADER_SOURCE_DIR}/loader.c
    ${LOADER_SOURCE_DIR}/printf.c
    ${LOADER_SOURCE_DIR}/sbi.c
    ${LOADER_SOURCE_DIR}/string.c
    ${LOADER_SOURCE_DIR}/elf.c
    ${CMAKE_SOURCE_DIR}/src/host/elf64.c
    ${CMAKE_SOURCE_DIR}/src/host/elf32.c
    )

list(APPEND C_OBJ_FILES
    ${LOADER_OBJ_DIR}/loader.c.o
    ${LOADER_OBJ_DIR}/printf.c.o
    ${LOADER_OBJ_DIR}/sbi.c.o
    ${LOADER_OBJ_DIR}/string.c.o
    ${LOADER_OBJ_DIR}/elf.c.o
    ${LOADER_OBJ_DIR}/elf64.c.o
    ${LOADER_OBJ_DIR}/elf32.c.o
    )

set(INCLUDE_DIRS -I${CMAKE_SOURCE_DIR}/loader/inc -I${CMAKE_SOURCE_DIR}/include/host)

set(CMAKE_C_FLAGS          "${CMAKE_C_FLAGS} ${CFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LDFLAGS}")

# compile C files
foreach (SOURCE_FILE OBJ_FILE IN ZIP_LISTS C_SOURCE_FILES C_OBJ_FILES)
add_custom_command(OUTPUT ${OBJ_FILE} COMMAND riscv64-unknown-linux-gnu-gcc ${LOADER_CFLAGS} ${INCLUDE_DIRS} ${SOURCE_FILE} -o ${OBJ_FILE})
endforeach()

# compile ASM files
foreach (SOURCE_FILE OBJ_FILE IN ZIP_LISTS ASM_SOURCE_FILES ASM_OBJ_FILES)
add_custom_command(OUTPUT ${OBJ_FILE} COMMAND riscv64-unknown-linux-gnu-gcc ${LOADER_CFLAGS} ${INCLUDE_DIRS} ${SOURCE_FILE} -o ${OBJ_FILE})
endforeach()

add_custom_command(OUTPUT ${LOADER_OBJ_DIR}/loader.elf DEPENDS ${C_OBJ_FILES} DEPENDS ${ASM_OBJ_FILES} COMMAND riscv64-unknown-linux-gnu-ld ${LOADER_LDFLAGS} ${INCLUDE_DIRS} ${C_OBJ_FILES} ${ASM_OBJ_FILES} -o ${LOADER_OBJ_DIR}/loader.elf)

