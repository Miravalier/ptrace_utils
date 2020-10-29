#define _GNU_SOURCE
#include <ctype.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <search.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>

// Macros
#define ERROR_PUTS(fmt, ...) fprintf(stderr, "[\x1b[31merror\x1b[0m] %s:%d " fmt "\n", __FILE__, __LINE__)

#define SUCCESS_PUTS(fmt, ...) fprintf(stderr, "[\x1b[32minfo\x1b[0m] %s:%d " fmt "\n", __FILE__, __LINE__)

#define ERROR_PRINTF(fmt, ...) fprintf(stderr, "[\x1b[31merror\x1b[0m] %s:%d " fmt, \
                                __FILE__, __LINE__, ## __VA_ARGS__)

#define SUCCESS_PRINTF(fmt, ...) fprintf(stderr, "[\x1b[32minfo\x1b[0m] %s:%d " fmt, \
                                __FILE__, __LINE__, ## __VA_ARGS__)
#define DBG_EXECUTE 0
#define DBG_WRITE   1
#define DBG_READ    3
#define DBG_1_BYTE  0
#define DBG_2_BYTES 1
#define DBG_4_BYTES 3
#define DBG_8_BYTES 2

typedef union dr7_t {
    struct {
        unsigned int dr0_local  : 1;
        unsigned int dr0_global : 1;
        unsigned int dr1_local  : 1;
        unsigned int dr1_global : 1;
        unsigned int dr2_local  : 1;
        unsigned int dr2_global : 1;
        unsigned int dr3_local  : 1;
        unsigned int dr3_global : 1;
        unsigned int le         : 1;
        unsigned int ge         : 1;
        unsigned int unused_10  : 1;
        unsigned int rtm        : 1;
        unsigned int unused_12  : 1;
        unsigned int gd         : 1;
        unsigned int unused_14  : 1;
        unsigned int unused_15  : 1;
        unsigned int dr0_break  : 2;
        unsigned int dr0_len    : 2;
        unsigned int dr1_break  : 2;
        unsigned int dr1_len    : 2;
        unsigned int dr2_break  : 2;
        unsigned int dr2_len    : 2;
        unsigned int dr3_break  : 2;
        unsigned int dr3_len    : 2;
    };
    unsigned long long value;
} dr7_t;

#define MEM_READ    4
#define MEM_WRITE   2
#define MEM_EXECUTE 1

typedef struct map_t {
    uintptr_t       base;
    size_t          size;
    char            *image;
    struct map_t    *next;
    bool            read;
    bool            write;
    bool            execute;
} map_t;

typedef struct instruction_t {
    size_t length;
    uint8_t bytes[16];
    char *nasm;
} instruction_t;

typedef struct user user_t;
typedef struct user_regs_struct gp_reg_t;
typedef struct user_fpregs_struct fp_reg_t;
typedef struct reg_t {
    gp_reg_t    gp;
    fp_reg_t    fp;
} reg_t;
typedef unsigned long long debug_reg_t[8];

bool ptrace_current_instruction(pid_t pid, instruction_t *ins);
bool ptrace_peek_instructions(pid_t pid, instruction_t *ins, uintptr_t address, size_t count);

bool nasm_assemble(const char *nasm, instruction_t *ins);
bool nasm_disassemble(const void *addr, instruction_t *ins);
void free_instruction(instruction_t *ins);
size_t nasm_instruction_length(void *addr);

bool ptrace_inject_so(pid_t pid, const char *so);
bool ptrace_inject_shellcode(pid_t pid, uint8_t *shellcode, size_t bytes);
bool ptrace_inject_function_call(pid_t pid, unsigned long long *result, uintptr_t function);
bool ptrace_inject_syscall(pid_t pid, unsigned long long *result, int syscall, ...);
bool ptrace_attach(pid_t pid);
bool ptrace_detach(pid_t pid);
bool ptrace_continue(pid_t pid);
bool ptrace_single_step(pid_t pid);
bool ptrace_get_registers(pid_t pid, reg_t *registers);
bool ptrace_set_registers(pid_t pid, const reg_t *registers);
bool ptrace_read_memory(pid_t pid, void *dest, uintptr_t src, size_t bytes);
bool ptrace_write_memory(pid_t pid, const void *src, uintptr_t dest, size_t bytes);
bool patch_code(void *dest, const void *src, size_t bytes);
void print_registers(const reg_t *registers);

bool read_compare(int fd, size_t offset, const char *string);
bool read_offset(int fd, size_t source, void *dest, size_t bytes);
bool read_all(int fd, void *buffer, size_t bytes);
bool write_all(int fd, const void *buffer, size_t bytes);

bool ptrace_add_watchpoint(pid_t pid, uintptr_t address, size_t size, int permissions);
bool ptrace_remove_watchpoint(pid_t pid, uintptr_t address);
bool ptrace_get_debug_register(pid_t pid, unsigned long long *dst, int src);
bool ptrace_set_debug_register(pid_t pid, const unsigned long long *src, int dst);
bool ptrace_get_debug_registers(pid_t pid, debug_reg_t registers);
bool ptrace_set_debug_registers(pid_t pid, const debug_reg_t registers);

map_t       *get_memory_maps(pid_t pid);
void        free_memory_maps(map_t *maps);
void        print_memory_maps(const map_t *maps);
int         memory_permissions(const map_t *maps, const void *addr);

const char  *find_libc_image(const map_t *maps);
void        *find_libc_base(const map_t *maps);
uintptr_t   find_libc_symbol(const map_t *maps, const char *symbol);
uintptr_t   find_libc_entry(const map_t *maps);
const char  *find_so_image(const map_t *maps, const char *so);
void        *find_so_base(const map_t *maps, const char *so);
void        *find_image_base(const map_t *maps, const char *image);
uintptr_t   find_image_symbol(const map_t *maps, const char *image, const char *symbol);
uintptr_t   find_image_symbol_offset(const map_t *maps, const char *image, const char *symbol);
