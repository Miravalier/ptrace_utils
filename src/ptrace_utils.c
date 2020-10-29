#include <ptrace_utils.h>

static uintptr_t _find_elf_symbol(const char *image, const char *symbol);
static uint8_t _un_hex(char upper, char lower);
static bool ptrace_wait(pid_t pid);


bool ptrace_add_watchpoint(pid_t pid, uintptr_t address, size_t size, int permissions)
{
    if (address == 0)
    {
        ERROR_PUTS("cannot add NULL watchpoint");
        return false;
    }
    if (permissions == DBG_EXECUTE)
    {
        size = DBG_1_BYTE;
    }

    unsigned long long debug_control;
    if (!ptrace_get_debug_register(pid, &debug_control, 7))
    {
        return false;
    }

    int debug_index = -1;
    dr7_t dr7;
    dr7.value = debug_control;
    dr7.unused_10 = 1;
    dr7.le = 1;
    dr7.ge = 1;
    if (dr7.dr0_local == 0)
    {
        debug_index = 0;
        dr7.dr0_local = 1;
        dr7.dr0_len = size;
        dr7.dr0_break = permissions;
    }
    else if (dr7.dr1_local == 0)
    {
        debug_index = 1;
        dr7.dr1_local = 1;
        dr7.dr1_len = size;
        dr7.dr1_break = permissions;
    }
    else if (dr7.dr2_local == 0)
    {
        debug_index = 2;
        dr7.dr2_local = 1;
        dr7.dr2_len = size;
        dr7.dr2_break = permissions;
    }
    else if (dr7.dr3_local == 0)
    {
        debug_index = 3;
        dr7.dr3_local = 1;
        dr7.dr3_len = size;
        dr7.dr3_break = permissions;
    }
    debug_control = dr7.value;

    if (debug_index == -1)
    {
        ERROR_PUTS("no hardware watchpoints remaining");
        return false;
    }

    if (!ptrace_set_debug_register(pid, (unsigned long long *)&address, debug_index))
    {
        return false;
    }

    if (!ptrace_set_debug_register(pid, &debug_control, 7))
    {
        return false;
    }

    return true;
}


bool ptrace_remove_watchpoint(pid_t pid, uintptr_t address)
{
    if (address == 0)
    {
        ERROR_PUTS("cannot remove NULL watchpoint");
        return false;
    }

    unsigned long long debug_control;
    if (!ptrace_get_debug_register(pid, &debug_control, 7))
    {
        return false;
    }

    unsigned long long watch_address;
    dr7_t dr7;
    dr7.value = debug_control;
    dr7.unused_10 = 1;
    dr7.le = 1;
    dr7.ge = 1;
    if (dr7.dr0_local != 0)
    {
        if (!ptrace_get_debug_register(pid, &watch_address, 0))
        {
            return false;
        }
        if (watch_address == address)
        {
            dr7.dr0_local = 0;
        }
    }
    else if (dr7.dr1_local != 0)
    {
        if (!ptrace_get_debug_register(pid, &watch_address, 1))
        {
            return false;
        }
        if (watch_address == address)
        {
            dr7.dr1_local = 0;
        }
    }
    else if (dr7.dr2_local != 0)
    {
        if (!ptrace_get_debug_register(pid, &watch_address, 2))
        {
            return false;
        }
        if (watch_address == address)
        {
            dr7.dr2_local = 0;
        }
    }
    else if (dr7.dr3_local != 0)
    {
        if (!ptrace_get_debug_register(pid, &watch_address, 3))
        {
            return false;
        }
        if (watch_address == address)
        {
            dr7.dr3_local = 0;
        }
    }
    debug_control = dr7.value;

    if (!ptrace_set_debug_register(pid, &debug_control, 7))
    {
        return false;
    }

    return true;
}


bool ptrace_get_debug_register(pid_t pid, unsigned long long *dst, int src)
{
    void *src_addr = (void*)offsetof(struct user, u_debugreg[src]);
    long word = ptrace(PTRACE_PEEKUSER, pid, src_addr, src_addr);
    if (word == -1)
    {
        ERROR_PUTS("failed to get debug register");
        return false;
    }

    *dst = (unsigned long long)word;
    return true;
}


bool ptrace_set_debug_register(pid_t pid, const unsigned long long *src, int dst)
{
    void *src_value = (void*)((uintptr_t)*src);
    void *dst_addr = (void*)offsetof(struct user, u_debugreg[dst]);
    if (ptrace(PTRACE_POKEUSER, pid, dst_addr, src_value) == -1)
    {
        ERROR_PUTS("failed to set debug register");
        return false;
    }

    return true;
}


bool ptrace_get_debug_registers(pid_t pid, debug_reg_t registers)
{
    for (int i=0; i < 8; i++)
    {
        if (!ptrace_get_debug_register(pid, registers+i, i))
        {
            return false;
        }
    }

    return true;
}


bool ptrace_set_debug_registers(pid_t pid, const debug_reg_t registers)
{
    for (int i=0; i < 8; i++)
    {
        if (!ptrace_set_debug_register(pid, registers+i, i))
        {
            return false;
        }
    }

    return true;
}


bool ptrace_peek_instructions(pid_t pid, instruction_t *ins, uintptr_t address, size_t count)
{
    uint8_t opcodes[16];
    for (size_t i=0; i < count; i++)
    {
        if (!ptrace_read_memory(pid, opcodes, address, sizeof opcodes))
        {
            ERROR_PRINTF("failed to read %zx\n", address);
            return false;
        }

        if (!nasm_disassemble(opcodes, ins+i))
        {
            ERROR_PUTS("failed to disassemble instructions");
            return false;
        }

        address += (ins+i)->length;
    }

    return true;
}


bool ptrace_current_instruction(pid_t pid, instruction_t *ins)
{
    reg_t registers;
    if (!ptrace_get_registers(pid, &registers))
    {
        ERROR_PUTS("failed to get registers");
        return false;
    }

    uint8_t opcodes[16];
    if (!ptrace_read_memory(pid, opcodes, registers.gp.rip, sizeof opcodes))
    {
        ERROR_PUTS("failed to read rip");
        return false;
    }

    if (!nasm_disassemble(opcodes, ins))
    {
        ERROR_PUTS("failed to disassemble instructions at rip");
        return false;
    }

    return true;
}


size_t nasm_instruction_length(void *addr)
{
    instruction_t ins;
    if (nasm_disassemble(addr, &ins))
    {
        size_t length = ins.length;
        free_instruction(&ins);
        return length;
    }
    return 0;
}


bool nasm_assemble(const char *nasm, instruction_t *ins)
{
    bool result = false;
    
    // Create the memory files
    int src = memfd_create("", 0);
    if (src == -1)
    {
        perror("memfd_create");
        ERROR_PUTS("failed to create src memfd");
        return false;
    }
    int pipefds[2] = {-1, -1};
    if (pipe(pipefds) == -1)
    {
        perror("pipe");
        ERROR_PUTS("failed to pipe");
        goto ERROR;
    }

    // Get paths to the memory files
    char src_path[32];
    sprintf(src_path, "/proc/self/fd/%d", src);
    char pipe_path[32];
    sprintf(pipe_path, "/proc/self/fd/%d", pipefds[1]);

    // Write nasm into temporary file
    if (!write_all(src, "BITS 64\n", 8))
    {
        ERROR_PUTS("failed to write");
        goto ERROR;
    }
    if (!write_all(src, nasm, strlen(nasm)))
    {
        ERROR_PUTS("failed to write");
        goto ERROR;
    }
    if (!write_all(src, "\n", 1))
    {
        ERROR_PUTS("failed to write");
        goto ERROR;
    }

    // Call nasm child process to write into pipe
    pid_t pid = fork();
    if (pid == -1)
    {
        ERROR_PUTS("failed to fork");
        goto ERROR;
    }
    if (pid == 0)
    {
        //close(STDIN_FILENO);
        //close(STDOUT_FILENO);
        //close(STDERR_FILENO);
        close(pipefds[0]);
        execlp("nasm", "nasm", src_path, "-o", pipe_path, NULL);
        ERROR_PUTS("failed to exec");
        exit(1);
    }
    else
    {
        close(pipefds[1]);
        pipefds[1] = -1;
        int wait_status;
        int wait_return;
        do
        {
            wait_return = waitpid(pid, &wait_status, 0);
        } while (wait_return == -1 && errno == EINTR);
    }
    
    // Read up to 16 bytes from pipe
    ssize_t length = read(pipefds[0], ins->bytes, 16);
    if (length <= 0)
    {
        perror("read");
        ERROR_PUTS("pipe unreadable or empty");
        goto ERROR;
    }

    ins->length = length;
    ins->nasm = strdup(nasm);
    result = true;
ERROR:
    close(src);
    close(pipefds[0]);
    close(pipefds[1]);
    return result;
}


bool nasm_disassemble(const void *addr, instruction_t *ins)
{
    bool result = false;
    
    // Create the memory files
    int src = memfd_create("", 0);
    if (src == -1)
    {
        perror("src memfd create");
        ERROR_PUTS("failed to create src memfd");
        return false;
    }
    int pipefds[2] = {-1, -1};
    if (pipe(pipefds) == -1)
    {
        perror("pipe");
        ERROR_PUTS("failed to pipe");
        goto ERROR;
    }

    // Get paths to the memory files
    char src_path[32];
    sprintf(src_path, "/proc/self/fd/%d", src);

    // Write 16 bytes into temporary file
    if (!write_all(src, addr, 16))
    {
        ERROR_PUTS("failed to write into memfd");
        goto ERROR;
    }

    // Call ndisasm child process to write into the pipe
    pid_t pid = fork();
    if (pid == -1)
    {
        ERROR_PUTS("failed to fork");
        goto ERROR;
    }
    if (pid == 0)
    {
        close(pipefds[0]);
        close(STDIN_FILENO);
        dup2(pipefds[1], STDOUT_FILENO);
        dup2(pipefds[1], STDERR_FILENO);
        close(pipefds[1]);
        execlp("ndisasm", "ndisasm", "-b64", src_path, NULL);
        ERROR_PUTS("failed to exec");
        exit(1);
    }
    else
    {
        close(pipefds[1]);
        pipefds[1] = -1;
        int wait_status;
        int wait_return;
        do
        {
            wait_return = waitpid(pid, &wait_status, 0);
        } while (wait_return == -1 && errno == EINTR);
    }
    
    // Read 128 bytes from pipe
    char string_buffer[128];
    ssize_t string_buffer_length = read(pipefds[0], string_buffer, 128);
    if (string_buffer_length <= 0)
    {
        perror("read from pipe");
        ERROR_PUTS("pipe unreadable or empty");
        goto ERROR;
    }

    // Parse length, bytes, and nasm from the string buffer
    char *s = string_buffer;
    // Skip to the first whitespace
    while (!isspace(*s)) s++;
    // Skip to the next nonspace
    while (isspace(*s)) s++;
    // Mark the start of bytes
    char *bytes = s;
    // Skip to the next whitespace
    while (!isspace(*s)) s++;
    // Null terminate bytes
    *s++ = '\0';
    // Skip until the next non-whitespace
    while (isspace(*s)) s++;
    // Mark the start of nasm
    char *nasm = s;
    // Skip until the next newline
    while (*s != '\n') s++;
    // Null terminate nasm
    *s++ = '\0';

    ins->length = strlen(bytes) / 2;
    if (ins->length > 16) {
        ins->length = 16;
    }
    ins->nasm = strdup(nasm);
    for (size_t i=0; i < ins->length; i++)
    {
        ins->bytes[i] = _un_hex(bytes[i*2], bytes[i*2+1]);
    }
    result = true;
ERROR:
    close(src);
    close(pipefds[0]);
    close(pipefds[1]);
    return result;
}


static uint8_t _un_hex(char upper, char lower)
{
    uint8_t result = 0;

    if (isdigit(upper))
    {
        result += (upper - '0') << 4;
    }
    else if (islower(upper))
    {
        result += (upper - 'a' + 10) << 4;
    }
    else
    {
        result += (upper - 'A' + 10) << 4;
    }

    if (isdigit(lower))
    {
        result += (lower - '0');
    }
    else if (islower(lower))
    {
        result += (lower - 'a' + 10);
    }
    else
    {
        result += (lower - 'A' + 10);
    }

    return result;
}


void free_instruction(instruction_t *ins)
{
    if (ins != NULL && ins->nasm != NULL)
    {
        free(ins->nasm);
    }
}


bool ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        return false;
    }
    
    int wait_return;
    int wait_status;
    do
    {
        wait_return = waitpid(pid, &wait_status, 0);
    } while (wait_return == -1 && errno == EINTR);

    if (wait_return == -1)
    {
        return false;
    }

    return true;
}


bool ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    {
        return false;
    }
    return true;
}


static bool ptrace_wait(pid_t pid)
{
    int wait_return;
    int wait_status;
    do
    {
        wait_return = waitpid(pid, &wait_status, 0);
    } while (wait_return == -1 && errno == EINTR);
    
    if (wait_return == -1)
    {
        return false;
    }

    if (!WIFSTOPPED(wait_status) || (WSTOPSIG(wait_status) != SIGTRAP))
    {
        if (WIFSTOPPED(wait_status))
            // Unexpected stop
            errno = 200;
        else if (WIFEXITED(wait_status))
            // Unexpected exit
            errno = 201;
        else if (WIFSIGNALED(wait_status))
            // Unexpected signal
            errno = 202;
        else
            // Unexpected status
            errno = 203;
        return false;
    }

    return true;
}


bool ptrace_single_step(pid_t pid)
{
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
    {
        return false;
    }
    
    return ptrace_wait(pid);
}


bool ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        return false;
    }

    return ptrace_wait(pid);
}


bool ptrace_get_registers(pid_t pid, reg_t *registers)
{
    if (ptrace(PTRACE_GETREGS, pid, &registers->gp, &registers->gp) == -1)
    {
        return false;
    }
    if (ptrace(PTRACE_GETFPREGS, pid, &registers->fp, &registers->fp) == -1)
    {
        return false;
    }
    return true;
}


bool ptrace_set_registers(pid_t pid, const reg_t *registers)
{
    if (ptrace(PTRACE_SETREGS, pid, &registers->gp, &registers->gp) == -1)
    {
        return false;
    }
    if (ptrace(PTRACE_SETFPREGS, pid, &registers->fp, &registers->fp) == -1)
    {
        return false;
    }
    return true;
}


void print_registers(const reg_t *registers)
{
    const gp_reg_t *r = &registers->gp;
    printf(
        "---------------------------------------------\n"
        "RAX: %016llx   RBX: %016llx\n"
        "RCX: %016llx   RDX: %016llx\n"
        "RDI: %016llx   RSI: %016llx\n"
        "R8:  %016llx   R9:  %016llx\n"
        "R10: %016llx   R11: %016llx\n"
        "R12: %016llx   R13: %016llx\n"
        "R14: %016llx   R15: %016llx\n"
        "RBP: %016llx   RSP: %016llx\n"
        "RIP: %016llx\n"
        "EFLAGS: %016llx\n"
        "---------------------------------------------\n",
        r->rax, r->rbx, r->rcx, r->rdx,
        r->rdi, r->rsi, r->r8, r->r9,
        r->r10, r->r11, r->r12, r->r13,
        r->r14, r->r15, r->rbp, r->rsp,
        r->rip, r->eflags
    );
}


bool ptrace_read_memory(pid_t pid, void *dest, uintptr_t src, size_t bytes)
{
    uintptr_t word;
    for (size_t bytes_read=0; bytes_read < bytes; bytes_read += sizeof word)
    {
        size_t read_size = bytes - bytes_read;
        if (read_size > sizeof word)
        {
            read_size = sizeof word;
        }
        errno = 0;
        word = ptrace(PTRACE_PEEKTEXT, pid, (void*)(src+bytes_read), (void*)(src+bytes_read));
        if (errno != 0)
        {
            return false;
        }
        memcpy(((uint8_t*)dest) + bytes_read, &word, read_size);
    }

    return true;
}


bool ptrace_write_memory(pid_t pid, const void *src, uintptr_t dest, size_t bytes)
{
    uintptr_t word;
    if (bytes < sizeof word)
    {
        if (!ptrace_read_memory(pid, &word, dest, sizeof word))
        {
            return false;
        }
        memcpy(&word, src, bytes);
        return ptrace_write_memory(pid, &word, dest, sizeof word);
    }

    for (size_t i=0; i < bytes; i += sizeof word)
    {
        size_t write_size = bytes - i;
        if (write_size < 8)
        {
            i -= 8 - write_size;
        }
        memcpy(&word, ((uint8_t*)src)+i, sizeof word);
        if (ptrace(PTRACE_POKETEXT, pid, (void*)(dest+i), (void*)word) == -1)
        {
            return false;
        }
    }

    return true;
}


bool ptrace_inject_so(pid_t pid, const char *so_path)
{
    // Make sure the so path will fit in memory
    size_t so_path_size = strlen(so_path) + 1;

    // Get the memory maps of the process
    map_t *maps = get_memory_maps(pid);
    if (maps == NULL)
    {
        ERROR_PRINTF("failed to get memory maps\n");
        return false;
    }

    // Find the process's dlopen
    uintptr_t dlopen = find_libc_symbol(maps, "__libc_dlopen_mode");
    free_memory_maps(maps);
    if (dlopen == 0)
    {
        ERROR_PRINTF("failed to find dlopen\n");
        goto ERROR;
    }

    // Inject an mmap call to the process
    uintptr_t mmap_buffer;
    bool syscall_success = ptrace_inject_syscall(
        pid, (unsigned long long*)&mmap_buffer, SYS_mmap,
        NULL,
        65536+16+so_path_size,
        PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_PRIVATE|MAP_ANONYMOUS,
        -1,
        0
    );
    if (!syscall_success || mmap_buffer == 0)
    {
        ERROR_PRINTF("failed to ptrace_inject_syscall\n");
        goto ERROR;
    }

    // Get starting registers
    reg_t registers;
    if (!ptrace_get_registers(pid, &registers))
    {
        goto ERROR;
    }

    // Put the shared object path into memory
    if (!ptrace_write_memory(pid, so_path, mmap_buffer+65536+16, so_path_size))
    {
        goto ERROR;
    }

    // Modify registers to pass dlopen arguments
    reg_t modified = registers;
    modified.gp.rsp = mmap_buffer + 65536;
    modified.gp.rdi = mmap_buffer + 65536+16;
    modified.gp.rsi = RTLD_LAZY;
    if (!ptrace_set_registers(pid, &modified))
    {
        goto ERROR;
    }

    // Inject a dlopen call to make the process open the shared object
    if (!ptrace_inject_function_call(pid, NULL, dlopen))
    {
        goto ERROR;
    }
    
    // Restore original registers
    if (!ptrace_set_registers(pid, &registers))
    {
        goto ERROR;
    }

    return true;
ERROR:
    return false;
}


bool ptrace_inject_function_call(pid_t pid, unsigned long long *result, uintptr_t function)
{
    // Set up rax to hold the function
    reg_t registers;
    if (!ptrace_get_registers(pid, &registers))
    {
        return false;
    }
    registers.gp.rax = function;
    if (!ptrace_set_registers(pid, &registers))
    {
        return false;
    }

    // Inject shellcode to call rax
    uint8_t call_shellcode[] = {0xFF, 0xD0, 0xCC}; // call rax, int3
    if (!ptrace_inject_shellcode(pid, call_shellcode, sizeof call_shellcode))
    {
        return false;
    }

    // Store result
    if (result != NULL)
    {
        if (!ptrace_get_registers(pid, &registers))
        {
            return false;
        }
        *result = registers.gp.rax;
    }

    return true;
}


bool patch_code(void *dest, const void *src, size_t bytes)
{
    size_t page_size = (size_t)getpagesize();
    uintptr_t start_page = (uintptr_t)dest & (~(page_size - 1));
    uintptr_t end_page = ((uintptr_t)dest + bytes) & (~(page_size - 1));
    size_t pages = (end_page - start_page) / page_size + 1;
    for (size_t i=0; i < pages; i++)
    {
        void *page = (void*)(start_page + (i*page_size));
        if (mprotect(page, page_size, PROT_READ|PROT_WRITE|PROT_EXEC) != 0)
        {
            for (size_t j=0; j < i; j++)
            {
                page = (void*)(start_page + (j*page_size));
                mprotect(page, page_size, PROT_READ|PROT_EXEC);
            }
            return false;
        }
    }

    memmove(dest, src, bytes);

    for (size_t i=0; i < pages; i++)
    {
        void *page = (void*)(start_page + (i*page_size));
        mprotect(page, page_size, PROT_READ|PROT_EXEC);
    }

    return true;
}


int memory_permissions(const map_t *maps, const void *addr)
{
    for (const map_t *map = maps; map != NULL; map = map->next)
    {
        if ((uintptr_t)addr >= map->base && (uintptr_t)addr <= (map->base + map->size))
        {
            int permissions = 0;
            if (map->read)
                permissions |= MEM_READ;
            if (map->write)
                permissions |= MEM_WRITE;
            if (map->execute)
                permissions |= MEM_EXECUTE;
            return permissions;
        }
    }

    return 0;
}


void *find_libc_base(const map_t *maps)
{
    return find_so_base(maps, "libc");
}


void *find_so_base(const map_t *maps, const char *so)
{
    uintptr_t base = UINTPTR_MAX;
    for (const map_t *map = maps; map != NULL; map = map->next)
    {
        if (map->image == NULL)
            continue;
        if (strstr(map->image, so) && strstr(map->image, ".so"))
        {
            if (map->base < base)
            {
                base = map->base;
            }
        }
    }

    if (base == UINTPTR_MAX)
    {
        return NULL;
    }
    return (void*)base;
}


uintptr_t find_libc_symbol(const map_t *maps, const char *symbol)
{
    // Find image for libc
    const char *image = find_libc_image(maps);
    if (image == NULL)
    {
        return 0;
    }
    // Call general image symbol finder
    return find_image_symbol(maps, image, symbol);
}


uintptr_t find_image_symbol(const map_t *maps, const char *image, const char *symbol)
{
    return ((uintptr_t)find_image_base(maps, image))
            + find_image_symbol_offset(maps, image, symbol);
}


uintptr_t find_image_symbol_offset(const map_t *maps, const char *image, const char *symbol)
{
    // Find the symbol's offset in the image
    uintptr_t symbol_offset = _find_elf_symbol(image, symbol);
    if (symbol_offset == 0)
    {
        return 0;
    }
    // Add the offset to the base
    return symbol_offset;
}


static uintptr_t _find_elf_symbol(const char *image, const char *symbol)
{
    // Open image for parsing
    int fd = open(image, O_RDONLY);
    if (fd == -1)
    {
        return 0;
    }

    // Read the ELF header
    Elf64_Ehdr  elf_header;
    if (!read_all(fd, &elf_header, sizeof elf_header))
    {
        close(fd);
        return 0;
    }

    // Read the string table section header
    Elf64_Shdr  section_header;
    if (!read_offset(fd, elf_header.e_shoff + elf_header.e_shstrndx * elf_header.e_shentsize,
        &section_header, sizeof section_header))
    {
        close(fd);
        return 0;
    }
    Elf64_Off   section_name_base = section_header.sh_offset;

    // Find the .dynstr and .dynsym sections
    Elf64_Off   dynstr_base = 0;
    Elf64_Xword dynstr_size;
    Elf64_Off   dynsym_base = 0;
    Elf64_Xword dynsym_size;
    Elf64_Xword dynsym_entry_size;
    for (size_t i = 0; i < elf_header.e_shnum; i++)
    {
        // Read the current section
        if (!read_offset(fd,
            elf_header.e_shoff + i * elf_header.e_shentsize,
            &section_header, sizeof section_header))
        {
            close(fd);
            return 0;
        }

        // Read the first 8 bytes of the section name
        char section_name[8 + 1] = {0};
        if (!read_offset(fd,
            section_name_base + section_header.sh_name,
            section_name, sizeof section_name - 1))
        {
            close(fd);
            return 0;
        }

        // Check for .dynstr
        if (section_header.sh_type == SHT_STRTAB && strcmp(section_name, ".dynstr") == 0)
        {
            dynstr_base = section_header.sh_offset;
            dynstr_size = section_header.sh_size;
        }
        // Check for .dynsym
        else if (section_header.sh_type == SHT_DYNSYM && strcmp(section_name, ".dynsym") == 0)
        {
            dynsym_base = section_header.sh_offset;
            dynsym_size = section_header.sh_size;
            dynsym_entry_size = section_header.sh_entsize;
        }

        // Stop looking if both are located
        if (dynstr_base != 0 && dynsym_base != 0)
        {
            break;
        }
    }

    // Make sure both dynsym and dynstr were located
    if (dynstr_base == 0 || dynsym_base == 0)
    {
        close(fd);
        return 0;
    }

    // Find the .dynsym entry whose .dynstr matches the symbol
    for (size_t i=0; i < dynsym_size / dynsym_entry_size; i++)
    {
        // Read the symbol entry into memory
        Elf64_Sym   symbol_entry;
        if (!read_offset(fd,
            dynsym_base + i * dynsym_entry_size,
            &symbol_entry, sizeof symbol_entry))
        {
            close(fd);
            return 0;
        }

        // If this compare returns true, the symbol is found
        if (read_compare(fd,
            dynstr_base + symbol_entry.st_name,
            symbol))
        {
            close(fd);
            return symbol_entry.st_value;
        }
    }

    // The symbol was not found
    close(fd);
    return 0;
}


bool read_compare(int fd, size_t offset, const char *string)
{
    uint8_t byte;

    if (lseek(fd, offset, SEEK_SET) == -1)
    {
        return false;
    }
    for (size_t i=0; i < strlen(string) + 1; i++)
    {
        // No more bytes can be read, or the bytes don't match
        if (!read(fd, &byte, sizeof byte) || byte != string[i])
        {
            return false;
        }
    }
    
    return true;
}


bool read_offset(int fd, size_t source, void *dest, size_t bytes)
{
    if (lseek(fd, source, SEEK_SET) == -1)
    {
        return false;
    }
    return read_all(fd, dest, bytes);
}


bool write_all(int fd, const void *buffer, size_t bytes)
{
    size_t bytes_written = 0;
    while (bytes_written < bytes)
    {
        ssize_t last_written = write(
            fd,
            ((const uint8_t*)buffer) + bytes_written,
            bytes - bytes_written
        );
        if (last_written <= 0)
        {
            return false;
        }
        bytes_written += last_written;
    }
    return true;
}


bool read_all(int fd, void *buffer, size_t bytes)
{
    size_t bytes_read = 0;
    while (bytes_read < bytes)
    {
        ssize_t last_read = read(
            fd,
            ((uint8_t*)buffer) + bytes_read,
            bytes - bytes_read
        );
        if (last_read <= 0)
        {
            return false;
        }
        bytes_read += last_read;
    }
    return true;
}


uintptr_t find_libc_entry(const map_t *maps)
{
    // Find base for libc
    uintptr_t libc_base = (uintptr_t)find_libc_base(maps);

    // Find image for libc
    const char *libc_image = find_libc_image(maps);
    if (libc_image == NULL)
    {
        return 0;
    }

    // Open image for parsing
    int fd = open(libc_image, O_RDONLY);
    if (fd == -1)
    {
        return 0;
    }

    // Read the ELF header
    Elf64_Ehdr  elf_header;
    if (!read_all(fd, &elf_header, sizeof elf_header))
    {
        close(fd);
        return 0;
    }

    // Return the entry point of libc in memory
    close(fd);
    return elf_header.e_entry + libc_base;
}


const char *find_libc_image(const map_t *maps)
{
    return find_so_image(maps, "libc");
}

const char *find_so_image(const map_t *maps, const char *so)
{
    for (const map_t *map = maps; map != NULL; map = map->next)
    {
        if (map->image == NULL)
            continue;
        if (strstr(map->image, so) && strstr(map->image, ".so"))
        {
            return map->image;
        }
    }

    return NULL;
}

void *find_image_base(const map_t *maps, const char *image)
{
    uintptr_t base = UINTPTR_MAX;
    for (const map_t *map = maps; map != NULL; map = map->next)
    {
        if (map->image == NULL)
            continue;
        if (strcmp(map->image, image) == 0)
        {
            if (map->base < base)
            {
                base = map->base;
            }
        }
    }

    if (base == UINTPTR_MAX)
    {
        return NULL;
    }
    return (void*)base;
}

void print_memory_maps(const map_t *maps)
{
    for (const map_t *map = maps; map != NULL; map = map->next)
    {
        printf(
            "%lx %zu %c%c%c %s\n",
            map->base,
            map->size,
            map->read ? 'r' : '-',
            map->write ? 'w' : '-',
            map->execute ? 'x' : '-',
            map->image
        );
    }
}

void free_memory_maps(map_t *maps)
{
    for (map_t *map = maps; map != NULL;)
    {
        map_t *next = map->next;
        free(map->image);
        free(map);
        map = next;
    }
}

map_t *get_memory_maps(pid_t pid)
{
    char path[32];
    snprintf(path, 32, "/proc/%d/maps", pid);
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        return NULL;
    }

    char c;
    size_t count = 0;
    size_t capacity = 128;
    char *line = malloc(capacity);
    map_t *maps = calloc(1, sizeof(map_t));
    map_t *map = maps;
    while (true)
    {
        if (count >= capacity - 1)
        {
            capacity *= 2;
            line = realloc(line, capacity);
        }
        int status = read(fd, &c, 1);
        if (status == 0)
        {
            break;
        }
        else if (status == -1)
        {
            close(fd);
            free_memory_maps(maps);
            free(line);
            return NULL;
        }
        line[count++] = c;
        if (c == '\n')
        {
            line[count] = '\0';
            uintptr_t end = 0;
            char *perms = NULL;
            sscanf(
                line,
                "%lx-%lx %ms %*x %*x:%*x %*d %ms",
                &map->base,
                &end,
                &perms,
                &map->image
            );
            map->size = end - map->base;
            if (perms[0] == 'r')
                map->read = true;
            if (perms[1] == 'w')
                map->write = true;
            if (perms[2] == 'x')
                map->execute = true;
            free(perms);
            map->next = calloc(1, sizeof(map_t));
            map = map->next;
            count = 0;
        }
    }

    free(line);
    close(fd);
    return maps;
}
