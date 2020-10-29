#!/usr/bin/env python3
from collections import namedtuple
import ctypes

dll = ctypes.CDLL("libptrace_utils.so")

# Ptrace
pid_t = ctypes.c_int
uintptr_t = ctypes.c_uint64

DBG_1_BYTE = 0
DBG_2_BYTES = 1
DBG_4_BYTES = 3
DBG_8_BYTES = 2

DBG_EXECUTE = 0
DBG_WRITE = 1
DBG_READ = 3

MEM_READ = 4
MEM_WRITE = 2
MEM_EXECUTE = 1

class map_t(ctypes.Structure):
    pass
map_t._fields_ = [
    ('base', uintptr_t),
    ('size', ctypes.c_size_t),
    ('image', ctypes.c_char_p),
    ('next', ctypes.POINTER(map_t)),
    ('read', ctypes.c_bool),
    ('write', ctypes.c_bool),
    ('execute', ctypes.c_bool)
]
map_t_p = ctypes.POINTER(map_t)

class gp_reg_t(ctypes.Structure):
    _fields_ = [
        ('r15', ctypes.c_ulonglong),
        ('r14', ctypes.c_ulonglong),
        ('r13', ctypes.c_ulonglong),
        ('r12', ctypes.c_ulonglong),
        ('rbp', ctypes.c_ulonglong),
        ('rbx', ctypes.c_ulonglong),
        ('r11', ctypes.c_ulonglong),
        ('r10', ctypes.c_ulonglong),
        ('r9', ctypes.c_ulonglong),
        ('r8', ctypes.c_ulonglong),
        ('rax', ctypes.c_ulonglong),
        ('rcx', ctypes.c_ulonglong),
        ('rdx', ctypes.c_ulonglong),
        ('rsi', ctypes.c_ulonglong),
        ('rdi', ctypes.c_ulonglong),
        ('orig_rax', ctypes.c_ulonglong),
        ('rip', ctypes.c_ulonglong),
        ('cs', ctypes.c_ulonglong),
        ('eflags', ctypes.c_ulonglong),
        ('rsp', ctypes.c_ulonglong),
        ('ss', ctypes.c_ulonglong),
        ('fs_base', ctypes.c_ulonglong),
        ('gs_base', ctypes.c_ulonglong),
        ('ds', ctypes.c_ulonglong),
        ('es', ctypes.c_ulonglong),
        ('fs', ctypes.c_ulonglong),
        ('gs', ctypes.c_ulonglong)
    ]

class fp_reg_t(ctypes.Structure):
    _fields_ = [
        ('cwd', ctypes.c_ushort),
        ('swd', ctypes.c_ushort),
        ('ftw', ctypes.c_ushort),
        ('fop', ctypes.c_ushort),
        ('rip', ctypes.c_ulonglong),
        ('rdp', ctypes.c_ulonglong),
        ('mxcsr', ctypes.c_uint),
        ('mxcr_mask', ctypes.c_uint),
        ('st_space', ctypes.c_uint * 32),
        ('xmm_space', ctypes.c_uint * 64),
        ('padding', ctypes.c_uint * 24)
    ]

class reg_t(ctypes.Structure):
    _fields_ = [
        ("gp", gp_reg_t),
        ("fp", fp_reg_t)
    ]
reg_t_p = ctypes.POINTER(reg_t)

class instruction_t(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_size_t),
        ("bytes", ctypes.c_uint8 * 16),
        ("nasm", ctypes.c_char_p)
    ]
instruction_t_p = ctypes.POINTER(instruction_t)
Instruction = namedtuple("Instruction", ('opcode', 'asm'))

ptrace_add_watchpoint = dll.ptrace_add_watchpoint
ptrace_add_watchpoint.restype = ctypes.c_bool
ptrace_add_watchpoint.argtypes = (pid_t, uintptr_t, ctypes.c_size_t, ctypes.c_int)

def watchpoint_size(size):
    if size == 1:
        return DBG_1_BYTE
    elif size == 2:
        return DBG_2_BYTES
    elif size == 4:
        return DBG_4_BYTES
    elif size == 8:
        return DBG_8_BYTES
    else:
        raise ValueError("watchpoint size must be 1, 2, 4, or 8")

def ptrace_add_code_watchpoint(pid, address):
    return ptrace_add_watchpoint(pid, address, DBG_1_BYTE, DBG_EXECUTE)

def ptrace_add_write_watchpoint(pid, address, size=8):
    return ptrace_add_watchpoint(pid, address, watchpoint_size(size), DBG_WRITE)

def ptrace_add_read_watchpoint(pid, address, size=8):
    return ptrace_add_watchpoint(pid, address, watchpoint_size(size), DBG_READ)

ptrace_remove_watchpoint = dll.ptrace_remove_watchpoint
ptrace_remove_watchpoint.restype = ctypes.c_bool
ptrace_remove_watchpoint.argtypes = (pid_t, uintptr_t, ctypes.c_size_t, ctypes.c_int)

_ptrace_current_instruction = dll.ptrace_current_instruction
_ptrace_current_instruction.restype = ctypes.c_bool
_ptrace_current_instruction.argtypes = (pid_t, instruction_t_p)

def ptrace_current_instruction(pid):
    ins = instruction_t()
    if not _ptrace_current_instruction(pid, ins):
        return None
    opcodes = bytes(ins.bytes)[:ins.length]
    asm = ins.nasm.decode('ascii')
    free_instruction(ins)
    return opcodes, asm
    
_ptrace_peek_instructions = dll.ptrace_peek_instructions
_ptrace_peek_instructions.restype = ctypes.c_bool
_ptrace_peek_instructions.argtypes = (pid_t, instruction_t_p, uintptr_t, ctypes.c_size_t)

def ptrace_peek_instructions(pid, count, address):
    ins_array = (instruction_t * count)()
    if not _ptrace_peek_instructions(pid, ins_array, address, count):
        return None

    results = []
    for i in range(count):
        ins = ins_array[i]
        opcode = bytes(ins.bytes)[:ins.length]
        asm = ins.nasm.decode('ascii')
        results.append(Instruction(opcode, asm))
        free_instruction(ins)

    return results

_nasm_assemble = dll.nasm_assemble
_nasm_assemble.restype = ctypes.c_bool
_nasm_assemble.argtypes = (ctypes.c_char_p, instruction_t_p)

def nasm_assemble(asm):
    ins = instruction_t()
    _nasm_assemble(asm.encode('ascii'), ins)
    opcode = bytes(ins.bytes)[:ins.length]
    free_instruction(ins)
    return Instruction(opcode, asm)

_nasm_disassemble = dll.nasm_disassemble
_nasm_disassemble.restype = ctypes.c_bool
_nasm_disassemble.argtypes = (ctypes.c_void_p, instruction_t_p)

def nasm_disassemble(memory):
    ins = instruction_t()
    _nasm_disassemble(memory, ins)
    asm = ins.nasm.decode('ascii')
    opcode = bytes(ins.bytes)[:ins.length]
    free_instruction(ins)
    return Instruction(opcode, asm)

nasm_instruction_length = dll.nasm_instruction_length
nasm_instruction_length.restype = ctypes.c_size_t
nasm_instruction_length.argtypes = (ctypes.c_void_p,)

free_instruction = dll.free_instruction
free_instruction.restype = None
free_instruction.argtypes = (instruction_t_p,)

ptrace_inject_so = dll.ptrace_inject_so
ptrace_inject_so.restype = ctypes.c_bool
ptrace_inject_so.argtypes = (pid_t, ctypes.c_char_p)

ptrace_attach = dll.ptrace_attach
ptrace_attach.restype = ctypes.c_bool
ptrace_attach.argtypes = (pid_t,)

ptrace_detach = dll.ptrace_detach
ptrace_detach.restype = ctypes.c_bool
ptrace_detach.argtypes = (pid_t,)

ptrace_single_step = dll.ptrace_single_step
ptrace_single_step.restype = ctypes.c_bool
ptrace_single_step.argtypes = (pid_t,)

ptrace_continue = dll.ptrace_continue
ptrace_continue.restype = ctypes.c_bool
ptrace_continue.argtypes = (pid_t,)

ptrace_get_registers = dll.ptrace_get_registers
ptrace_get_registers.restype = ctypes.c_bool
ptrace_get_registers.argtypes = (pid_t, reg_t_p)

ptrace_set_registers = dll.ptrace_set_registers
ptrace_set_registers.restype = ctypes.c_bool
ptrace_set_registers.argtypes = (pid_t, reg_t_p)

print_registers = dll.print_registers
print_registers.restype = None
print_registers.argtypes = (reg_t_p,)

ptrace_read_memory = dll.ptrace_read_memory
ptrace_read_memory.restype = ctypes.c_bool
ptrace_read_memory.argtypes = (pid_t, ctypes.c_void_p, uintptr_t, ctypes.c_size_t)

ptrace_write_memory = dll.ptrace_write_memory
ptrace_write_memory.restype = ctypes.c_bool
ptrace_write_memory.argtypes = (pid_t, ctypes.c_void_p, uintptr_t, ctypes.c_size_t)

get_memory_maps = dll.get_memory_maps
get_memory_maps.restype = map_t_p
get_memory_maps.argtypes = (pid_t,)

free_memory_maps = dll.free_memory_maps
free_memory_maps.restype = None
free_memory_maps.argtypes = (map_t_p,)

print_memory_maps = dll.print_memory_maps
print_memory_maps.restype = None
print_memory_maps.argtypes = (map_t_p,)

memory_permissions = dll.memory_permissions
memory_permissions.restype = ctypes.c_int
memory_permissions.argtypes = (map_t_p, ctypes.c_void_p)

find_libc_image = dll.find_libc_image
find_libc_image.restype = ctypes.c_char_p
find_libc_image.argtypes = (map_t_p,)
find_libc_base = dll.find_libc_base
find_libc_base.restype = ctypes.c_void_p
find_libc_base.argtypes = (map_t_p,)
find_libc_symbol = dll.find_libc_symbol
find_libc_symbol.restype = uintptr_t
find_libc_symbol.argtypes = (map_t_p, ctypes.c_char_p)
find_libc_entry = dll.find_libc_entry
find_libc_entry.restype = uintptr_t
find_libc_entry.argtypes = (map_t_p,)

find_so_image = dll.find_so_image
find_so_image.restype = ctypes.c_char_p
find_so_image.argtypes = (map_t_p, ctypes.c_char_p)
find_so_base = dll.find_so_base
find_so_base.restype = ctypes.c_void_p
find_so_base.argtypes = (map_t_p, ctypes.c_char_p)

find_image_base = dll.find_image_base
find_image_base.restype = ctypes.c_void_p
find_image_base.argtypes = (map_t_p, ctypes.c_char_p)
find_image_symbol_offset = dll.find_image_symbol_offset
find_image_symbol_offset.restype = uintptr_t
find_image_symbol_offset.argtypes = (map_t_p, ctypes.c_char_p, ctypes.c_char_p)

BREAKPOINT = nasm_assemble("int3").opcode

class PtraceError(ValueError):
    pass

class Ptrace:
    def __init__(self, pid):
        self.pid = pid
        self.breakpoints = {}
        self.attach()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.detach()

    def attach(self):
        if not ptrace_attach(self.pid):
            raise PtraceError("unable to attach")

    def detach(self):
        if not ptrace_detach(self.pid):
            raise PtraceError("unable to detach")

    @property
    def registers(self):
        registers = reg_t()
        if not ptrace_get_registers(self.pid, registers):
            raise PtraceError("unable to get registers")
        return registers

    @registers.setter
    def registers(self, value):
        if not ptrace_set_registers(self.pid, value):
            raise PtraceError("unable to set registers")

    @property
    def rax(self):
        return self.registers.gp.rax

    @rax.setter
    def rax(self, value):
        registers = self.registers
        registers.gp.rax = value
        self.registers = registers

    @property
    def rbx(self):
        return self.registers.gp.rbx

    @rbx.setter
    def rbx(self, value):
        registers = self.registers
        registers.gp.rbx = value
        self.registers = registers

    @property
    def rcx(self):
        return self.registers.gp.rcx

    @rcx.setter
    def rcx(self, value):
        registers = self.registers
        registers.gp.rcx = value
        self.registers = registers

    @property
    def rdx(self):
        return self.registers.gp.rdx

    @rdx.setter
    def rdx(self, value):
        registers = self.registers
        registers.gp.rdx = value
        self.registers = registers

    @property
    def rdi(self):
        return self.registers.gp.rdi

    @rdi.setter
    def rdi(self, value):
        registers = self.registers
        registers.gp.rdi = value
        self.registers = registers

    @property
    def rsi(self):
        return self.registers.gp.rsi

    @rsi.setter
    def rsi(self, value):
        registers = self.registers
        registers.gp.rsi = value
        self.registers = registers

    @property
    def rbp(self):
        return self.registers.gp.rbp

    @rbp.setter
    def rbp(self, value):
        registers = self.registers
        registers.gp.rbp = value
        self.registers = registers

    @property
    def rsp(self):
        return self.registers.gp.rsp

    @rsp.setter
    def rsp(self, value):
        registers = self.registers
        registers.gp.rsp = value
        self.registers = registers

    @property
    def rip(self):
        return self.registers.gp.rip

    @rip.setter
    def rip(self, value):
        registers = self.registers
        registers.gp.rip = value
        self.registers = registers

    @property
    def current_instruction(self):
        result = ptrace_current_instruction(self.pid)
        if result is None:
            raise PtraceError("unable to ptrace_current_instruction")
        return result

    def peek_instructions(self, count=None, address=None):
        if count is None:
            count = 10
        if address is None:
            address = self.rip
        result = ptrace_peek_instructions(self.pid, count, address)
        if result is None:
            raise PtraceError("unable to ptrace_peek_instructions")
        return result

    def print_instructions(self, count=None):
        rip = self.rip
        offset = 0
        for opcode, nasm in self.peek_instructions(count, rip):
            opcode_string = " ".join("{:02x}".format(byte) for byte in opcode)
            offset_string = "{:x}+{:x}".format(rip, offset)
            print("{:16} {:26} {}".format(offset_string, opcode_string, nasm))
            offset += len(opcode)

    def print_registers(self):
        print_registers(self.registers)

    def add_software_breakpoint(self, address):
        memory = self[address:address+16]
        instruction = nasm_disassemble(memory)
        self.breakpoints[address] = instruction.opcode
        self[address] = BREAKPOINT

    def remove_software_breakpoint(self, address):
        self[address] = self.breakpoints[address]
        del self.breakpoints[address]

    def step_instruction(self):
        rip = self.rip
        if rip in self.breakpoints:
            self[rip] = self.breakpoints[rip]
            if not ptrace_single_step(self.pid):
                raise PtraceError("error in ptrace_single_step")
            self[rip] = BREAKPOINT
        else:
            ptrace_single_step(self.pid)

    def resume(self):
        self.step_instruction()
        if not ptrace_continue(self.pid):
            raise PtraceError("error in ptrace_continue")

    def __getitem__(self, address):
        # Get start, stop, step
        if isinstance(address, slice):
            start = address.start
            stop = address.stop
            step = address.step
        else:
            start = address
            stop = address + 1
            step = None

        # Allocate memory
        size = stop - start
        if step is not None:
            memory = (ctypes.c_uint8 * (int(size/step)+1))()
        else:
            memory = (ctypes.c_uint8 * size)()

        # Read memory
        if step is None:
            if not ptrace_read_memory(self.pid, memory, start, size):
                raise PtraceError("unable to read memory at address 0x{:x}".format(address))
        else:
            for i in range(start, stop, step):
                if not ptrace_read_memory(self.pid, memory+i, start+(i*step), 1):
                    raise PtraceError("unable to read memory at address 0x{:x}".format(address))

        return bytes(memory)

    def __setitem__(self, address, memory):
        if isinstance(address, slice):
            raise NotImplementedError("Slicing is not supported with Ptrace.__setitem__")

        if not ptrace_write_memory(self.pid, memory, address, len(memory)):
            raise PtraceError("unable to write to address 0x{:x}".format(address))
