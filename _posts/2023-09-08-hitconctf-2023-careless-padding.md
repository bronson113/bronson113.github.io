---
title: HITCON CTF 2023 - Careless Padding
tag:
  - CTF
  - My Challenge
  - Crypto
---

# HITCON CTF 2023 - Careless Padding
## Challenge Description
This is a challenge I created for HITCON CTF 2023. As the name sugguests, this is a challenge related to padding oracle attack.

You might say: "Hey that's boring, everyone know padding oracle already... What's new?" 

Well, what about a whole new padding methods? I hope this sparks your interest, and keep reading for my writeup and thought process for creating this challenge.

<!--more-->

## Challenge detail
```
How careless can you be as an assistant...

nc chal-careless-padding.chal.hitconctf.com 11111

author: bronson113
solves: 30
```

We are presented with the challenge code as follows
{% capture server_py %}
```python!=
#!/usr/bin/python3
import random
import os
from secret import flag
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

N = 16

# 0 -> 0, 1~N -> 1, (N+1)~(2N) -> 2 ...
def count_blocks(length):
    block_count = (length-1) // N + 1
    return block_count

def find_repeat_tail(message):
    Y = message[-1]
    message_len = len(message)
    for i in range(len(message)-1, -1, -1):
        if message[i] != Y:
            X = message[i]
            message_len = i + 1
            break
    return message_len, X, Y

def my_padding(message):
    message_len = len(message)
    block_count = count_blocks(message_len)
    result_len =  block_count * N
    if message_len % N == 0:
        result_len += N
    X = message[-1]
    Y = message[(block_count-2)*N+(X%N)]
    if X==Y:
        Y = Y^1
    padded = message.ljust(result_len, bytes([Y]))
    return padded

def my_unpad(message):
    message_len, X, Y = find_repeat_tail(message)
    block_count = count_blocks(message_len)
    _Y = message[(block_count-2)*N+(X%N)]
    if (Y != _Y and Y != _Y^1):
        raise ValueError("Incorrect Padding")
    return message[:message_len]

def chal():
    k = os.urandom(16)
    m = json.dumps({'key':flag}).encode()
    print(m)

    iv = os.urandom(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)

    padded = my_padding(m)
    enc = cipher.encrypt(padded)
    print(f"""
*********************************************************
You are put into the classical prison and trying to escape.
Thanksfully, someone forged a key for you, but seems like it's encrypted...
Fortunately they also leave you a copied (and apparently alive) prison door.
The replica pairs with this encrypted key. Wait, how are this suppose to help?
Anyway, here's your encrypted key: {(iv+enc).hex()}
*********************************************************
""")

    while True:
        enc = input("Try unlock:")
        enc = bytes.fromhex(enc)
        iv = enc[:16]
        cipher = AES.new(k, AES.MODE_CBC, iv)
        try:
            message = my_unpad(cipher.decrypt(enc[16:]))
            if message == m:
                print("Hey you unlock me! At least you know how to use the key")
            else:
                print("Bad key... do you even try?")
        except ValueError:
            print("Don't put that weirdo in me!")
        except Exception:
            print("What? Are you trying to unlock me with a lock pick?")

if __name__ == "__main__":
    chal()
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="server_py" button-text="Show server.py" toggle-text=server_py %}

This padding method is taken from [this paper](https://link.springer.com/chapter/10.1007/978-3-319-30840-1_21). The "New Padding Method 3" in particular. The paper claims that these padding methods will be resistant to padding oracle attacks, as the attackers have little probablility of creating a valid padding, and therefore little information can be gathered from the oracle. I first saw this paper when I'm working on a final project for one of my cryptography course, and notice that the method proposed are not exactly secure. After a little bit of fiddling, I realized that all the methods can be broken with relative ease. Among all three, the third padding method is definitely the easiest. 

The challenge itself is simple. The flag is padding with this new method, then encrypted using AES CBC mode. The server then take user input in hex, decrypts it, unpad, and check the "key". It's clear that if an padding error occured, the server will respond differently. This is obviously an oracle. So the matter is how to leverage this knowledge to leak out the flag.

## Understanding the padding

By reading the padding code (or by looking up the graphs from the paper), we can start to understand how the padding works. Essentially, the idea is that the padding is one byte chosen from the previous block. This binds the padding result to both the last and the second to last block. When padding the string, the last byte of the plaintext ($X$ in the paper) is used to index into the second to last block, and the bytes pointed by that index will be used as the padding byte ($Y$ in th paper). If the chosen byte happens to be the same as the last byte, we xor the result with 1 so the padding pad is different from the last byte. The unpadding method works in reverse. We first find the repeating bytes at the end and removs them. We then verify if the removed bytes matches the byte indexed by the last plaintext byte. Due to the nature of the padding, the last bit of the verification isn't checked.

> When I created the challenge, I actually read the padding part wrong! How "careless" am I... It states that the xor with 1 check should be verified by double checking if Y and the indexed byte matches. This, however, was later discovered by myself to be easier to exploit, so I kept the earlier version. See the appendix for more information.

Now this property that the padding byte is dependent on the previous block really hinders our ability to do padding oracle. If we thinking about the common CBC padding oracle with PKCS#1.7 . We can flip bits in the iv to control the decrypted output of the block. But now this would not be an effective measure here since that will also changed what the iv block decrypts to. So the padding will jump around. Even if we hit and success padding, we have no way to know what byte the padding is exactly, since the output of decrypting with AES can be seen as random without knowning the key. 
## The solve
### Forge Same Plaintext Block
Now let's look at other part of the challenge. You might notice that before the flag is encrypted, it is wrapped in the json format. Now this is interesting. Combined with the flag format, if we count the bytes that we know, namely `{'win': 'hitcon{`,  that's 16 bytes, which is a full block! Is this a hint to somthing? 

As we mentioned in the previous section, the repeating tail are remove in the first step. There are NO verification as to whether the tail is longer than a full block. If we forge a block such that all the characters are the same, the unpad method will remove the whole block, making the last plaintext byte in the second to last block, and the indexed byte in the even previous block! 

So lets first forge this last block. Since we have a know plaintext block, we can xor the plaintext with the iv, and that will give us a all zero block when decrypted. That's easy, what then?

### Leaking Top 7 Bits
Think about the implication of having the last plantext byte in a different block. For now we don't know what the last byte of the randomly decrypted second to last block is, but lets assume we know X. Then by control the IV of the thrid to last block, we can enumerate the indexed byte, and see when we have a match. This sounds similar to the standard CBC oracle right? We're just manipulating a byte in the middle block and not the padding bytes themselves. Of course due to the nature of the padding, we can only leak the top 7 bits, since the last bit will be ignored when verifying.

Back to the problem of not knowing X, we might notice that X itself is not that important. We just need the lower half of it, as that will give us the indexed byte. Since we know one full plaintext block, we can construct a cipher text that looks like IV'\|CT\|IV'\|CT, so that it decrypts to Y\*16\|random\|Y\*16. Now no matter what the X is, this should always validate. You can then go through each byte in the first block and change it to something different (like ^0xff) and see if it invalidate it this time. If there is any, we found the lower half of X! 

Of course to leak each position, we need to find 16 different Xs such that every byte in the block is indexed. We can construct in total 256 different versions of the same plaintext block, and each of them will randomly hit one of the Xs. So the probably to not have every single X is a mere $(15/16)^{256} \approx 6.67\times 10^{-8}$. With the Xs known, we can execute the plan above and leak the lower 7 bits of the message.

### Leaking Low Bit
How about the last bit? Here we'll use a different strategy. Even though we never know the padding byte, if we brute force all 256 possible values, there must be one hit, as long as we're actually permuting the indexed byte. So we can manipulate the plaintext and guess if the currect byte is used as the index or not. If after the bruteforce none of the bytes gives a valid padding, then our assumptions of the indexing byte must be incorrect. I'd call this a behavioral oracle, we're observing based on if there is 1 successful padding or not within 256 oracles, and not a specific one. 

In technically, this will only give us if the byte are the same as the previous byte, so we will still need one pivot point. From the previous step we know a method to extract the lower 4 bit of a X, so we can use a similar technique here. We just need to construct this once and we'll get one lower bit.


> Note that I believe that there ways to using a similar construction as the previous step 
> (CT\|IV\|CT) to finish the whole step, but I'm too lazy and this is already efficient enough.


### IO Optimization
After you implement everything, you'll notice the oracle complexity is O(256b + k) where b is the messag length in bytes and k is a startup overhead. If you do one query at a time this will be painfully slow. The good thing is that for a lot of these nc connected challenges, you can abuse the buffering and send out a lot of querys at once before recieveing to reduce the networking overhead. Notice that in both of the bruteforcing step, we pretty much need to send out all the payload to get back a result anyway. So if we batch the input and output, we can get a much faster query time. When testing, my script can complete each oracle block in around 40 second with a server over sea.

### Flag!
And with everything implemented, we now fire the exploit against the server and get out sweet prize!
`hitcon{p4dd1ng_w0n7_s4v3_y0u_Fr0m_4_0rac13_617aa68c06d7ab91f57d1969e8e8532}`

### Reference solve script

{% capture solve_py %}
```python
from pwn import *
from Crypto.Util.number import long_to_bytes
import time

N = 16

#p = process("./chal.py")
#p = remote("127.0.0.1", 11111)
p = remote("107.167.176.135", 11111)

p.recvuntil(b"key: ")
cipher = p.recvline()
cipher = bytes.fromhex(cipher.decode())
p.recvline()
p.recvline()

IV = cipher[:16]
FB = cipher[16:32]
Z = b"\x00"*16
I = [255]*16
known = b'{"key": "hitcon{'[:16]
IV0 = xor(IV, known)

oracle_count = 0

def oracle(m):
    global oracle_count
    oracle_count += 1
    p.sendline(m.hex().encode())
    return not b"weirdo" in p.recvline()

# async send to reduce network lag
def oracle_multi(ms):

    # res = [oracle(m) for m in ms]
    # return res

    global oracle_count
    l = len(ms)
    oracle_count += l
    for m in ms:
        p.sendline(m.hex().encode())
    res = [0] * l
    for i in range(l):
        res[i] = not b"weirdo" in p.recvline()
    return res

offset_db = [-1 for i in range(16)]

def get_offset_db():
    cur = 0;
    for i in range(256):
        if not -1 in offset_db:
            break
        ciphers = []
        for offset in range(16):
            OFF = (offset ^ FB[-1]) % 16
            check = I[:]
            check[offset] = 0
            cipher = xor(IV0, check, i) + FB + xor(IV0, i) + FB
            ciphers.append(cipher)
        res = oracle_multi(ciphers)
        if res.count(True) == 1:
            offset = res.index(True)
            OFF = (offset ^ FB[-1]) % 16
            offset_db[OFF] = i
    return offset_db


def oracle_block_top(BIV, BC):
    res = [0] * 16

    for offset in range(16):
        # get top 7 bit
        real_offset = (offset ^ BC[-1]) % 16
        IVL = xor(IV0, offset_db[offset])
        top_7 = -1
        ciphers = []
        for diff in range(0, 256, 2):
            check = list(BIV[:])
            check[real_offset] ^= diff
            cipher = xor(BIV, check) + BC + IVL + FB
            ciphers.append(cipher)

        res2 = oracle_multi(ciphers)
        result = list(zip(res2, range(0, 256, 2)))
        for ora, diff in result:
            if ora:
                print(offset, diff)
                top_7 = (diff ^ BIV[real_offset] ^ offset_db[offset]) & 0xfe
                res[real_offset] = top_7
                break
        else:
            # honestly I don't know what happned here
            # Sometime things just fall through for some reason...
            raise ValueError("Padding not found")

    return res

def oracle_block_lower(BIV, BC, Mtop):
    # 14th byte first, use as anchor
    # make sure Mtop[-1] != Mtop[-2]
    # cipher: control IV1 | control IV2 | BC
    # IV2 -> BIV + offset to control Mtop decrypt result -> partial known X, Y
    # IV1 -> use to bruteforce all permutation
    lowers = [0] * 16

    baseIV = xor(BIV, Mtop) # so decrypt(BC, iv = baseIV) will only contain 0 or 1
    diff = [0] * 16
    diff[-2] = 0xf0 # make sure it don't propagate
    IV2 = xor(baseIV, diff)

    # we check if some value in the first location match
    # yes -> last bit of Mtop[-2] is 0
    # no  -> last bit of Mtop[-2] is 1
    ciphers = []
    for brute in range(0, 256, 2):
        IV1 = [brute] + [0] * 15
        ciphers.append(bytes(IV1) + IV2 + BC)

    if oracle_multi(ciphers).count(True) == 1:
        lowers[-2] = 0
    else:
        lowers[-2] = 1

    # now we check if the last bit is the same as Mtop[-2]
    diff = [0] * 16
    diff[-3] = 0xf8 # make sure it don't propagate
    IV2 = xor(baseIV, diff, lowers)
    # we check if some value in the first location match
    # yes -> Mtop[-2] is X -> last bit of Mtop[-1] is 1
    # no  -> Mtop[-2] is not X -> last bit of Mtop[-1] is 0
    ciphers = []
    for brute in range(0, 256, 2):
        IV1 = [brute] + [0] * 15
        ciphers.append(bytes(IV1) + IV2 + BC)

    if oracle_multi(ciphers).count(True) == 1:
        lowers[-1] = 1
    else:
        lowers[-1] = 0

    # now we can consistantly form repeating tail
    # fill the rest of the lower bits
    for loc in range(13, -1, -1):
        diff = [0] * 16
        diff[loc] = 0xf0 # make sure it don't propagate
        IV2 = xor(baseIV, diff, lowers)
        ciphers = []
        for brute in range(0, 256, 2):
            IV1 = [brute] + [0] * 15
            ciphers.append(bytes(IV1) + IV2 + BC)

        if oracle_multi(ciphers).count(True) == 1:
            lowers[loc] = 0
        else:
            lowers[loc] = 1

    return [i+j for i, j in zip(Mtop, lowers)]

def oracle_block(BIV, BC):
    tops = oracle_block_top(BIV, BC)
    full = oracle_block_lower(BIV, BC, tops)
    return full


def attack():
    offset_db = get_offset_db()
    print(offset_db, oracle_count)
    m = known
    for loc in range(32, len(cipher), 16):
        m+=bytes(oracle_block(cipher[loc-16:loc], cipher[loc:loc+16]))
        print(m)

    print(m)
    print(oracle_count)


if __name__ == "__main__":
    attack()
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="solve_py" button-text="Show solve.py" toggle-text=solve_py %}
## Misc stuff
### Theme
In the blog post I mentioned that we need a know plaintext block. To create a not-so-obvious one I thought about various ideas like zipping or drawing the flag in a small png. But all the ideas end up with one problem: The final file is too large. Testing with a oversea connection with optimized IO, I can only reasonably get ~200 bytes over 10 minutes, and we wish to make sure the challenge can be solved below that timeframe from everywhere. @maple3142 give me the idea of using json, and along with the flag format, that would make up a full block. Initially it's something like `{'flag':...` but I then realize that the python json module adds a space after the colon, so I choosed key instead, and the theme just grow from there =D Hopefully it's not too weird and enjoyable.

### Server misconfigure
It is actually not intended for the server to have such a short timeout. As mentioned in the main article, it took 40 second even for an optimized solver to solve 1 block, so a 30 second timer is pretty unreasonable. I didn't notice that the server have an timeout initially, but soon someone solved it, so it's too late at this point to change that. My justification though is that you can leak different part of the flag across multiple connections, so technically this shouldn't add too much complexity to the solve. But I do still appoligies for the inconvinent that this brings. 
### Unintended Solution
After the competition ended, @mouthon and @4yn mentioned that there is an unintended solution to this challenge. If we look at the line `_Y = message[(block_count-2)*N+(X%N)]`, notice that if block_count is less then 2, the index would be negative. Thanks to the wonderful property of python negative indexing, this would actually still run, but get the bytes in the same block as X. This provides a lot of information about the single block. Again, this proves how careless I am... The detail of this attack is left as an exercise to the reader.

## Appendix A - the proper padding and attack
In the main article, I mentioned that the challenge is easier if implemented correctly. Diffing the two files (this challenge and the correct implementation) shows the following:

```diff
$ diff chal.py chal2.py
43,44c43,47
<     if (Y != _Y and Y != _Y^1):
<         raise ValueError("Incorrect Padding")
---
>     if (Y != _Y and (Y != _Y^1 or _Y != X) ):
>             raise ValueError("Incorrect Padding")
```

It merely adds a check to verify that the xor with 1 case only happens when the indexed byte and the last byte collides. This eliminates the confusion on the last bit, so the full flag can be leaked using the first method. The corresponding solve script is as follows (just executing the first part of the exploit and leak the whole flag).

{% capture solve2_py %}
```python
from pwn import *
from Crypto.Util.number import long_to_bytes
import time

N = 16

p = process("./chal2.py")
#p = remote("s.maple3142.net", 1337)

p.recvuntil(b"key: ")
cipher = p.recvline()
cipher = bytes.fromhex(cipher.decode())
p.recvline()
p.recvline()

IV = cipher[:16]
FB = cipher[16:32]
Z = b"\x00"*16
I = [255]*16
known = b'{"key": "hitcon{'[:16]
IV0 = xor(IV, known)

oracle_count = 0

def oracle(m):
    global oracle_count
    oracle_count += 1
    p.sendline(m.hex().encode())
    return not b"weirdo" in p.recvline()

# async send to reduce network lag
def oracle_multi(ms):

    # res = [oracle(m) for m in ms]
    # return res

    global oracle_count
    l = len(ms)
    oracle_count += l
    for m in ms:
        p.sendline(m.hex().encode())
    res = [0] * l
    for i in range(l):
        res[i] = not b"weirdo" in p.recvline()
    return res

offset_db = [-1 for i in range(16)]

def get_offset_db():
    cur = 0;
    for i in range(256):
        if not -1 in offset_db:
            break
        ciphers = []
        for offset in range(16):
            OFF = (offset ^ FB[-1]) % 16
            check = I[:]
            check[offset] = 0
            cipher = xor(IV0, check, i) + FB + xor(IV0, i) + FB
            ciphers.append(cipher)
        res = oracle_multi(ciphers)
        if res.count(True) == 1:
            offset = res.index(True)
            OFF = (offset ^ FB[-1]) % 16
            offset_db[OFF] = i
    return offset_db


def oracle_block(BIV, BC):
    res = [0] * 16

    for offset in range(16):
        # get top 7 bit
        real_offset = (offset ^ BC[-1]) % 16
        IVL = xor(IV0, offset_db[offset])
        top_7 = -1
        ciphers = []
        for diff in range(0, 256):
            check = list(BIV[:])
            check[real_offset] ^= diff
            cipher = xor(BIV, check) + BC + IVL + FB
            ciphers.append(cipher)

        res2 = oracle_multi(ciphers)
        result = list(zip(res2, range(0, 256)))
        for ora, diff in result:
            if ora:
                print(offset, diff)
                top_7 = (diff ^ BIV[real_offset] ^ offset_db[offset])
                res[real_offset] = top_7
                break
        else:
            # honestly I don't know what happned here
            # Sometime things just fall through for some reason...
            raise ValueError("Padding not found")

    return res

def attack():
    offset_db = get_offset_db()
    print(offset_db, oracle_count)
    m = known
    for loc in range(32, len(cipher), 16):
        m+=bytes(oracle_block(cipher[loc-16:loc], cipher[loc:loc+16]))
        print(m)

    print(m)
    print(oracle_count)


if __name__ == "__main__":
    attack()
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="solve2_py" button-text="Show solve.py" toggle-text=solve2_py %}
## References and Attribution
- Thanks @maple3142 for testing and giving me ideas on various parts
