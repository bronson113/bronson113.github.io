---
layout: post
title: b01lersCTF 2024 Author Writeup
tag:
  - CTF
  - Reverse
  - Crypto
  - My Challenge
---
# b01lersCTF 2024 Author Writeup
 
## Overview
 
Time flies. Suddenly it's been one full year since the last b01lersCTF. This year's edition featured A LOT more challenges and seems like an overall success. Prop to the new President ([@Gabe](https://gabri3l.net/)) for organizing the whole event!
 
This year I created 5 challenges for b01lersCTF, and I hoped that everyone enjoyed them.
 
<!--more-->
 
Without further ado, here are the writeups for my challenges. The source code for all of the challenges can be found [HERE](https://github.com/bronson113/My_CTF_Challenges/tree/main/b01lersCTF2024)!
 
## Reverse
 
### js-safe
 
```plaintext
Crack the safe...
 
`http://gold.b01le.rs:4006`
Solves: 84 solves / 355 points
```
 
When you visit the website, you'll see a numpad. Now let's try to click some buttons. You'll notice that it checks if you're number is correct when you've entered 6 "digits". Notice that the check is done on the front end, hence we have access to the full logic. Now, the source is unreadable, and some anti-debugging seems to be in place. One way is to go backward. You can find some mention of CryptoJS in the source file. We can "guess" that that's where our flag is decrypted and displayed. Right before that, there is a sequence of `&=` with a variable. This checks if the results are all true to then call our decrypted function. This should be the key to our solution.
 
Now after reconstructing all the constants from the obfuscated code, we can get a picture of how the password is checked. 
 
```
let pass = true;
pass&=(pw[4] == (pw[1] - 4));
pass&=(pw[1] == (pw[0] ^ 68));
pass&=(pw[0] == (pw[2] - 7));
pass&=(pw[3] == (pw[2] ^ 37));
pass&=(pw[5] == (pw[0] ^ 20));
pass&=(pw[4] == (pw[1] - 4));
pass&=(pw[0] == (pw[3] ^ 34));
pass&=(pw[0] == (pw[2] - 7));
pass&=(pw[0] == (pw[5] + 12));
pass&=(pw[2] == (pw[4] + 71));
pass&=(pw[2] == (pw[5] ^ 19));
pass&=(pw[5] == (pw[3] ^ 54));
pass&=(82 == (pw[3]));
```
 
We then retrieve the password by solving those constraints. This can be done with any sat solver, or by hand since there are only 6 digits. The twist here is that the password isn't actually just digits, but contains letters as well. If you now enter the password to the function itself through `addToPassword` function, the program will decrypt the flag for us!
 
`bctf{345y-p4s5w0rd->w<}`
 
### catch me if you can
 
```plaintext
I give you this flag generator, but it's too slow. You need to speed up to catch me =D
 
Solves: 6 solves / 493 points
```
 
We are given a pyc file, but pycdc can't decompile it. It seems like this file uses some sort of match statements, so pycdc can't decompile it back into the python source. The other thing is that all the variable names seem to be obfuscated.
 
After some reversing, you'll notice that the file clearly splits into two parts. 
An array is first constructed, acting like a key of some sort. 
Then, each value is xored with a value that's generated using a complicated algorithm. However, the later the character, the longer the algorithm seems to take to finish. So our goal is to speed up this algorithm.
 
Notice that there is a weird try-except-finally block in the script. In fact, the challenge is intentionally triggering a divide by zero exception and using that to change the program flow. After some de-obfuscation, the control flow looks like this (with i being the current loop ID):
 
```python
try:
 for j in range(25, 50):
 if j/(j-i) == 1: random.seed(j)
 n = 3 ** i
except:
 n = n ** 3
finally:
 n = 3 ** i # *This line shouldn't be here
 some_alg(n) # apply that function n iterations to get our key
```
 
> \*: The given program file actually won't print out the full flag, which I only discovered after the competition had ended.
> Seems like 6 teams guessed my intention and still ended up with a solution. This is an oversight on my part, as the encoded flag is generated in another script without that. 
 
Now here is the pseudocode of the algorithm:
 
```python
def some_alg(n):
 a, b, c = 1, 2, 3
 mod = 1000000007
 for i in range(n):
 match (i%3, i%5):
 case (0, 0):
 a, b, c = b, c, (a)%mod
 case (0, _):
 a, b, c = b, c, (a+b+c)%mod
 case (1, _):
 a, b, c = b, c, (a+b)%mod
 case (2, _):
 a, b, c = b, c, (a+c)%mod
 return a
```
 
The algorithm is similar to a fibonacci sequence (imo), but more complicated. Firstly, the state transition is not fixed, but in a fizzbuzz like manner. In addition, three previous states are used to derive the next state. Thankfully, all transition is modded, so the result won't grow extremely large.
 
Despite the difference to the normal fibonacci sequence, you can still model 15 iterations of this algorithm as a transition matrix, and use repeated squaring on that matrix to get results faster.
However, when the iteration count is too high (as it's expected to go to $3^{25^{3\times 25}}$), The power itself is hard to compute. The trick is to reduce this using the multiplicative order of the matrix, which turns out to be our mod squared and get the result back really fast.
You still need to be aware of some minor details though, since the matrix represents 15 iterations, you'll need to be careful when working with the remainder. Personally, I did the iteration count mod ${15\times mod^2}$ to avoid the issue, but there might be some other ways as well. I know that some teams used some very different modulo and still got the same result (like mod+1).
 
`bctf{we1rd_pyth0nc0d3_so1v3_w1th_f4s7_M47r1x_Mu1t}`
 
{% capture catch_solve %}
 
```python
import sys
import random
 
target = [96, 98, 68, 160, 172, 115, 20, 108, 25, 122, 208, 71, 158, 63, 233, 59, 180, 165, 115, 203, 177, 17, 166, 196, 255, 127, 70, 172, 55, 11, 204, 20, 198, 31, 60, 167, 17, 1, 132, 106, 195, 19, 38, 151, 203, 163, 211, 27, 73, 98]
 
mod = 1000000007
F = GF(mod)
transitionA = matrix(F, [
 [0, 1, 0],
 [0, 0, 1],
 [1, 1, 1]
 ]).T
transitionB = matrix(F,[
 [0, 1, 0],
 [0, 0, 1],
 [1, 1, 0]
 ]).T
transitionC = matrix(F,[
 [0, 1, 0],
 [0, 0, 1],
 [1, 0, 1]
 ]).T
transitionD = matrix(F,[
 [0, 1, 0],
 [0, 0, 1],
 [1, 0, 0]
 ]).T
 
def gen_remain(x):
 total_transition = matrix.identity(F, 3)
 for i in range(x):
 if i%5 == 0 and i%3 == 0:
 total_transition = total_transition * transitionD
 elif i%3 == 0:
 total_transition = total_transition * transitionA
 elif i%3 == 1:
 total_transition = total_transition * transitionB
 else:
 total_transition = total_transition * transitionC
 return total_transition
 
 
 
T = gen_remain(15)
initial = vector(F, [1, 2, 3])
order = T.multiplicative_order()
F2 = Zmod(order*15)
 
def not_fibonacci(count):
 return int((initial * (T**(int(count)//15)) * gen_remain(int(count)%15))[0])
 
base = 3
 
result = []
for i in range(0, 50):
 try:
 for j in range(25, 50):
 random.seed(j / (j-i))
 iter_count = base ** (i)
 except ZeroDivisionError:
 iter_count = F2(iter_count ** base)
 finally:
 key = not_fibonacci(iter_count)
 
 flag = (target[i]) ^^ (key & 0xff)
 print(chr(flag), end="")
 sys.stdout.flush()
```
 
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="catch_solve" button-text="Show solve.sage" toggle-text=catch_solve%}
 
## Crypto
 
### choose the param
 
```plaintext
I wounder why we need to specify parameter length in the spec...
 
`nc gold.b01le.rs 5001`
Solves: 46 solves / 432 points
```
 
```python
#!/bin/python3
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from secret import flag
import os
 
 
def Encrypt(key, message, nonce):
 cipher = AES.new(key, AES.MODE_CTR, nonce=long_to_bytes(nonce))
 return cipher.encrypt(message).hex()
 
 
def chal():
 key = os.urandom(16)
 print("Treat or Trick, count my thing. ")
 nonce_counter = 1
 print(Encrypt(key, flag, nonce_counter))
 while True:
 nonce_counter += 1
 to_enc = input("Give me something to encrypt: ")
 print(Encrypt(key, bytes.fromhex(to_enc), nonce_counter))
 
 
if __name__ == "__main__":
 chal()
```
 
This challenge is quite straightforward. We are given a service that will encrypt the flag using primes of the length of our choice. It's clear that with a small prime, we can easily factor N, and recover m. However, since the flag is padded on both ends, we won't gain any useful information if our prime is too small, or do we?
 
If we check what we actually retrieved from the RSA decryption, we get $ m = c^{d} \mod{n} $. This means that we get $m \mod{n}$ for each query. If we have multiple pairs of these m, we can recover the full m using Chinese Remainder Theorem. 
 
`bctf{dont_let_the_user_choose_the_prime_length_>w<}`
 
```python
from Crypto.Util.number import long_to_bytes
from sage.all import Integer, CRT
from pwn import *
 
p = remote("gold.b01le.rs", 5001)
 
ms = []
ns = []
bits = 500*8
prime_len = 48
print(bits//prime_len)
for i in range(bits//prime_len):
 p.recvuntil("primes> ")
 p.sendline(str(prime_len))
 
 n = int(p.recvline().split(b" = ")[-1], 16)
 e = int(p.recvline().split(b" = ")[-1], 16)
 c = int(p.recvline().split(b" = ")[-1], 16)
 print(n, e, c)
 
 (P, _), (Q, _) = Integer(n).factor()
 d = pow(e, -1, (P-1)*(Q-1))
 m = pow(c, int(d), n)
 ms.append(m)
 ns.append(n)
 
flag = long_to_bytes(CRT(ms, ns))
print(flag[200:-200])
```
 
### count the counter
 
```plaintext
000 001 010 011 100...
 
`nc gold.b01le.rs 5002`
Solves: 26 solves / 466 points
```
 
```python
#!/bin/python3
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from secret import flag
import os
 
 
def Encrypt(key, message, nonce):
 cipher = AES.new(key, AES.MODE_CTR, nonce=long_to_bytes(nonce))
 return cipher.encrypt(message).hex()
 
 
def chal():
 key = os.urandom(16)
 print("Treat or Trick, count my thing. ")
 nonce_counter = 1
 print(Encrypt(key, flag, nonce_counter))
 while True:
 nonce_counter += 1
 to_enc = input("Give me something to encrypt: ")
 print(Encrypt(key, bytes.fromhex(to_enc), nonce_counter))
 
 
if __name__ == "__main__":
 chal()
```
 
In this challenge, our flag is encrypted using a nonce. We can then supply our own message to be encrypted, but each time the nonce is incremented. Normally this wouldn't pose an issue, as you would assume that with different nonce, CTR mode will produce different results. To verify this, we'll need to look into how the nonce is used to create our counter.
 
In [pycryptodome](https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Cipher/_mode_ctr.py#L349), the full counter is created as nonce concatenated with a counter.
Namely, the counter is in the form `|<nonce>|<counter>|`.
However, the length of each section isn't defined. Instead, the nonce is first taken, then the length of the counter is set to make the whole counter length to be 16 bytes.
 
Now notice that if the nonce ends in a null byte, it'll act the same if we truncated out the null byte from the end. Therefore, if we wait until the challenge gives us 256 as the nonce, the nonce will be represented and '\x01\x00', which will be the same as the initial '\x01' nonce.
 
The rest is trivial if you know how CTR mode works. Since the key stream of the two ciphers is the same. We can xor the results from two encryption to remove the stream key and get back our result.
 
`bctf{there_is_a_reason_for_random_nonce_and_with_fixed_length_8c6bf5a1398d1f1d95f1}`
 
```python
from pwn import remote, xor
 
p = remote("gold.b01le.rs", 5002)
# trick or treat
p.recvline()
 
# Initial Cipher
enc = p.recvline().strip()
enc_bytes = bytes.fromhex(enc.decode())
print(f"Encrypted: {enc_bytes}")
 
# Wait until nonce wrap around
skip = 254
for i in range(skip):
 p.sendline(b"00")
for i in range(skip+1):
 p.recvuntil(b"Give me")
 
# Send message will all null bytes
p.sendline(b"0"*len(enc))
null_encrypt = p.recvline().split(b": ")[-1]
null_encrypt_bytes = bytes.fromhex(null_encrypt.decode())
print(f"Encrypt Null: {null_encrypt_bytes}")
 
# xor out the ctr cipher stream
print("Flag: ", xor(enc_bytes, null_encrypt_bytes))
```
 
### propagating counter block chaining
 
```plaintext
Another counter mode challenge
 
`nc gold.b01le.rs 5003`
Solves: 11 solves / 487 points
```
 
{% capture counter_chal %}
 
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from functools import reduce
from secret import flag
import os
import json
 
BLOCK_SIZE = 16
key_ctr1 = os.urandom(BLOCK_SIZE)
key_ctr2 = os.urandom(BLOCK_SIZE)
key_cbc = os.urandom(BLOCK_SIZE)
nonce1 = os.urandom(8)
nonce2 = os.urandom(8)
 
def AES_ECB_enc(key, message):
 enc = AES.new(key, AES.MODE_ECB)
 return enc.encrypt(message)
 
def AES_ECB_dec(key, message):
 enc = AES.new(key, AES.MODE_ECB)
 return enc.decrypt(message)
 
# Returning a block each time
def get_blocks(message):
 for i in range(0, len(message), BLOCK_SIZE):
 yield message[i:i+BLOCK_SIZE]
 return
 
# Takes any number of arguements, and return the xor result.
# Similar to pwntools' xor, but trucated to minimum length
def xor(*args):
 _xor = lambda x1, x2: x1^x2
 return bytes(map(lambda x: reduce(_xor, x, 0), zip(*args)))
 
 
def counter(nonce):
 count = 0
 while count < 2**(16 - len(nonce)):
 yield nonce + str(count).encode().rjust(16-len(nonce), b"\x00")
 count+=1
 return
 
 
def encrypt(message):
 cipher = b""
 iv = os.urandom(BLOCK_SIZE)
 prev_block = iv
 counter1 = counter(nonce1)
 counter2 = counter(nonce2)
 for block in get_blocks(pad(message, BLOCK_SIZE)):
 enc1 = AES_ECB_enc(key_ctr1, next(counter1))
 enc2 = AES_ECB_enc(key_cbc, xor(block, prev_block, enc1))
 enc3 = AES_ECB_enc(key_ctr2, next(counter2))
 enc4 = xor(enc3, enc2)
 prev_block = xor(block, enc4)
 cipher += enc4
 
 return iv + cipher
 
def decrypt(cipher):
 message = b""
 iv = cipher[:16]
 cipher_text = cipher[16:]
 
 prev_block = iv
 counter1 = counter(nonce1)
 counter2 = counter(nonce2)
 for block in get_blocks(cipher_text):
 dec1 = AES_ECB_enc(key_ctr2, next(counter2))
 dec2 = AES_ECB_dec(key_cbc, xor(block, dec1))
 dec3 = AES_ECB_enc(key_ctr1, next(counter1))
 message += xor(prev_block, dec2, dec3)
 prev_block = xor(prev_block, dec2, block, dec3)
 
 return unpad(message, BLOCK_SIZE)
 
def main():
 certificate = os.urandom(8) + flag + os.urandom(8)
 print(f"""
*********************************************************
 
Certificate as a Service
 
*********************************************************
 
Here is a valid certificate: {encrypt(certificate).hex()}
 
*********************************************************""")
 while True:
 try:
 cert = bytes.fromhex(input("Give me a certificate >> "))
 if len(cert) < 32:
 print("Your certificate is not long enough")
 
 message = decrypt(cert)
 if flag in message:
 print("This certificate is valid")
 else:
 print("This certificate is not valid")
 except Exception:
 print("Something went wrong")
 
if __name__ == "__main__":
 main()
```
 
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="counter_chal" button-text="Show chal.py" toggle-text=counter_chal%}
 
We can first inspect the encrypt function. We see that two different sets of counters are used, and some sort of block chaining is used. The output of the counters is used to xor both the input and the output of the block cipher. Additionally, the results from the previous block are xored into the input of the next block. In essence, it's a chaining CTR-PCBC-CTR mode.
 
Other than the encrypt function, this challenge is quite a barebone example of a padding oracle attack. and So the main difficulty will be in figuring out how to apply the attack on the new CTR-PCBC-CTR mode.
 
Let's first ignore the CTR modes as we should be able to adjust for them later. How does PCBC mode padding oracle work? If we look at the figure, you'll notice that controlling IV allows us to control the output of each block, since the result will snake through each plaintext and influence the next block accordingly. This can be used to directly influence the padding, and proceed with the normal padding oracle attack.

![PCBC_encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PCBC_encryption.svg/1920px-PCBC_encryption.svg.png#_blog_img_darkmode_invert)
![PCBC_decryption](https://upload.wikimedia.org/wikipedia/commons/thumb/5/5b/PCBC_decryption.svg/1920px-PCBC_decryption.svg.png#_blog_img_darkmode_invert)
(Image quoted from [wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC)))
 
Now we need to worry about the counters. We can recall that CTR acted like a stream cipher, meaning that characters at the correct place will be decrypted correctly. Naturally, if we keep the ciphertext where it should be, the decryption process will help us decrypt the correct plaintext, and we don't need to worry about them. Since controlling the IV allows us to control every block of the output, we can choose which block we want the padding to be at, and resolve this issue. See the solve script for more details.
 
`bctf{adding_ctr_mode_doesn't_provide_any_security_to_padding_oracle..._c850d60d210169}`
 
{% capture counter_solve %}
```python
# ctr - pcbc - ctr
# but the chaining is done from ctr output
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import *
import os
 
 
BLOCK_SIZE = 16
 
def oracle(p, ct):
 p.sendline(ct.hex())
 
def oracle_res(p, count):
 result = []
 for i in range(count):
 p.recvuntil(b">> ")
 res = p.recvline()
 if b"Something went wrong" in res:
 result.append(False)
 else:
 result.append(True)
 return result
 
def oracle_block(p, iv, ct):
 guess = []
 for l in range(1, 17):
 for c in range(256):
# print(bytes(guess+[c])[::-1])
 new_iv = xor(bytes([c]+guess[::-1]).rjust(16,b"\x00"), bytes([l]*16), iv)
 oracle(p, new_iv+ct)
 
 res = oracle_res(p, 256)
 
 for c in range(256):
 if res[c]:
 guess.append(c)
 break
 print(bytes(guess[::-1]))
 return bytes(guess[::-1])
 
def main():
# p = remote("127.0.0.1", "5003")
 p = remote("gold.b01le.rs", "5003")
# p = process(["python3", "./src/chal.py"])
 p.recvuntil(b"valid certificate: ")
 cipher_text = bytes.fromhex(p.recvline().decode())
 iv, ct = cipher_text[:16], cipher_text[16:]
 flag = b"".join((oracle_block(p, iv, ct[:i*16]) for i in range(1, len(ct)//16+1)))
 print(flag)
 
 
if __name__ == "__main__":
 main()
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="counter_solve" button-text="Show solve.py" toggle-text=counter_solve%}
 
