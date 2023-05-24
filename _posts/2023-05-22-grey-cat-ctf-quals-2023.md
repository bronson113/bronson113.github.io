---
title: Greycat CTF Quals 2023 Writeup
---

# Greycat CTF Quals 2023 Writeup
## Overview
Last weekend, I participated in Grey Cat CTF Qual 2023 with b01lers. We ranked 22nd overall. I think the challenges are interesting and decided to post writeups on the challenges I solved.
I solved 6 crypto and 1 pwn (with help from teammate) during the competition.

Challenge solved after the competition are marked as \[\*\] 

<!--more-->

---
## The Vault
```text
Can you break into a double-encrypted vault?

- qvinhprolol

nc 34.124.157.94 10591
solves: 100/454
```

We are given chall.py.

{% capture vault_chal_py %}
```python
from hashlib import sha256
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from math import log10

FLAG = "grey{fake_flag}"

n = pow(10, 128)
def check_keys(a, b):
    if a % 10 == 0:
        return False

    # Check if pow(a, b) > n
    if b * log10(a) > 128:
        return True
    return False

def encryption(key, plaintext):
    iv = "Greyhats".encode()
    cipher = AES.new(key, AES.MODE_CTR, nonce = iv)
    return cipher.encrypt(plaintext)

print("Welcome back, NUS Dean. Please type in the authentication codes to open the vault! \n")

a = int(input("Enter the first code: "))
b = int(input("Enter the second code: "))

if not check_keys(a, b):
    print("Nice try thief! The security are on the way.")
    exit(0)

print("Performing thief checks...\n")
thief_check = get_random_bytes(16)

# Highly secure double encryption checking system. The thieves stand no chance!
x = pow(a, b, n)
first_key = sha256(long_to_bytes(x)).digest()
second_key = sha256(long_to_bytes(pow(x, 10, n))).digest()

if thief_check == encryption(first_key, encryption(second_key, thief_check)):
    print("Vault is opened.")
    print(FLAG)
else:
    print("Stealing attempts detected! Initializing lockdown")
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="vault_chal_py"
    button-text="Show chall.py" toggle-text=vault_chal_py %}
		
Since the encryption uses CTR with the same nonce, if we make first_key == second_key, the encryption will cancel out itself.

```python
# Highly secure double encryption checking system. The thieves stand no chance!
x = pow(a, b, n)
first_key = sha256(long_to_bytes(x)).digest()
second_key = sha256(long_to_bytes(pow(x, 10, n))).digest()
```

Observing how the two keys are generated. 
Therefore, we just need to find `a` and `b` that makes $x \equiv x^{10} \mod{n}$. Naturally, we would want to make x = 1.

One method is to simply make $a \equiv 1 \mod{n}$, since there is no bounding check on a, if we make a = n+1, and b sufficiently large, we can pass the keys check.

The other way is to utilize [eular's theorm](https://en.wikipedia.org/wiki/Euler%27s_theorem), which states $x^{\phi({n})} \equiv 1 \mod(n)$. By setting $b = \phi({n})$ and supply a sufficiently large a, we can solve the challenge.

{% capture vault_solve_py %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import *

from pwn import *
nc_str = "nc 34.124.157.94 10591"
_, host, port = nc_str.split(" ")
p = remote(host, int(port))


p.sendline(str(10**128+1))
p.sendline(str(10))
p.interactive()
#grey{th3_4n5w3R_T0_Th3_3x4M_4nD_3v3ry7H1N6_1s_42}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="vault_solve_py"
    button-text="Show solve.py" toggle-text=vault_solve_py %}
	
---
## Greycat Trial
```text
In the sacred realm of GreyCat, amidst the swirling mists of arcane power, a momentous trial unfolds, seeking the one destined to bear the mantle of the next mighty GreyCat wizard.

- qvinhprolol

nc 34.124.157.94 10592 
solves: 63/454
```

{% capture trial_chal_py %}
```python
from random import randint

FLAG = "grey{fake_flag}"

print("Lo and behold! The GreyCat Wizard, residing within the Green Tower of PrimeLand, is a wizard of unparalleled prowess")
print("The GreyCat wizard hath forged an oracle of equal potency")
print("The oracle hath the power to bestow upon thee any knowledge that exists in the world")
print("Gather the requisite elements to triumph over the three trials, noble wizard.")
print()

a = int(input("The first element: "))
b = int(input("The second element: "))
print()

all_seeing_number = 23456789

# FIRST TRIAL
if b <= 0:
    print("Verily, those who would cheat possess not the might of true wizards.")
    exit(0)

if pow(all_seeing_number, a - 1, a) != 1:
    print("Alas, thy weakness hath led to defeat in the very first trial.")
    exit(0)

# SECOND TRIAL
trial_numbers = [randint(0, 26) for i in range(26)]

for number in trial_numbers:
    c = a + b * number
    if pow(all_seeing_number, c - 1, c) != 1:
        print("Thou art not yet strong enough, and thus hast been vanquished in the second trial")
        exit(0)

# THIRD TRIAL
d = a + b * max(trial_numbers)
if (d.bit_length() < 55):
    print("Truly, thou art the paramount wizard. As a reward, we present thee with this boon:")
    print(FLAG)
else:
    print("Thou art nigh, but thy power falters still.")
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="trial_chal_py"
    button-text="Show chall.py" toggle-text=trial_chal_py %}
		
Notice that the "trial" is a [fermat primality test](https://en.wikipedia.org/wiki/Fermat_primality_test). While there exists some exceptions ([Carmichael numbers](https://en.wikipedia.org/wiki/Carmichael_number)), all we need to do is to find a long enough sequence of prime in arithmetic progression. A quick google search will lead to [this wiki page](https://en.wikipedia.org/wiki/Primes_in_arithmetic_progression), where there are a example with length of 21 included. 

$5749146449311 + 26004868890n$

```python
>>> [pow(23456789, 5749146449311 + 26004868890*i - 1, 5749146449311 + 26004868890*i) for i in range(26)]
[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5969533133056, 1942548458790, 3086279453216, 1, 774068330828]
```

Now notice that in the trial, the trial numbers are randomly chosen, so we don't need to perfectly pass every test. With the example from wikipedia, 22 out of 26 numbers will pass the primality test, which gives us a $({22}/{26})^{26} \approx 1.3\%$ chance of passing the trail every single time. With enough trys, the odd will stand in our favor. (On average 76 trys will be needed).

{% capture trial_solve_py %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import *

from pwn import *

for i in range(10000):
    print(i)
    nc_str = "nc 34.124.157.94 10592"
    _, host, port = nc_str.split(" ")
    p = remote(host, int(port))

    p.sendline(b"5749146449311")
    p.sendline(b"26004868890")

    s = p.recvall()
    if b"grey{" in s:
        print(s)
        break
#grey{Gr33N-tA0_The0ReM_w1z4rd}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="trial_solve_py"
    button-text="Show solve.py" toggle-text=trial_solve_py %}


---
## OT
```text
Oblivious Transfer is amazing :D

- mechfrog88

nc 34.124.157.94 10521 
solves: 41/454
```
{% capture ot_chal_py %}
```python
import secrets
import hashlib
from Crypto.Util.number import isPrime, long_to_bytes

FLAG = b'grey{fake_flag}'

e = 0x10001

def checkN(N):
    if (N < 0):
        return "what?"
    if (N.bit_length() != 4096):
        return "N should be 4096 bits"
    if (isPrime(N) or isPrime(N + 23)):
        return "Hey no cheating"
    return None

def xor(a, b):
    return bytes([i ^ j for i,j in zip(a,b)])

def encrypt(key, msg):
    key = hashlib.shake_256(long_to_bytes(key)).digest(len(msg))
    return xor(key, msg)

print("This is my new Oblivious transfer protocol built on top of the crypto primitive (factorisation is hard)\n")
print("You should first generate a number h which you know the factorisation,\n")
print("If you wish to know the first part of the key, send me h")
print(f"If you wish to know the second part of the key, send me h - {23}\n")

N = int(input(("Now what's your number: ")))

check = checkN(N)
if check != None:
    print(check)
    exit(0)

k1, k2 = secrets.randbelow(N), secrets.randbelow(N)
k = k1 ^ k2

print("Now I send you these 2 numbers\n")
print(f"pow(k1, e, N) = {pow(k1, e, N)}")
print(f"pow(k2, e, N+23) = {pow(k2, e, N + 23)}\n")

print("Since you only know how to factorise one of them, you can only get one part of the data :D\n")
print("This protocol is secure so sending this should not have any problem")
print(f"flag = {encrypt(k, FLAG).hex()}")
print("Bye bye!")
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="ot_chal_py"
    button-text="Show main.py" toggle-text=ot_chal_py %}

Since we need to decode both rsa encryption, we'll need to know the factorization of both N and N+23. However, the server checked to make sure that N and N+23 are both prime. In order to constuct such number, we can try to find a number k where we know the factorization of k, but k+1 is a prime, then N will be 23k and 23(k+1) respsectively. 

The way I construct the number is by building up primes from 2, then bruteforce the last prime so that k+1 is a prime. With that, we have the factorization of both N and N+23. Simply by calculating the phi and decrypt the rsa in both cases, and decrypt the flag using the same function, we can recover the flag.

{% capture ot_solve_py %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.number import isPrime
from sage.all import *
import secrets
import hashlib
from Crypto.Util.number import isPrime, long_to_bytes

from pwn import *

# construct smooth prime
p1 = 2
a = 2
while int(p1*23).bit_length() < 4060:
    p1*= next_prime(a)
    a = next_prime(a)

print(a)
b = next_prime((1<<4095)// 23 // p1)
counter = 1
while not isPrime(p1*b+1) or int(23*p1*b).bit_length() < 4096:
    counter+=1
    if(counter%100000 == 0):
        print(counter)
        print(int(23*p1*b).bit_length())
    b = next_prime(b)

print(a)
k = 23*(p1*b)
print(a, b)
print(int(k).bit_length())

nc_str = "nc 34.124.157.94 10521"
_, host, port = nc_str.split(" ")
p = remote(host, int(port))

p.sendline(str(int(k)))

p.recvuntil(b"pow(k1, e, N) = ")
c1 = int(p.recvline())
p.recvuntil(b"pow(k2, e, N+23) =")
c2 = int(p.recvline())
p.recvuntil(b"flag = ")
flag = bytes.fromhex(p.recvline().strip().decode())

print(c1, c2)

# key 1 (N)
d1 = 1
for i in range(a):
    if isPrime(i):
        d1*=i-1
d1*=b-1
d1*=23
k1 = pow(c1, int(pow(65537, -1, int(d1))), k)

# key 2 (N+23)
d2 = (23-1)*(p1*b)
k2 = pow(c2, int(pow(65537, -1, int(d2))), k+23)

k = int(k1)^int(k2)

# since the encryption is just xor with the hash of the key, 
# it also served as a decryption function
def decrypt(key, msg):
    key = hashlib.shake_256(long_to_bytes(key)).digest(len(msg))
    return xor(key, msg)

print(decrypt(k, flag))
#grey{waitttt_I_thought_factorization_is_hard!!?_bSug9kksE3W9SrPL}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="ot_solve_py"
    button-text="Show solve.py" toggle-text=ot_solve_py %}
		
---
## PLCG
```text
Add some probability to spice up the game

- mechfrog88

nc 34.124.157.94 10531 
solves: 32/454
```

{% capture plcg_chal_py %}
```python
#!/usr/bin/python3
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys

FLAG = b'grey{fake_flag}'

while True:
    sample = [3, 80] + [secrets.randbelow(256) for _ in range(2)]
    if len(sample) == len(set(sample)) and 0 not in sample:
        break

def getBiasRandomByte():
    return secrets.choice(sample)

def getRandomByte():
    n = 0; g = 0
    for _ in range(20):
        n += getBiasRandomByte() * getBiasRandomByte()
    for _ in range(20):
        g = (g + getBiasRandomByte()) % 256
    for _ in range(n):
        g = (getBiasRandomByte() * g + getBiasRandomByte()) % 256
    return g

def encrypt(msg):
    key = bytes([getRandomByte() for _ in range(6)])
    cipher = AES.new(pad(key, 16), AES.MODE_CTR, nonce=b'\xc1\xc7\xcc\xd1D\xfbI\x10')
    return cipher.encrypt(msg)

print("Hello there, this is our lucky numbers")
print(" ".join(map(str,sample)))

s = int(input("Send us your lucky number! "))

if not (0 <= s <= 10):
    print("I dont like your number :(")
    exit(0)

for i in range(s):
    print("Here's your lucky flag:", encrypt(FLAG).hex())
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="plcg_chal_py"
    button-text="Show main.py" toggle-text=plcg_chal_py %}
		
In this challenge, the key used to encrypt the flag is generated from a custom-made prng generator. Notice that in the last step, if we get some $2^x$ number as the bias random byte, the previous result of g will be shifted upward, leaving very little randomness. For example, if one of the vault in sample is 128, then when that is chosen, the output can only be one in 8 values, either the four values with the 8th bit or without the 8th bit. To actually calculate the probablility of each value as the outcome given `sample`, we can model the transition between two steps using a markov chain. 

Assuming that the markov chain converges to stable sufficently fast, I simply apply the transformation matrix on a uniform distribution to see how skewed the output will be given the sample set. I them connect to the server multiple times until a set skewed enough is retrieved. After that, by bruteforcing the possible keys and attempting to decrypt the text gives us the flag. Using the bruteforce script, I get a challenge sample set \[3, 80, 64, 240\] and able to bruteforce the output.
		
{% capture plcg_brute_py %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import *
from sage.all import *

while True:
    try:
        p = remote("34.124.157.94", 10531)
        p.recvline()
        lucky = list(map(int, p.recvline().split(b" ")))
        print(lucky)
        sample = lucky
        # markov chain
        valid_output = [[(i*j+k)%256 for j in sample for k in sample] for i in range(256)]
        transition = matrix(QQ, [[valid_output[i].count(j) for j in range(256)] for i in range(256)]).transpose()/16
        initial = vector(QQ, [1 for i in range(256)])/256
        dist = (transition**100) * initial


        if min(dist) < 1e-5:
            break
        p.close()
    except Exception:
        pass

p.recvuntil(b"! ")
p.sendline(b"10")
for i in range(10):
    print(p.recvline())

p.interactive()
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="plcg_brute_py"
    button-text="Show brute.py" toggle-text=plcg_brute_py %}

{% capture plcg_solve_py %}
```python
#!/usr/bin/python3
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from sage.all import *
import sys

FLAG = b'grey{fake_flag}'

sample = [3, 80, 64, 240]

# markov chain
valid_output = [[(i*j+k)%256 for j in sample for k in sample] for i in range(256)]
transition = matrix(QQ, [[valid_output[i].count(j) for j in range(256)] for i in range(256)]).transpose()/16
initial = vector(QQ, [1 for i in range(256)])/256
dist = (transition**100) * initial

print(dist)
valid_output = []
for i in range(256):
    count = int(dist[i]*1000)
    valid_output += [i for j in range(count)]
print(min(dist))

#[3, 80, 64, 240], taken from brute.sage
res = """
Here's your lucky flag: 5558e88faadbe697d50f09ccd98c1043af0bf8a9e20f5de60dcd5dff0b79ebe9c94ff43c90f24ae2bf5ea060ed3d0ad96b3309e2e06e1a20
Here's your lucky flag: 83080a6358c87c3182893bc174ecc7f53a6cf2c92a4704f5f2392c9868d555588cd7776d29b9493a6b2a2f3a122d43e312f2de2196219200
Here's your lucky flag: e13d21b2c4f224d8dfc17064e6d4fb0db339aea3ab6b65569c50d130808436dd37440c7061d8bb11cea2ab6f0c1c11701be335d42ac394e9
Here's your lucky flag: e6828db5d74e2947812ed1c3a39b39db47c887c728ff50fb384662301a129e6437ca89b37e8df45765a1c6c112beda3bf517108d2996a4f8
Here's your lucky flag: 609f1f2134e9f6f5b294c40cb37eb806ed441fc2d47f209fcc41cf462bfd46d1facf29ccbfcd66d98d959bb812b304f8d90f5fd9d16671be
Here's your lucky flag: 960bb72692a12a7b52cd9c4e70c99a70204112608e6dd53011be2e6d413a4af991fe30f2829a8a2fae7c2ece1bfd6539db0574bb3d396765
Here's your lucky flag: 587f8b03596c4ca80ab30fdb8efc6d8c6cff385870f10c398ef0b9c177f0b8b487d6a03bc097bd67aabd6b409240378e7abc8cb875fd7b36
Here's your lucky flag: 02c7e9edfc0721693c2f60ab2f313506ec3d196a9d0617b77371c7f3d34a2d53fd26096b0f58c82d33f40d16eb95daf3628fe9fb70fd21a7
Here's your lucky flag: a223335d57dfe47cffdc8b22dbb99919a49b7fdae6f213f21f6f6454c068dbfb6babb82854e054a27ccee256a40ebf487cb2af474af7411f
Here's your lucky flag: 1edc130b23a9f0d9d042cebc16ec4055e7d25e169e5c0171b5098ec79c4a43c15b91ca6b3fc47e40e6f2cc9d271d3f21a03a9628e50ce34f
"""

enc_flags = [i.split(": ")[-1] for i in res.split("\n")][1:-1]
enc_flags = [bytes.fromhex(i) for i in enc_flags]
print(enc_flags)

counter = 0
while True:
    key = bytes([secrets.choice(valid_output) for _ in range(6)])
    cipher = AES.new(pad(key, 16), AES.MODE_CTR, nonce=b'\xc1\xc7\xcc\xd1D\xfbI\x10')
    for msg in enc_flags:
        dec = cipher.decrypt(msg)
        if b"grey" in dec:
            print(key)
            print(msg, dec)

    counter+=1
    if counter%10000 == 0:
        print(counter)

#b'\x03\xf0\xf0PP\x03'
#b'UX\xe8\x8f\xaa\xdb\xe6\x97\xd5\x0f\t\xcc\xd9\x8c\x10C\xaf\x0b\xf8\xa9\xe2\x0f]\xe6\r\xcd]\xff\x0by\xeb\xe9\xc9O\xf4<\x90\xf2J\xe2\xbf^\xa0`\xed=\n\xd9k3\t\xe2\xe0n\x1a '
#b'grey{G3T_Rand0m_Byte-is_Still_Bi@s_Oof_7nwh8eQfV5e8eZwC}'

```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="plcg_solve_py"
    button-text="Show solve.py" toggle-text=plcg_solve_py %}

---
## Encrypted
```text
Let's just do something simple

- mechfrog88

solves: 22/454
```

{% capture encrypted_chal_py %}
```python
from Crypto.Util.number import bytes_to_long
from secrets import randbits

FLAG = b'fake_flag'

p = randbits(1024)
q = randbits(1024)

def encrypt(msg, key):
    m = bytes_to_long(msg)
    return p * m + q * m**2 + (m + p + q) * key

n = len(FLAG)
s = randbits(1024)

print(f'n = {n}')
print(f'p = {p}')
print(f'q = {q}')
print(f'c1 = {encrypt(FLAG[:n//2], s)}')
print(f'c2 = {encrypt(FLAG[n//2:], s)}')

```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="encrypted_chal_py"
    button-text="Show main.py" toggle-text=encrypted_chal_py %}
		
For this challenge, the encryption is as follow with $p$, $q$, $c_1$, $c_2$ given. 

$$\begin{align}
c_1 &= p \times m_1 + q \times m_1^{2} + (m_1+p+q) \times k  \\ 
c_2 &= p \times m_2 + q \times m_2^{2} + (m_2+p+q) \times k  \\  
\end{align}$$

I start by manipulating the equations around too see how can I simplify it. I know that we're trying to find a small root of the equation (m is significantly smaller than all other parameter) but I'm not sure what I can do. When I try to take mod q on the equation, I found the following relationship. (I'll focus on one copy

$$\begin{align}
c \equiv  p \times m + (m+p) \times k  &\mod{q}\\  
c - p \times m \equiv  (m+p) \times k  &\mod{q}\\  
(c - p \times m) \times (m+p)^{-1} \equiv  k &\mod{q}\\  
\end{align}$$

By combining the two equations together.

$$\begin{align}
(c_1 - p \times m_1) \times (m_1+p)^{-1} &\equiv  k \equiv (c_2 - p \times m_2) \times (m_2+p)^{-1}   &\mod{q}\\  
(c_1 - p \times m_1) \times (m_1+p)^{-1} &\equiv (c_2 - p \times m_2) \times (m_2+p)^{-1}   &\mod{q}\\  
(c_1 - p \times m_1) \times (m_2+p) &\equiv (c_2 - p \times m_2) \times (m_1+p)  &\mod{q}\\  
\end{align}$$

$$\begin{align} 
(c_1 - p \times m_1) \times (m_2+p) - (c_2 - p \times m_2) \times (m_1+p)  &\equiv 0 \mod{q}\\ 
p\times (c_1-c_2) + (c_1 m_2 - c_2 m_1) - p^{2} m_1 + p^{2} m_2 &\equiv 0 \mod{q}\\ 
m_1 (c_2+p^{2}) - m_2 (c_1+p^{2}) - p (c_1 - c_2) &\equiv 0 \mod{q}\\ 
\end{align}$$

After all the manipulation, we can get
$$m_1 (c_2+p^{2}) - m_2 (c_1+p^{2}) - p (c_1 - c_2) - Kq =  0$$
, where $K \in \mathbb{Z}$

We can using this relationship to form the following lattice.
$$\begin{align} 
m_1 (c_2+p^{2}) - m_2 (c_1+p^{2}) - p (c_1 - c_2) - Kq &=  0\\  
m_1 &= m_1\\ 
m_2 &= m_2 \\ 
1 &= 1\\ 
\end{align}$$

$$\begin{align} m_1  \begin{bmatrix}  c_2+p^{2} \\  1 \\ 0 \\ 0 \end{bmatrix}
				 -m_2 \begin{bmatrix} c_1+p^{2} \\  0 \\  -1 \\  0 \\  \end{bmatrix}
				 -\begin{bmatrix} p(c_1 - c_2) \\ 0 \\ 0 \\ -1 \end{bmatrix}
				 - K \begin{bmatrix} q \\ 0 \\ 0 \\ 0 \end{bmatrix}
				 =\begin{bmatrix} 0 \\ m_1 \\ m_2 \\ 1 \end {bmatrix}
				 \end{align} $$

To make the resulting vector balanced, we apply a weight matrixs so that LLL can better find the target vector we want. See the solve script for more detail.
	
{% capture encrypted_solve_sage %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
#from pwn import *

n = 60
p = 154086578594169457435595675666643895734811841080572558765373507236578028216591747533849923751469191596377661004029046877904042460778919103625210259448925051403568654035172094553059686620938995150323671690612067502149750334217640430881837803398594614204799922967620005040202036583050736150941842152536365544084
q = 125017463628708786112045898783989519686518641018787292892390877841668306746146702301981172263729102252453507006240973911324033106244068376643435622158128309826549542204034257871545558185841458407254799884829820319949756220781717646450760642511971882897039183232753628829418868493229485015468373205449789812260
c1 = 31118850289098152832161049930974564440792673516199584784484864528279481500612948601526706062621276262711210497739562987491633664814289725255046485262798604510626941827187912034287402128550018798165331343869198539137692903451118993538977788768945912026980846832254010558073806464461172522295653614635829516912620303901074895536704497550933805653512993413784431814034970399353908315083734783641688845887335175756415452320057666293794222522192970247045775053062573130002154959221285571979645935259561842756575513382500001710093979669436220490166791279222321068474420336287079321260681992725702004322840264333436628467610
c2 = 31118850289098152832161049930974564440792673516199584784484864528279481500612948601526706062621276262711210497739562987491633664814289725255046485262798604510626941817672660832127847041917018566902241465270388458210289299587958256824375312920716794521835108724034002277333245660951027397544591256117371462945925063227877052543505162260331377627961855698406102909764518955398788366432268123471930922870790059289526241832032413046933338032005163677585629816264668273416126506175004091486421225900247767247311587061422436593600806854703842740334379936590431991884721985057366825456467986462930236986239275935656810387114

# LLL (4*4 with weights)
weights = [1, 1/2^240, 1/2^240, 1]
Q = diagonal_matrix(weights)
L = Matrix([
    [c2+p^2, 1, 0, 0],
    [c1+p^2, 0, -1, 0],
    [p*(c1-c2), 0, 0, -1],
    [q, 0, 0, 0]])
L = L*Q
Sol = L.LLL()/Q
print(Sol)

for col in Sol:
    if col[0] == 0 and col[3] == 1:
        print(long_to_bytes(int(col[1]))+long_to_bytes(int(col[2])))

#grey{shortest_crypto_challenge_in_this_ctf_srfrGRUEShP8FKwn}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="encrypted_solve_sage"
    button-text="Show solve.sage" toggle-text=encrypted_solve_sage %}


---
## QRSA
```text
Questionable RSA

 - mechfrog88

solves: 17/454
```
{% capture qrsa_chal_py %}
```python
from Crypto.Util.number import bytes_to_long
from secret import qa, qb, pa, pb

FLAG = b'fake_flag'

class Q:
    d = 41
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def __add__(self, other):
        return Q(self.a + other.a, self.b + other.b)

    def __sub__(self, other):
        return Q(self.a - other.a, self.b - other.b)

    def __mul__(self, other):
        a = self.a * other.a + Q.d * self.b * other.b
        b = self.b * other.a + self.a * other.b
        return Q(a, b)

    def __mod__(self, other):
        # Implementation Hidden
        # ...
        return self

    def __str__(self) -> str:
        return f'({self.a}, {self.b})'

def power(a, b, m):
    res = Q(1, 0)
    while (b > 0):
        if (b & 1): res = (res * a) % m
        a = (a * a) % m
        b //= 2
    return res

p, q = Q(pa, pb), Q(qa, qb)
N = p * q
m = Q(bytes_to_long(FLAG[:len(FLAG)//2]), bytes_to_long(FLAG[len(FLAG)//2:]))
e = 0x10001
c = power(m, e, N)

print(f"N_a = {N.a}")
print(f"N_b = {N.b}")
print(f"C_a = {c.a}")
print(f"C_b = {c.b}")
print(f"e = {e}")
print(f"D = {Q.d}")
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="qrsa_chal_py"
    button-text="Show main.py" toggle-text=qrsa_chal_py %}
#TODO

---
## ROPV
```text
Echo service again??????????

 - jiefeng

nc 139.177.185.41 12335 
solves: 38/454
```
#TODO


---
## write-me-a-book\[\*\]
```text
Give back to the library! Share your thoughts and experiences!

The flag can be found in /flag

- Elma

nc 34.124.157.94 12346 
solves: 30/454
```
#TODO
