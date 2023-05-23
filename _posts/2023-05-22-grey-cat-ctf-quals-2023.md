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

sample = [3, 80, 128, 182]

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
		
#TODO

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
    [c2+p^2, -1, 0, 0],
    [c1+p^2, 0, 1, 0],
    [q, 0, 0, 0],
    [p*(c1-c2), 0, 0, 1]])
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
#TODO

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
