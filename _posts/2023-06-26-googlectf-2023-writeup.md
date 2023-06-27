---
title: GoogleCTF 2023 Writeup
---

# GoogleCTF 2023 Writeup
## Overview
Last weekend, I played GoogleCTF with b01lers. We ranked 55th in the end. I solved 2 misc, 1 rev, 1 crypto, and 3 pwn. This writeup will mostly focus on my own thought process while solving the challenges, and I'd recommand reading the [official writeups](https://github.com/google/google-ctf/tree/master/2023) as well.

Challenge solved after the competition are marked as \[\*\] 

<!--more-->

---

# Misc
## npc
```text
A friend handed me this map and told me that it will lead me to the flag. 
It is confusing me and I don't know how to read it, can you help me out?

solves: 102
```
{% capture npc_encrypt_py %}
```python
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This file encrypts a given file using a generated, easy to remember password.

Additionally, it generates a hint in case you forgot the password.
"""

import dataclasses
import re
import secrets
import sys

from pyrage import passphrase


def get_word_list():
  with open('USACONST.TXT', encoding='ISO8859') as f:
    text = f.read()
  return list(set(re.sub('[^a-z]', ' ', text.lower()).split()))


def generate_password(num_words):
  word_list = get_word_list()
  return ''.join(secrets.choice(word_list) for _ in range(num_words))


@dataclasses.dataclass
class Node:
  letter: str
  id: int


@dataclasses.dataclass
class Edge:
  a: Node
  b: Node


@dataclasses.dataclass
class Graph:
  nodes: list[Node]
  edges: list[Edge]


class IdGen:
  def __init__(self):
    self.ids = set()

  def generate_id(self):
    while True:
      new_id = secrets.randbelow(1024**3)
      if new_id not in self.ids:
        self.ids.add(new_id)
        return new_id


def generate_hint(password):
  random = secrets.SystemRandom()
  id_gen = IdGen()
  graph = Graph([],[])
  for letter in password:
    graph.nodes.append(Node(letter, id_gen.generate_id()))
  for a, b in zip(graph.nodes, graph.nodes[1:]):
    graph.edges.append(Edge(a, b))
  for _ in range(int(len(password)**1.3)):
    a, b = random.sample(graph.nodes, 2)
    graph.edges.append(Edge(a, b))
  random.shuffle(graph.nodes)
  random.shuffle(graph.edges)
  for edge in graph.edges:
    if random.random() % 2:
      edge.a, edge.b = edge.b, edge.a
  return graph

def write_hint(graph, out_file):
  out_file.write('graph {\n')
  for node in graph.nodes:
    out_file.write(f'    {node.id} [label={node.letter}];\n')
  for edge in graph.edges:
    out_file.write(f'    {edge.a.id} -- {edge.b.id};\n')
  out_file.write('}\n')


def encrypt(num_words, secret):
  password = generate_password(num_words)
  hint = generate_hint(password)
  with open('hint.dot', 'w') as hint_file:
    write_hint(hint, hint_file)
  filename = 'secret.age'
  with open(filename, 'wb') as f:
    f.write(passphrase.encrypt(secret, password))
  print(f'Your secret is now inside password-protected file {filename}.')
  print(f'Use the password {password} to access it.')
  print(
      'In case you forgot the password, maybe hint.dot will help your memory.')


if __name__ == '__main__':
  encrypt(num_words=int(sys.argv[1]), secret=sys.argv[2].encode('utf-8'))

```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="npc_encrypt_py"
    button-text="Show encrypt.py" toggle-text=npc_encrypt_py %}
		
In this challenge, the flag file is encrypted using a passphrase that generated from a wordlist. A `hint.dot` file is also provided. THe most import part is to identiy how the hint is generate. 
In the `encrypt.py` file we can see that each letter is assigned a node, and each consecutive letters are link with a directly edge. Afterward, random edges are added, the node orders are shuffled, and the edge order are randomly flipped. Since there are a lot of randomness in the hint, all we can extract from the hint are what letters are in the passphrase, and what letters can be connected.
I parse the hint file and get the list of letters presented. I then treat all edges as bi-directional, and filter the words based on the following criteria.

1. The letters in the word can be found in the passphrase
2. There are edges between any two consecutive letter pairs

This filters the word list down to 86 words, I then randomly generates passphrase from that wordlist that have the same word sets as the passphrase. I then permutes that word sets and test all permutations until the correct passphrase is found. See solve.py for more detail. 

I think that the word set phase can potentially be change to a more efficient approach, as that problem is similar to a subset sum, not sure if there are any potential in a more efficient algorithm.

{% capture npc_solve_py %}
```python
import re
import random
import secrets
from tqdm import tqdm
import string
from sage.all import *
from pyrage import passphrase
from itertools import permutations

def get_word_list():
    with open('USACONST.TXT', encoding='ISO8859') as f:
        text = f.read()
    return list(set(re.sub('[^a-z]', ' ', text.lower()).split()))

word_list = get_word_list()

def get_valid_nodes():
    with open("hint.dot") as f:
        header = f.readline()
        tmp = f.readline()
        nodes = {}
        inv_nodes = {}
        edges = []
        while "label" in tmp:
            node_id, letter = tmp.split('[label=')
            letter = letter[0]
            node_id = int(node_id)
            nodes[node_id] = letter
            if letter in inv_nodes:
                inv_nodes[letter].append(node_id)
            else:
                inv_nodes[letter] = [node_id]

            tmp = f.readline()

        while "--" in tmp:
            fid, tid = tmp.split('--')
            fid = int(fid)
            tid = int(tid[:-2]) # ;\n
            edges.append((fid, tid))
            edges.append((tid, fid)) # since it's randomly flipped, treat as non directional

            tmp = f.readline()

        return nodes, inv_nodes, edges

nodes, inv_nodes, edges = get_valid_nodes()

def path_exist(inv_map, edge, f, t):
    for fr in inv_map[f]:
        for dst in inv_map[t]:
            if (fr, dst) in edge:
                return True
#    print(f, t)
    return False

#print(n, e)



appeared_letter = list(nodes.values())
valid_words = []
for w in word_list:
    if not all(i in appeared_letter for i in w):
        continue

    for l in w:
        if w.count(l) > appeared_letter.count(l):
            break
    else:
        for s, e in zip(w, w[1:]):
            if not path_exist(inv_nodes, edges, s, e):
                break
        else:
            valid_words.append(w)


print(valid_words)
print(len(appeared_letter))
print(len(valid_words))

verify = "".join(sorted(appeared_letter)).strip()
print(verify)
print(type(verify))
password_len = len(verify)

def generate_password(num_words):
  word_list = valid_words
  return ''.join(secrets.choice(word_list) for _ in range(num_words))

def word2vec(word):
    return [word.count(l) for l in string.ascii_lowercase]


#verify = "aacddeeeeegiiinnnoorrrsssstt"

secret = open("secret.age", "rb").read()

for words in Subsets(valid_words):
    password = "".join(words)
    if len(password) != password_len:
        continue
    s_password = "".join(sorted(password))
#    print(s_password)
#    print(type(s_password), type(verify))
    if s_password in verify:
        print(password)
        print(words)

        for ws in permutations(words):
            password = "".join(ws)
            print(password)

            for s, e in zip(password, password[1:]):
                if not path_exist(inv_nodes, edges, s, e):
                    break
            else:
                try:
                    print(passphrase.decrypt(secret, password))
                    print("FOUND!!!!")
                    exit(1)
                except Exception as e:
                    pass
#standardwatersigngivenchosen
#b'CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}'

```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="npc_solve_py"
    button-text="Show solve.py" toggle-text=npc_solve_py %}
`CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}`
## symatrix
```text
The CIA has been tracking a group of hackers who communicate using PNG files embedded with a custom steganography algorithm. 
An insider spy was able to obtain the encoder, but it is not the original code. 
You have been tasked with reversing the encoder file and creating a decoder as soon as possible in order to read the most recent PNG file they have sent.

solves: 110
```
[encoder.c (From googleCTF github)](https://github.com/google/google-ctf/tree/master/2023)

The challenge comes with a large encoder.c file, this seems intimidating initially. However, reading through the code a little bit, we quickly found out that there are part of the original python file written in the comment. Using a simple parser I extracted the python source from encoder.c file. (My parser actually missed a else: line, and I manuelly added that afterward)

{% include widgets/toggle-field.html toggle-name="symatrix_parse_py" button-text="Show parse_c.py" toggle-text=symatrix_parse_py %}
{% include widgets/toggle-field.html toggle-name="symatrix_encoder_py" button-text="Show encoder.py" toggle-text=symatrix_encoder_py %}

Base on the encoder.py file, it's clear that the original image is mirrored, and the flag bit and embedded to the right half of the image. The pixel that are modifyed are always increamented by either (0, 1, 0) or (0, 1, 1), with the formar encoding 0 and the latter encoding 1. To decode the flag, we simply go through all the bytes, and extract those that are different left side v.s. right side. We can ignore the random offset since only the pixels that have data encoded are changed.
{% include widgets/toggle-field.html toggle-name="symatrix_solve_py" button-text="Show solve.py" toggle-text=symatrix_solve_py %}
`CTF{W4ke_Up_Ne0+Th1s_I5_Th3_Fl4g!}`

{% capture symatrix_parse_py %}
```python
f = open("encoder.c")

source = ["" for i in range(70)]
for line in f:
    if "encoder.py" in line:
#        print(line)
        try:
            line_number = int(line.split(':')[-1].split(" ")[0])
        except Exception:
            continue
#        print(line_number)
        for af in range(5):
            temp = f.readline()
            if "<<<<<" in temp:
                source[line_number] = temp[3:-1].split("#")[0]

with open("encoder.py", "w") as f:
    f.write("\n".join(source))
```
{% endcapture %}


		

{% capture symatrix_encoder_py %}
```python
from PIL import Image
from random import randint
import binascii

def hexstr_to_binstr(hexstr):
    n = int(hexstr, 16)
    bstr = ''
    while n > 0:
        bstr = str(n % 2) + bstr
        n = n >> 1
    if len(bstr) % 8 != 0:
        bstr = '0' + bstr
    return bstr


def pixel_bit(b):
    return tuple((0, 1, b))


def embed(t1, t2):
    return tuple((t1[0] + t2[0], t1[1] + t2[1], t1[2] + t2[2]))


def full_pixel(pixel):
    return pixel[1] == 255 or pixel[2] == 255

print("Embedding file...")

bin_data = open("./flag.txt", 'rb').read()
data_to_hide = binascii.hexlify(bin_data).decode('utf-8')

base_image = Image.open("./original.png")

x_len, y_len = base_image.size
nx_len = x_len * 2

new_image = Image.new("RGB", (nx_len, y_len))

base_matrix = base_image.load()
new_matrix = new_image.load()

binary_string = hexstr_to_binstr(data_to_hide)
remaining_bits = len(binary_string)

nx_len = nx_len - 1
next_position = 0

for i in range(0, y_len):
    for j in range(0, x_len):

        pixel = new_matrix[j, i] = base_matrix[j, i]

        if remaining_bits > 0 and next_position <= 0 and not full_pixel(pixel):
            new_matrix[nx_len - j, i] = embed(pixel_bit(int(binary_string[0])),pixel)
            next_position = randint(1, 17)
            binary_string = binary_string[1:]
            remaining_bits -= 1
        else:
            new_matrix[nx_len - j, i] = pixel
            next_position -= 1


new_image.save("./symatrix.png")
new_image.close()
base_image.close()

print("Work done!")
exit(1)
```
{% endcapture %}



{% capture symatrix_solve_py %}
```python
from PIL import Image
import binascii
from Crypto.Util.number import long_to_bytes

encoded_image = Image.open("./symatrix.png")
x_len, y_len = encoded_image.size

encoded_matrix = encoded_image.load()

center = x_len//2

flag_bits = ""
for i in range(0, y_len):
    for j in range(0, x_len//2):
        if encoded_matrix[j, i] == encoded_matrix[x_len-1-j, i]:
            continue
        else:
            flag_bits += str(encoded_matrix[x_len-1-j, i][2] - encoded_matrix[j, i][2])
#            print(flag_bits)

flag = long_to_bytes(int(flag_bits, 2))
print(flag)
```
{% endcapture %}

---
# Reverse
## Turtle
```text
Are we not all but turtles drifting in the sea, executing instructions as we stumble upon them?

solves: 27
```
##todo

---
# Crypto
## Least Common Genominator?
```text
Someone used this program to send me an encrypted message but I can't read it! It uses something called an LCG, do you know what it is? I dumped the first six consecutive values generated from it but what do I do with it?!

solves: 352
```
{% capture lcg_generator_py %}
```python
from secret import config
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, isPrime

class LCG:
    lcg_m = config.m
    lcg_c = config.c
    lcg_n = config.n

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

if __name__ == '__main__':

    assert 4096 % config.it == 0
    assert config.it == 8
    assert 4096 % config.bits == 0
    assert config.bits == 512

    # Find prime value of specified bits a specified amount of times
    seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
    lcg = LCG(seed)
    primes_arr = []

    dump = True
    items = 0
    dump_file = open("dump.txt", "w")

    primes_n = 1
    while True:
        for i in range(config.it):
            while True:
                prime_candidate = lcg.next()
                if dump:
                    dump_file.write(str(prime_candidate) + '\n')
                    items += 1
                    if items == 6:
                        dump = False
                        dump_file.close()
                if not isPrime(prime_candidate):
                    continue
                elif prime_candidate.bit_length() != config.bits:
                    continue
                else:
                    primes_n *= prime_candidate
                    primes_arr.append(prime_candidate)
                    break

        # Check bit length
        if primes_n.bit_length() > 4096:
            print("bit length", primes_n.bit_length())
            primes_arr.clear()
            primes_n = 1
            continue
        else:
            break

    # Create public key 'n'
    n = 1
    for j in primes_arr:
        n *= j
    print("[+] Public Key: ", n)
    print("[+] size: ", n.bit_length(), "bits")

    # Calculate totient 'Phi(n)'
    phi = 1
    for k in primes_arr:
        phi *= (k - 1)

    # Calculate private key 'd'
    d = pow(config.e, -1, phi)

    # Generate Flag
    assert config.flag.startswith(b"CTF{")
    assert config.flag.endswith(b"}")
    enc_flag = bytes_to_long(config.flag)
    assert enc_flag < n

    # Encrypt Flag
    _enc = pow(enc_flag, config.e, n)

    with open ("flag.txt", "wb") as flag_file:
        flag_file.write(_enc.to_bytes(n.bit_length(), "little"))

    # Export RSA Key
    rsa = RSA.construct((n, config.e))
    with open ("public.pem", "w") as pub_file:
        pub_file.write(rsa.exportKey().decode())
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="lcg_generator_py"
    button-text="Show generator.py" toggle-text=lcg_generator_py %}
		
This challenge is first generates p and q using a lcg, then use the p and q generated to encrypted the flag using rsa. Notice that the seed for lcg is provided, and the first 6 output of the lcg is provided. Therefore, if we recover the parameters for lcg, we can re-generate the same p and q from the program, and decrypt rsa accordingly. 

While recovering m and c is trivial, recovering n is harder. I found [this script](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/parameter_recovery.py) and modify it a bit since the modulus end up not being a prime. After recoving the parameters, the rest of the solve are straight forward.

{% capture lcg_solve_py %}
```python
from math import gcd
from sage.all import GF, Zmod
from sage.all import is_prime_power
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, isPrime, long_to_bytes

# https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/parameter_recovery.py
# with some modification
def attack(y, m=None, a=None, c=None):
    """
    Recovers the parameters from a linear congruential generator.
    If no modulus is provided, attempts to recover the modulus from the outputs (may require many outputs).
    If no multiplier is provided, attempts to recover the multiplier from the outputs (requires at least 3 outputs).
    If no increment is provided, attempts to recover the increment from the outputs (requires at least 2 outputs).
    :param y: the sequential output values obtained from the LCG
    :param m: the modulus of the LCG (can be None)
    :param a: the multiplier of the LCG (can be None)
    :param c: the increment of the LCG (can be None)
    :return: a tuple containing the modulus, multiplier, and the increment
    """
    if m is None:
        assert len(y) >= 4, "At least 4 outputs are required to recover the modulus"
        for i in range(len(y) - 3):
            d0 = y[i + 1] - y[i]
            d1 = y[i + 2] - y[i + 1]
            d2 = y[i + 3] - y[i + 2]
            g = d2 * d0 - d1 * d1
            m = g if m is None else gcd(g, m)

        #assert is_prime_power(m), "Modulus must be a prime power, try providing more outputs"

    gf = Zmod(m)
    if a is None:
        assert len(y) >= 3, "At least 3 outputs are required to recover the multiplier"
        x0 = gf(y[0])
        x1 = gf(y[1])
        x2 = gf(y[2])
        a = int((x2 - x1) / (x1 - x0))

    if c is None:
        assert len(y) >= 2, "At least 2 outputs are required to recover the multiplier"
        x0 = gf(y[0])
        x1 = gf(y[1])
        c = int(x1 - a * x0)

    return m, a, c

lcg = list(map(int, open("dump.txt", "r").read().split()))
seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
lcg = [seed] + lcg

print(lcg)
m, a, c = attack(lcg)
print(m, a, c)

# verify output
for i in range(len(lcg) - 1):
    assert (a*lcg[i]+c)%m == lcg[i+1]

# taken from generate.py
class LCG:
    global m, a, c
    lcg_m = a
    lcg_c = c
    lcg_n = m

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

# Find prime value of specified bits a specified amount of times
seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
lcg = LCG(seed)
primes_arr = []

dump = False
items = 0
#dump_file = open("dump.txt", "w")

primes_n = 1
while True:
    for i in range(8):
        while True:
            prime_candidate = lcg.next()
            if dump:
                dump_file.write(str(prime_candidate) + '\n')
                items += 1
                if items == 6:
                    dump = False
                    dump_file.close()
            if not isPrime(prime_candidate):
                continue
            elif prime_candidate.bit_length() != 512:
                continue
            else:
                primes_n *= prime_candidate
                primes_arr.append(prime_candidate)
                break

    # Check bit length
    if primes_n.bit_length() > 4096:
        print("bit length", primes_n.bit_length())
        primes_arr.clear()
        primes_n = 1
        continue
    else:
        break

# Create public key 'n'
n = 1
for j in primes_arr:
    n *= j
print("[+] Public Key: ", n)
print("[+] size: ", n.bit_length(), "bits")

# now decrypt the flag with p and q
print(primes_arr)
phi = 1
for k in primes_arr:
    phi *= (k - 1)

key = RSA.importKey(open("public.pem", "rb").read())
print(key.e, key.n)
print(key.n == n)
e = key.e

d = pow(e, -1, phi)

c = int.from_bytes(open("flag.txt", "rb").read(), "little")
print(c)

print(long_to_bytes(pow(c, d, n)))
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="lcg_solve_py"
    button-text="Show solve.py" toggle-text=lcg_solve_py %}

---
# Pwn
## Write Flag Where [1~3]
```text
Part1:
This challenge is not a classical pwn
In order to solve it will take skills of your own
An excellent primitive you get for free
Choose an address and I will write what I see
But the author is cursed or perhaps it's just out of spite
For the flag that you seek is the thing you will write
ASLR isn't the challenge so I'll tell you what
I'll give you my mappings so that you'll have a shot.

Part2:
Was that too easy? Let's make it tough
It's the challenge from before, but I've removed all the fluff

Part3:
Your skills are considerable, I'm sure you'll agree
But this final level's toughness fills me with glee
No writes to my binary, this I require
For otherwise I will surely expire

nc wfw[123].2023.ctfcompetition.com 1337
solves 294 / 155 / 43
```
From reversing the challenge, we can quickly identify the behavior. The challenge first output the process map, allowing us to know pie, libc, and stack addresses. It then close stdin/stdout/stderr, and only accept inputs from fd 1337. Lastly, the challenge goes into a while loop, taking an address and a count, then write count number of bytes of flag to the specified address. Note that the flag is written by writting directly to the process memory file, so all addresses are writable, **including the code themselves**. This will be handy for part 3.
