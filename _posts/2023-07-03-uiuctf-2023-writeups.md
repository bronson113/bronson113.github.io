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
#### Overview
```text
I found this safe, but something about it seems a bit off - can you crack it?

Author: Anakin
Solves: 62
```

```python
from Crypto.Cipher import AES
from secret import key, FLAG

p = 4170887899225220949299992515778389605737976266979828742347
ct = bytes.fromhex("ae7d2e82a804a5a2dcbc5d5622c94b3e14f8c5a752a51326e42cda6d8efa4696")

def crack_safe(key):
    return pow(7, int.from_bytes(key, 'big'), p) == 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759

assert crack_safe(key) and AES.new(key,AES.MODE_ECB).decrypt(ct) == FLAG
```
This is a really short challenge and not a lot of code to read through. Essentially we need to solve the discrete log problem to find the key such that 
$$7^{key} \equiv \mathtt{0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759} \mod{p}$$

We can first verify that p is a prime number. Typically, DLP under finite field is consider a hard problem. However, the difficulty of the DLP problem is bounded by the largest prime factor of the order of the finite field. Let's check the factors of the order, which is p-1 in this case. It turns out that p-1 is smooth, which means that the largest prime factor of p-1 is relatively small.

$$
\begin{align}
&4170887899225220949299992515778389605737976266979828742347 \\ 
&= 2 \times 19 \times 151 \times 577 \times 67061 \times 18279232319 \times  11154337669 \times 9213409941746658353293481
\end{align}
$$

Even the largest factor, 9213409941746658353293481, is only 83 bits long. This calls for a Pohlig-Hellman attack. 

#### Pohlig-Hellman Attack
What is a Pohlig-Hellman Attack though? According to [Wikipedia](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm), it is a way to break down a large DLP problem into multiple smaller sub-problems, then combine the result using chinese reminder theorm (CRT). The rough idea is as follows. Given a group $\mathbb{G}$ with order $p$, where $p$ is not a prime, and we want to find $x$ such that $g^x = k$ 
1. We know that after $p$ operation, the cycle loop back to itself. i.e. $k^p = 1$
2. Let's take a factor $e$ and let $t = p/e$, if we pre-compute $g_0 = g^t$ and set x then we know $g_0^e = 1$
3. This tells us that $g_0$ actually forms a smaller group with group order $e$. If we transfor g and k into element of this smaller group, it will be easier to find the solution. This solution is of course incomplete, but we will gain some information related to x.
4. In particular, the tranformation takes $g_0 = g^t$ and $k_0 = k^t$, and solve for the equation $g_0^{x_0} = k_0$, we can observe the following equation.

	$$\begin{align}
	g^x &= k \\  
	(g^x)^t &= k^t \\  
	g_0^{x_0} = (g^t)^{x_0} &= k^t \\ 
	xt &\equiv tx_0 \mod{p}\\ 
	x &\equiv x_0  \mod{\frac{p}{t}} \qquad \because t \vert p \ ^{*1}  \\   
	x &\equiv x_0  \mod{e} \\ 
	\end{align}$$
	
	\*1: Note that I'm not sure if this holds, but it make sense =D

5. After we gather all the reminder from the various factors, we can use CRT to reconstruct $x$ from all the $x_0$

When I'm initially learning a bout pohlig-hellman attack, [this blog](https://l0z1k.com/pohlig_hellman_attack) that applies this attack on elliptic curve cryptography helped me a lot. I get to understand how the attack works more intuiatively. If you want more detailed description on the attack, this will be a great resource along with the wiki page. 
#### Cado-nfs
Even though we can split the problem down into small chunks, we still need to deal with each smaller pieces. All the factors except the last one is relatively easy to tackle, as the built in sage discrete log function solves them quite easily. The last one is still problematic though. From some previous experience (i.e. GoogleCTF2023 - cursved), I know that cado-nfs is a good tool for solving dlp of size less than around 250 bits. I need to search around a little bit and found [the official cado-nfs repo](https://github.com/cado-nfs/cado-nfs). Just follow the steps to install it. 

Reading the user manual, we learn that the --dlp option allows us to find the discrete log of a number, but to a "random" base $b$, so $b^{x} \equiv a \mod b$. That's totally fine, as we can do a change of base algorithm to switch to any log base. 
$log_a(b) = log_c(b) / log_c(a)$

To use cado-nfs, we will first need to know that number we need to take the discrete log with. A short python script gives as the value.
```
p = 4170887899225220949299992515778389605737976266979828742347
k = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759

p_fs = [2, 19, 151, 577, 67061, 18279232319, 111543376699, 9213409941746658353293481]
e = p_fs[-1]
t = (p-1) // ell

print(pow(7, t, p))
print(pow(k, t, p))
# crack_the_safe$ python pre.py
#  2874921958440504604797627466936335381864476070281841795223
#  243520888574004127020636437512040223299982667282493152276
```

Then we run the following commands:
```
crack_the_safe$ cado-nfs.py -dlp -ell 9213409941746658353293481 target=2874921958440504604797627466936335381864476070281841795223 4170887899225220949299992515778389605737976266979828742347
[...]
Info:Complete Factorization / Discrete logarithm: Total cpu/elapsed time for entire Discrete logarithm: 247.08/102.098
Info:root: If you want to compute one or several new target(s), run ./cado-nfs.py /tmp/cado.sw277cqc/p60.parameters_snapshot.0 target=<target>[,<target>,...]
Info:root: logbase = 689700230313623370222183478814904246546188182712829892313
Info:root: target = 2874921958440504604797627466936335381864476070281841795223
Info:root: log(target) = 8483029440103488262728827 mod ell
8483029440103488262728827

crack_the_safe$ cado-nfs.py /tmp/cado.sw277cqc/p60.parameters_snapshot.0 target=243520888574004127020636437512040223299982667282493152276
[...]
Info:Complete Factorization / Discrete logarithm: Total cpu/elapsed time for entire Discrete logarithm: 325.79/124.619 # <- this time seems to be accumulative from the previoius run
Info:root: If you want to compute one or several new target(s), run ./cado-nfs.py /tmp/cado.sw277cqc/p60.parameters_snapshot.1 target=<target>[,<target>,...]
Info:root: logbase = 689700230313623370222183478814904246546188182712829892313
Info:root: target = 243520888574004127020636437512040223299982667282493152276
Info:root: log(target) = 1607529382666405025125600 mod ell
1607529382666405025125600
```
From the output we know the base is 689700230313623370222183478814904246546188182712829892313, and the log is 8483029440103488262728827 and 1607529382666405025125600 respectively. Now we just plug in the value, do CRT with the rest of the result, and we recover the flag.

`uiuctf{Dl0g_w/__UnS4F3__pR1Me5_}`

\*\* Note that from the output above, we can see that the total time elapses for the two command is around 124.6 seconds, or around 2 minute. I'm running this on a basic 11th gen i7 laptop, which is relatively low computing power I'd say. So it's not exactly fast, but reasonable for most computer. I think most computer can compute DLP using cado-nfs way faster than mine.


{% capture safe_cracker_py %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from subprocess import check_output

p = 4170887899225220949299992515778389605737976266979828742347
ct = bytes.fromhex("ae7d2e82a804a5a2dcbc5d5622c94b3e14f8c5a752a51326e42cda6d8efa4696")
k = 0x49545b7d5204bd639e299bc265ca987fb4b949c461b33759

F = GF(p)
p_fs = [2, 19, 151, 577, 67061, 18279232319, 111543376699, 9213409941746658353293481]
ell = p_fs[-1]
remain = (p-1) // ell

# to send to cado_nfs
print(F(7)^(remain))
print(F(k)^(remain))

# from cado_nfs
# cado-nfs.py -dlp -ell 9213409941746658353293481 target=2874921958440504604797627466936335381864476070281841795223 4170887899225220949299992515778389605737976266979828742347
# cado-nfs.py /tmp/cado.vxkkpmj5/p60.parameters_snapshot.0 target=2874921958440504604797627466936335381864476070281841795223
log7, logk = 8483029440103488262728827, 1607529382666405025125600
logbase = 689700230313623370222183478814904246546188182712829892313

res = []
for prime in p_fs[:-1]:
    r = (p-1)//prime
    P7 = F(7)^r
    Pk = F(k)^r
    res.append(discrete_log(Pk, P7))

assert(F(logbase)^log7 == F(7)^remain)
assert(F(logbase)^logk == F(k)^remain)
full_log_ell = int(logk * pow(log7, -1, ell) % ell)
assert((F(7)^remain)^full_log_ell, F(k)^remain)

key = CRT(res+[full_log_ell], p_fs)

print(key)
assert(int(pow(7, key, p)) == k)
print(AES.new(long_to_bytes(int(key)),AES.MODE_ECB).decrypt(ct))

#uiuctf{Dl0g_w/__UnS4F3__pR1Me5_}

```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="safe_cracker_py" button-text="Show solve.sage" toggle-text=safe_cracker_py %}
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

We are given a binary. After running it, it seems like the program is a simple calculator. 
```
fast_calc$ ./calc
Welcome to the fastest, most optimized calculator ever!
Example usage:
  Add:       1 + 2
  Subtract:  10 - 24
  Multiply:  34 * 8
  Divide:    20 / 3
  Modulo:    60 % 9
  Exponent:  2 ^ 12

If you enter the correct secret operation, I might decrypt the flag for you! ^-^

Enter your operation: 1 + 1
Result: 2.000000
Enter your operation: 2 * 2
Result: 4.000000
Enter your operation:
```

Obviously we will not be able to guess the correctly operation, so let's start decompiling the program. After looking at the code in ghidra, we get the rough pseudo code of the program as follow.
```
def main():
	flag = some_initial_flag_state
	sscanf("%lf %c %lf", lop, op, rop)
	res = calculate(op, lop, rop)
	if res == 8573.8567:
		for i in range(368):
			if guantlet(calculate(equations[i])):
				flip_bit(i, flag)
		print(flag)
```

Now we know the secret value, we can create an equation that result in that, like 8573.8567 + 0, and that should give us the flag, right? Running the program with that input gives us the following output.
```
fast_calc$ ./calc
Welcome to the fastest, most optimized calculator ever!
Example usage:
  Add:       1 + 2
  Subtract:  10 - 24
  Multiply:  34 * 8
  Divide:    20 / 3
  Modulo:    60 % 9
  Exponent:  2 ^ 12

If you enter the correct secret operation, I might decrypt the flag for you! ^-^

Enter your operation: 8573.8567 + 0
Result: 8573.856700

Correct! Attempting to decrypt the flag...
I calculated 368 operations, tested each result in the gauntlet, and flipped 119 bits in the encrypted flag!
Here is your decrypted flag:

uiuctf{This is a fake flag. You are too fast!}

Enter your operation:
```
Clearly there's something wrong, but where? If we look into the guantlet function, this is the pseudo code:
```
char gauntlet(int param_1)

{
  char cVar1;
  
  cVar1 = isNegative(param_1);
  if (((cVar1 == '\0') && (cVar1 = isNotNumber(param_1), cVar1 == '\0')) &&
     (cVar1 = isInfinity(param_1), cVar1 == '\0')) {
    return 0;
  }
  return 1;
}
```
But if we look into the isNotNumber function and the isInfinity function, they are both empty:
```
char isNotNumber(void)
{
  return 0;
}
char isInfinity(void)
{
  return 0;
}
```
Seems like when the program is compiled, these checks are optimized out. What we can do now is to re-implement those checks outselves, or extract the equations and do the comprisons with the correct checks. I choose to hook gdb to printout the result of each equations and extract the bits from there. The initial state of the flag can be gathered statically from ghidra.

Using gdb, we can set break points at the start of the guantlet function, and gather the result of each calculation. I print out the rax register, which is indirectly used to pass the argument into the guantlet function (The series of mov rax, xmm0). Since I use gef-gdb, I disabled the context output so the display function shows up.  With those set up, I just let the program run, enter the equation `8573.8567 + 0`, and press continue a bunch of time to gather the output from gdb. I then do some string processing to determine if the result fits the gauntlet function criteria, and reconstruct the key bit strings from there. 

The detail of the processing steps can be found in my solve script. I trime down the output from gdb and only leave the lines that displays the desire outputs. Note that -0.0 should be considered negative, which is likely coming from rounding a really small negative number. In my code, I simply match if there is a negative sign in the string or if `nan` is in the string, I didn't check for `inf` as it doesn't exist in the result. 

During the after competition Q&A section, we learn that this discrepancy is caused by the `-ffast-math` optimization flag. According to the [manual](https://gcc.gnu.org/wiki/FloatingPointMath), this flag enables multiple optimization, which assumes that there are no negative zero, no infinite number, and no "Not a number". This cause the function in this challenge to be optimized out and return the wrong results, like always return 0 for the `isInfinite` and `isNotNumber` functions. 

Anyway, after recovering the results of the calculations, we can recover the correct flag: `uiuctf{n0t_So_f45t_w1th_0bscur3_b1ts_of_MaThs}`

{% capture fast_math_solve %}
```python
from Crypto.Util.number import long_to_bytes
from pwn import xor, u64
from collections import namedtuple
import struct
flag_init = [0x10eeb90001e1c34b, 0xcb382178a4f04bee, 0xe84683ce6b212aea, 0xa0f5cf092c8ca741, 0x20a92860082772a1, 0x0000e9a435abb366]

## In gdb, run the following
## I have gef enable, so to disable the context command on break point
# gef config context.enable 0
## display the argument send into gauntlet function
# display/f $rax
## break at the function entry 
# break *gauntlet
## run and record the output at each break point
# continue

gauntlet_result_str = """1: /f $rax = 314.23572239497753
1: /f $rax = 343.1722504437929
1: /f $rax = -101.85126480640992
1: /f $rax = -0.14835009306536753
1: /f $rax = -70.145728960527265
1: /f $rax = -2.6849183740546723
1: /f $rax = -2.3380621927091738
1: /f $rax = 86.218782945280964
1: /f $rax = -3.3639097471103775e+173
1: /f $rax = 46094.822986351515
1: /f $rax = -67.229647073100352
1: /f $rax = 438.01221554209553
1: /f $rax = -62.22407895907827
1: /f $rax = 0.5686960704974473
1: /f $rax = -11.235858046371675
1: /f $rax = 45.736994758008109
1: /f $rax = -18.801101024741456
1: /f $rax = 411.84732421177659
1: /f $rax = 45.272562437363035
1: /f $rax = -0.37696866777117749
1: /f $rax = 88.471730127468447
1: /f $rax = -115.84593208858394
1: /f $rax = 4.7067980704139161e+81
1: /f $rax = 0.54632989995632775
1: /f $rax = 365.5900085787963
1: /f $rax = -12224407890038.037
1: /f $rax = -900.03969886574691
1: /f $rax = 192.03613945346399
1: /f $rax = 22794.907192724011
1: /f $rax = 5.5838341534360488e+102
1: /f $rax = -3.2637463171100762
1: /f $rax = 159.0671967048533
1: /f $rax = 30.011102835658335
1: /f $rax = -0.77702398729932365
1: /f $rax = -1.4816482051550224
1: /f $rax = -1.0767063255033242e+68
1: /f $rax = 129.41389307826773
1: /f $rax = -104.65344600547064
1: /f $rax = 257.8983468906606
1: /f $rax = 576.9359463423001
1: /f $rax = -0.47174390929966187
1: /f $rax = -4.1909544608317306
1: /f $rax = 0.23304225970708495
1: /f $rax = -84.792660796004725
1: /f $rax = -70341.035023618824
1: /f $rax = -8.3558344696096316e+64
1: /f $rax = -112.71915174806799
1: /f $rax = -0.77501348533601244
1: /f $rax = -0.79477368623462019
1: /f $rax = 138.55118925698957
1: /f $rax = 62867.158634785257
1: /f $rax = -3.000328242329492e+180
1: /f $rax = 2.1776919356209225e+151
1: /f $rax = -2.1194889785952991
1: /f $rax = 826.09998445102667
1: /f $rax = -360.78132147755349
1: /f $rax = 0.74474414688805379
1: /f $rax = -21.526343208515129
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -26.071269727239439
1: /f $rax = -0
1: /f $rax = 1.1862373081337182e+117
1: /f $rax = -195.86680296791417
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 51014.532345230917
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = -15.569984026884583
1: /f $rax = -54.755056250318489
1: /f $rax = 14200.373689706015
1: /f $rax = 218.53775827884192
1: /f $rax = 7.7720611029683001e+113
1: /f $rax = -54359.046985524998
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -6.370935462591425e+103
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -493.83639903330982
1: /f $rax = 91.739040381445648
1: /f $rax = -0
1: /f $rax = 5.5930414556039505
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -648.15538239805801
1: /f $rax = -1.7360428852698293
1: /f $rax = -88380681806354.375
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 149.63032247415293
1: /f $rax = -1.4381306131731484e+175
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 17796.731831557954
1: /f $rax = 472.60782602556361
1: /f $rax = 8.4333081523481042
1: /f $rax = -69.343045576994086
1: /f $rax = 166.97777525280043
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -0.78663690221494187
1: /f $rax = 124.48452366441916
1: /f $rax = -24.166235583316563
1: /f $rax = -0
1: /f $rax = -91893.006289350305
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = -77.947739723395614
1: /f $rax = 351.31148102293406
1: /f $rax = 677.84610642219423
1: /f $rax = -0
1: /f $rax = 61017.564352902024
1: /f $rax = -730.71847028262323
1: /f $rax = -2.9862791904668937e+57
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 0.46137120873229431
1: /f $rax = -1.5805958630033241
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -2047.9485377909623
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -279.92789568076961
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -3.5566717877102974e+160
1: /f $rax = -0
1: /f $rax = -35011.007801930165
1: /f $rax = -70.73409314339824
1: /f $rax = 0.13748648705254249
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -127.63031163891606
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -8.3377831242250409
1: /f $rax = -0
1: /f $rax = 73914.284889780072
1: /f $rax = -1.1205570846974704e+30
1: /f $rax = 868.91249403708673
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -3781.1025679452832
1: /f $rax = -398.23202773538833
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 6.150332565634857e+123
1: /f $rax = 106.92708315198797
1: /f $rax = -126958.01118794817
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = 2.3235637995996195
1: /f $rax = 1172.4570923687561
1: /f $rax = 282667694185.37067
1: /f $rax = 419.22101622342973
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 1.5015581523042944e+106
1: /f $rax = 14.116915444637357
1: /f $rax = -670.80920696640771
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -40.175576810129257
1: /f $rax = -0
1: /f $rax = -535.08846436597457
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -24.996900828879973
1: /f $rax = -0.4482337253576606
1: /f $rax = -22075.351523103447
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -66629.115626130355
1: /f $rax = -0
1: /f $rax = 4.7736504866351757
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -750.41785743580328
1: /f $rax = -397.49355092611438
1: /f $rax = 421.45554904220558
1: /f $rax = 272.44106051590188
1: /f $rax = -39853.033198178338
1: /f $rax = 163773.34383559634
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 909.06916666172924
1: /f $rax = -17044.293607727042
1: /f $rax = 0.65923135526929078
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 281.64059966529658
1: /f $rax = -2.8299636815986545e+135
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 362.73719659653017
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -1.3883485850670447
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 93.153374984795107
1: /f $rax = 13.013689110180962
1: /f $rax = 1.9706463137115084
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -332.70825023576583
1: /f $rax = -0.14833759536673966
1: /f $rax = 9.9017259669548139
1: /f $rax = 31842.681577482257
1: /f $rax = 3.1202574779650742
1: /f $rax = -0
1: /f $rax = 16382.118960546628
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -6.7132868546727442e+184
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -174.78551375100216
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = -1987.883710049279
1: /f $rax = -0
1: /f $rax = 318.67029200471404
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 65.16561987924581
1: /f $rax = 20.353222265520685
1: /f $rax = -0.73389327660335457
1: /f $rax = -266.24812381690595
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 112.28331135754138
1: /f $rax = -775.0884636297726
1: /f $rax = -0
1: /f $rax = -123.49647710482895
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 68.32948123433016
1: /f $rax = 42216.592524590371
1: /f $rax = -130.97917757842748
1: /f $rax = 29432.765402793259
1: /f $rax = -878.51164428076936
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 306.40280919331701
1: /f $rax = -0
1: /f $rax = -0.20570015125935212
1: /f $rax = -0
1: /f $rax = 47.573162560923492
1: /f $rax = 23.030280017535915
1: /f $rax = 378.44803504327092
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = 1.1328069324948051e+46
1: /f $rax = -210.34934864154206
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = -1.1007026146671162
1: /f $rax = -26.400390640113017
1: /f $rax = 397.48613844398091
1: /f $rax = 38525.844533000112
1: /f $rax = 30.648157313300999
1: /f $rax = 6.1955288111496536
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 0.70927007491958105
1: /f $rax = -0
1: /f $rax = 1.8864493518170104e+26
1: /f $rax = 0.16905148155093813
1: /f $rax = 1.3585953817759831e+92
1: /f $rax = 181.19460341004981
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 225.29942051219257
1: /f $rax = -185.39637228963687
1: /f $rax = 358.19308718059125
1: /f $rax = -0
1: /f $rax = 95.617280730657967
1: /f $rax = 64822.754928640163
1: /f $rax = -8.3805738251753192e+131
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 280.87137523260935
1: /f $rax = -0
1: /f $rax = -1.2639319359462708e+108
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -1.3969847218364998e+131
1: /f $rax = 0.14077936300692293
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 5.319300019172033
1: /f $rax = 527.08403233634419
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -32.299552813442517
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -2.429700289221689e+81
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 1.2655924566762723e+32
1: /f $rax = -0.92793953369268045
1: /f $rax = 219499.6079292119
1: /f $rax = 2.0876504455883737e+58
1: /f $rax = 1.6366868264419469e+113
1: /f $rax = -1.0405670972109875
1: /f $rax = -1.36021695876653e+144
1: /f $rax = -79.584542222673861
1: /f $rax = -146954.02785373406
1: /f $rax = -4.6878849674481635e+105
1: /f $rax = 5.2042273135353394
1: /f $rax = 68474.465419736342
1: /f $rax = -0
1: /f $rax = -263.87225021489024
1: /f $rax = -137.14753940351306
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 65.584892774741547
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 1.8375862375292325e+61
1: /f $rax = 64.923792584856926
1: /f $rax = -0
1: /f $rax = 409.39159782790705
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = 163.56416201962367
1: /f $rax = -0
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -7.6372145447543532e+61
1: /f $rax = -0.61724198201350899
1: /f $rax = 25447.55907409166
1: /f $rax = -41.845610177283163
1: /f $rax = 2.4896131626248281
1: /f $rax = 1.0207860141139902
1: /f $rax = -33941.712961799269
1: /f $rax = 7.8614623295186448
1: /f $rax = -3.8777423969773022
1: /f $rax = -0.68108037017455914
1: /f $rax = -0
1: /f $rax = -685.17496006588283
1: /f $rax = -8.0149697814365481
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 285.92254208579675
1: /f $rax = -287.40609702408972
1: /f $rax = 468.70035658374701
1: /f $rax = -nan(0x8000000000000)
1: /f $rax = -0
1: /f $rax = -0
1: /f $rax = 58.03201117994729
1: /f $rax = -4.0117609975907898e+151
1: /f $rax = -7.0854219349746412e+33
1: /f $rax = -0
1: /f $rax = 1.3966977676222205
1: /f $rax = -0
1: /f $rax = 93.01034943574615
1: /f $rax = -89.204424936891314
1: /f $rax = -0
1: /f $rax = -126.55669891797004
1: /f $rax = -613.57861842951388
1: /f $rax = 161.36487031616679
1: /f $rax = 178.73853880744343
1: /f $rax = -85.575377705299331
1: /f $rax = 8.5465193972006208e+26
1: /f $rax = -9.0363744286576492e+87
1: /f $rax = 8.2600129371691562
1: /f $rax = 0.0021326131099172149"""




flag_init_bytes = list(map(long_to_bytes, flag_init))
flag_init_bytes = b"".join(i[::-1] for i in flag_init_bytes) #fix endianness

gauntlet_result = [i.split(" = ")[-1] for i in gauntlet_result_str.split("\n")]
gauntlet_result_bits = ["1" if (i[0] == "-" or ("nan" in i)) else "0" for i in gauntlet_result]
gauntlet_result_bits = "".join(gauntlet_result_bits)

key = long_to_bytes(int(gauntlet_result_bits, 2))
print(xor(flag_init_bytes, key))
#uiuctf{n0t_So_f45t_w1th_0bscur3_b1ts_of_MaThs}
```
{% endcapture %}
{% include widgets/toggle-field.html toggle-name="fast_math_solve" button-text="Show solve.py" toggle-text=fast_math_solve %}

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
