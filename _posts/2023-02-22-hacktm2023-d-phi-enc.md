---
title: HackTM2023 - d-phi-enc
---

# HackTM 2023 - d-phi-enc

# Challenge Description
---

```
In CTF, there are many people who mistakenly encrypt p, q in RSA.
But this time...

Solves: 51 solves
```

# Inspection
---
In this challenge, we are given the source file and the output
```python
from Crypto.Util.number import bytes_to_long, getStrongPrime

from secret import flag

assert len(flag) == 255
e = 3
p = getStrongPrime(1024, e=e)
q = getStrongPrime(1024, e=e)
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
enc_d = pow(d, e, n)
enc_phi = pow(phi, e, n)
enc_flag = pow(bytes_to_long(flag), e, n)
print(f"{n = }")
print(f"{enc_d = }")
print(f"{enc_phi = }")
print(f"{enc_flag = }")
```
It is clear that we need to somehow extract  `d` or `phi` based on `enc_d` and `enc_phi`

## Small e
Since $e = 3$, the first though might be to hope that d is small ( $<n^{1/3}$ ), then we can just take cube root of it to get d. However, in this challenge, both number are too large.

The next thing is to somehow utilize the fact that e is small. We can observe the following two equations.

$$ e\times d \equiv 1 \pmod{\phi(n)} $$ 
$$ e\times d = k_1 \times\phi(n) + 1 $$


Because  $e=3$, $d<n$
Therefore $e\times d < 3n$, and $k_1 \in \{1, 2\}$ 

We now expend `enc_d` according to the above equation

$$ \begin{align} d_{enc}  &\equiv d^3 &\pmod{n} 
\\ e^3 \times d_{enc} &\equiv e^3\times d^3 &\pmod{n} 
\\ 27 \times d_{enc} &\equiv (ed)^3 &\pmod{n}
\\  &\equiv (k_1 * \phi(n) + 1)^3 &\pmod{n}
\\  &\equiv (k_1^3\phi^3(n) + 3k_1^2\phi^2(n) + 3k_1\phi(n) + 1) &\pmod{n}
\\  &\equiv (k_1^3\phi_{enc} + 3k_1^2\phi^2(n) + 3k_1\phi(n) + 1) &\pmod{n} \end{align} $$ 
$$ 3k_1^2\phi^2(n) + 3k_1\phi(n) + k_1^3\phi_{enc} + 1 - 27\times d_{enc}\equiv 0 \pmod{n} $$

We can view the last equation as a quadratic equation with respect to $\phi(n)$, as all other variables are given. However, since n is not a prime, solving such equation is not trival. Therefore we need to furture simplify the equation.

## Substitude phi(n)
Recalling that 

$$\begin{align}\phi(n) &= (p-1)(q-1) 
\\ &= pq - p - q - 1 
\\ &= n - p - q + 1\end{align}$$
$$\phi(n) \equiv -(p+q) + 1 \pmod{n} $$

If we define $r = (p+q)$, we can transfore the above equation

$$\begin{align} 3k_1^2\phi^2(n) + 3k_1\phi(n) + k_1^3\phi_{enc} + 1 - 27\times d_{enc}&\equiv 0 \pmod{n}
\\ 3k_1^2(1-r)^2 + 3k_1(1-r) + k_1^3\phi_{enc} + 1 - 27\times d_{enc}&\equiv 0 \pmod{n}
\\ 3k_1^2(1-2r+r^2) + 3k_1(1-r) + k_1^3\phi_{enc} + 1 - 27\times d_{enc}&\equiv 0 \pmod{n}
\\ 3k_1^2r^2 + (-6k_1^2-3k_1)r + (3k_1^2 + 3k_1 + k_1^3\phi_{enc} + 1 - 27\times d_{enc}) &\equiv 0 \pmod{n} \end{align}$$

Note that since $r = p+q$, it's small compare to n.
Assuming that $p>q$
Since p and q is generate to be 1024 bits, $p/q < 2$

$$ \begin{align} 
\\ r^2 &= (p+q)^2
\\ &= p^2 + q^2 + 2pq
\\ &= p^2 + q^2 + 2n
\\ &\le 5q^2 + 2n
\\ &\le 5n+2n
\\ &\le 7n
\\ 3k_1^2r^2 &\le 3\times 2^2\times r^2
\\ &= 12\times 7n
\\ &= 84n
\\ \end{align}$$

$$ 3k_1^2r^2 + (-6k_1^2-3k_1)r + (3k_1^2 + 3k_1 + k_1^3\phi_{enc} + 1 - 27\times d_{enc}) < 84n $$
$$ 3k_1^2r^2 + (-6k_1^2-3k_1)r + (3k_1^2 + 3k_1 + k_1^3\phi_{enc} + 1 - 27\times d_{enc}) = k_2\times n, k \le 84, k\in \Bbb{Z} $$

Therefore, we can bruteforce all possible $k_2$ and attempt to solve the equation under integer. The root of the equation will be $(p+q)$
# Recover phi, p, q
From the previous equation, we can recover $(p+q)$, so phi can be calculated easily

$$\phi(n) = n - r + 1 $$

To get p or q from n and phi(n), we can do the following calculation

$$\begin{align}  \phi(n) &= n - p - q + 1
\\ pn - p^2 - pq + p - p\phi(n)  &= 0
\\ p^2 - pn + p - p\phi(n) - n&=0
\\ p^2 - (n+phi(n) -1)p -n &=0
\\ \end{align}$$

Solving the quadrtic equation give us p, q as roots
After that, it's just recovering d, and decrypt the flag :)

`HackTM{Have you warmed up? If not, I suggest you consider the case where e=65537, although I don't know if it's solvable. Why did I say that? Because I have to make this flag much longer to avoid solving it just by calculating the cubic root of enc_flag.}`

# Appendix A - sol.sage
{% capture sol_sage %}
```python
from Crypto.Util.number import bytes_to_long, getStrongPrime

from secret import flag

assert len(flag) == 255
e = 3
p = getStrongPrime(1024, e=e)
q = getStrongPrime(1024, e=e)
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
enc_d = pow(d, e, n)
enc_phi = pow(phi, e, n)
enc_flag = pow(bytes_to_long(flag), e, n)
print(f"{n = }")
print(f"{enc_d = }")
print(f"{enc_phi = }")
print(f"{enc_flag = }")
bronson@Bronson_Laptop:/mnt/c/Users/brons/ctf/hacktm2023/crypto_d_phi_enc$ cat sol.sage
from Crypto.Util.number import long_to_bytes
n = 24476383567792760737445809443492789639532562013922247811020136923589010741644222420227206374197451638950771413340924096340837752043249937740661704552394497914758536695641625358888570907798672682231978378863166006326676708689766394246962358644899609302315269836924417613853084331305979037961661767481870702409724154783024602585993523452019004639755830872907936352210725695418551084182173371461071253191795891364697373409661909944972555863676405650352874457152520233049140800885827642997470620526948414532553390007363221770832301261733085022095468538192372251696747049088035108525038449982810535032819511871880097702167
enc_d = 23851971033205169724442925873736356542293022048328010529601922038597156073052741135967263406916098353904000351147783737673489182435902916159670398843992581022424040234578709904403027939686144718982884200573860698818686908312301218022582288691503272265090891919878763225922888973146019154932207221041956907361037238034826284737842344007626825211682868274941550017877866773242511532247005459314727939294024278155232050689062951137001487973659259356715242237299506824804517181218221923331473121877871094364766799442907255801213557820110837044140390668415470724167526835848871056818034641517677763554906855446709546993374
enc_phi = 3988439673093122433640268099760031932750589560901017694612294237734994528445711289776522094320029720250901589476622749396945875113134575148954745649956408698129211447217738399970996146231987508863215840103938468351716403487636203224224211948248426979344488189039912815110421219060901595845157989550626732212856972549465190609710288441075239289727079931558808667820980978069512061297536414547224423337930529183537834934423347408747058506318052591007082711258005394876388007279867425728777595263973387697391413008399180495885227570437439156801767814674612719688588210328293559385199717899996385433488332567823928840559
enc_flag = 24033688910716813631334059349597835978066437874275978149197947048266360284414281504254842680128144566593025304122689062491362078754654845221441355173479792783568043865858117683452266200159044180325485093879621270026569149364489793568633147270150444227384468763682612472279672856584861388549164193349969030657929104643396225271183660397476206979899360949458826408961911095994102002214251057409490674577323972717947269749817048145947578717519514253771112820567828846282185208033831611286468127988373756949337813132960947907670681901742312384117809682232325292812758263309998505244566881893895088185810009313758025764867


# for i in range(1, 3):
for k in range(1, 3):
    # Knowing that ed = k phi(N) + 1 and e = 3, k \in {1, 2}
    alpha = 3*(k^2)
    beta = -(6*(k^2)+3*k)
    gamma = 3*(k^2) + 3*k + (k^3)*enc_phi - 27*int(enc_d) + 1

    #f = alpha*(x^2) + beta*x + gamma
    det = beta^2 - 4*alpha*gamma
    print(det.is_square())
    for i in range(1000):
        gamma -= n
        det = beta^2 - 4*alpha*gamma
        if(det.is_square()):break
    print(k, det, i)
    if(det.is_square()):break


qrs = sqrt(beta^2 - 4*alpha*gamma)
print(qrs)

cand_r = (-1*beta + qrs)/(2*alpha) #p+q
phi = n - cand_r + 1
print(phi)

p = ((n + 1 - phi) + sqrt(((n + 1 - phi) ^ 2) - 4 * n))/ 2
print("p: ", p, n%p)
q = n // p
assert(p*q == n)

d = pow(e, -1, phi)
print(long_to_bytes(int(pow(enc_flag, d, n))))
#HackTM{Have you warmed up? If not, I suggest you consider the case where e=65537, although I don't know if it's solvable. Why did I say that? Because I have to make this flag much longer to avoid solving it just by calculating the cubic root of enc_flag.}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="sol_sage"
    button-text="Show sol.sage" toggle-text=sol_sage%}
