# HITCONCTF - cclemon


# Description



```
Speak in 🍋

Author: david942j
Solved: 24/286
```

# Inspection


Opening the file, we see that there is some byte code, it resembles python byte code, so we start reversing it as if it is in python.

# Simulation



With that, we slowly build up a python version of the code, as shown here in [solve.py](#appendix---solvepy), we then run it with pypy3 to receive the flag. The initial version doesn't produce the right answer, so we need to recheck each comparison and make sure the python script is running exactly the same thing as the byte code

`hitcon{42978937495235537896}`

After the competition, we learn that the code is actually in lemon language, hence the challenge title - cclemon

# Appendix - solve.py



```python
g0 = 68694329

def w():
    global g0
    g0 = (g0 * 1259409 + 321625345) % 4294967296
    return g0

g1 = w

class A:
    def __init__(self, n):
        self.a = []
        i = 0
        while i < n:
            self.a.append(g1())
            i += 1
        return

    def r(self, x, y):
        if x <= y:
            while x < y:
                self.s(x, y)
                x += 1
                y -= 1
            return
        else:
            return self.r(y, x)

    def s(self, x, y):
        l2 = self.a[x]
        self.a[x] = self.a[y]
        self.a[y] = l2
        return

    def o(self, x, y, val):
        if x > y:
            return self.o(y, x, val)
        else:
            i = x
            while i <= y:
                self.a[i] ^= val
                i += 1
            return

a = A(200000)
i = 0
while i < 200000 * 5:
    c = g1() % 3
    x = g1() % 200000
    y = g1() % 200000
    if c == 0:
        a.r(x, y)
    elif c == 1:
        a.s(x, y)
    elif c == 2:
        a.o(x, y, g1())
    i += 1
i = 0
sum = 0
while i < 200000:
    sum = sum + a.a[i] * (i + 1)
    i += 1

print("hitcon{" + str(sum) + "}")
```
