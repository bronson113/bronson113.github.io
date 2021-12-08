# HITCONCTF - baba is game


# Challenge Description

```
JIJI IS SHUT
JIJI IS STOP
TEXT HAS TEXT
JIJI IS JIJI
BABA IS YOU
JIJI IS OPEN
JIJI IS NOT YOU
HEDGE IS STOP
JIJI HAS JIJI
TEXT IS NOT YOU

nc 35.72.58.250 5566

Author: ddaa
Solves: 16/286
```

# Inspection

We are given a CLI and a GUI version of baba is you. The game level file is also given. By running the GUI version, we can see the level.

![game](/img/HITCONCTF2021-baba-is-game-game.png)

By reversing the CLI, we know we can start new game with 'g', move baba with 'w', 'a', 's', 'd', and undo move with 'x'. 

# Developing exploit

Since we know that we will eventually send out input to the remote server, I modified the GUI file so that it logs my movement so I can submit it later. I also add a reply feature to run to certain save state after recorded sequence of moves. 

```python
def main():
#...
if len(sys.argv)==3:
        checkpoint = open(sys.argv[2]).read()
    else:
        checkpoint = ''
    for i in checkpoint:
        if i == 'w':
            game.MovePlayer(pyBaba.Direction.UP)
        elif i == 's':
            game.MovePlayer(pyBaba.Direction.DOWN)
        elif i == 'a':
            game.MovePlayer(pyBaba.Direction.LEFT)
        elif i == 'd':
            game.MovePlayer(pyBaba.Direction.RIGHT)
        elif i == 'x':
            game.Undo()
inputs = checkpoint
#...
if event.key == pygame.K_UP:
	inputs+='w'  #same goes with other movement, log the relevent keys
#...
if event.key == pygame.K_ESCAPE:
	print(inputs) #print the current inputs and log it in file
	with open("checkpoint.txt","w") as f:
		f.write(inputs)
```

# The bug


After playing around with the GUI version of the game, we notice that putting blocks in an arrangement that spells out 'x has you' allows us to control x, which is different from the original game. This bug allow us to move jiji out of the way, construct baba is win, and move jiji onto baba to win. After getting the sequence from the modified GUI, we can submit the movements to the remote server (convert it so that we send each character one by one) and get the flag . 

`hitcon{th3_0r1g1n4l_m4p_1s_N9RV-FZU9}`

We later know that the intended solution has something to do with the reordering of tile when undoing moves.

# Appendix - submit solution.py

```python
from pwn import *

nc_str = 'nc 35.72.58.250 5566'
HOST = nc_str.split(' ')[1]
PORT = nc_str.split(' ')[2]
#p = process('nc 35.72.58.250 5566')
p = remote(HOST, PORT)

s = 'aaaawdwwdddsasddddddddaaaaaaaaawaaaaasdddddddddsdwaawwdsddddddwwwwddddwwdddsssdsaaaaaaawasssssssasdddwddsaaaaawwwdwwwwwwwwwdwdddddsaaaaawasssssssssssaaasdddddddddddddaaaaaaaaaaadwwwwwwwwwwwdddddddd'

for i in s:
    p.sendline(i)

p.interactive()
#hitcon{th3_0r1g1n4l_m4p_1s_N9RV-FZU9}
```