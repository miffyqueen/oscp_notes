# Windows Flag Hunting Cheat Sheet for OSCP

**_Usage_**: Copy and paste commands below. Replace placeholders (e.g., `<DRIVE>`, `<USERNAME>`, `<PATTERN>`) as needed.

---

## 1. List Root Directories on C:\
```bat
:: Change drive if different
<DRIVE>:
dir \ /AD
```

## 2. Enumerate User Profiles
```bat
dir C:\Users /B
```

## 3. List Desktop and Documents for Each User
```bat
for /D %%u in (C:\Users\*) do (
  echo ==== %%~nxu ====
  dir "C:\Users\%%~nxu\Desktop" "C:\Users\%%~nxu\Documents" /A-D 2>nul
)
```

## 4. Search for Flag-Like Files by Name
```bat
:: Common patterns: flag, proof, local, root, user
for %%p in (flag proof local root user) do (
  echo ==== Searching *%%p*.* ====
  dir C:\*%%p*.* /S /A-D 2>nul
)
```

## 5. Grep .txt Files for Keywords
```bat
:: Requires findstr
for /R C:\ %%f in (*.txt) do (
  findstr /I "flag proof local root user" "%%f" >nul && echo Found in %%f
)
```

## 6. Display Specific Flag Files
```bat
:: Example: Proof file on Administrator Desktop
:: Change <USERNAME> as needed
for %%u in (Administrator Guest Default) do (
  type "C:\Users\%%u\Desktop\proof.txt" 2>nul
  type "C:\Users\%%u\Desktop\flag.txt" 2>nul
  type "C:\Users\%%u\Desktop\local.txt" 2>nul
)
```

## 7. Search Common Web Root Paths
```bat
:: WAMP
dir C:\wamp\www\htdocs\*local*.* /S /A-D 2>nul
:: IIS
dir C:\inetpub\wwwroot\*flag*.* /S /A-D 2>nul
```

## 8. Recursively Find Filenames Containing Keywords
```bat
:: Finds files named with keywords anywhere
powershell -Command "Get-ChildItem -Path C:\ -Include *flag*,*proof*,*local*,*root*,*user* -File -Recurse -ErrorAction SilentlyContinue"
```

## 9. Verify Downloaded Binaries in Temp
```bat
cd %TEMP%
dir JuicyPotato.exe nc.exe 2>nul
```

## 10. Combine Commands into One Script
Save as `find_flags.bat` and run:
```bat
@echo off
set DRIVE=<DRIVE>
set PATTERNS=flag proof local root user
%DRIVE%:

echo Listing root dirs on %DRIVE%:
dir \ /AD

echo Enumerating users:
dir C:\Users /B

echo \nScanning for files matching patterns:\nfor %%p in (%PATTERNS%) do (
  echo ==== %%p ====
  dir C:\*%%p*.* /S /A-D 2>nul
)

echo \nGrep text files for keywords:\nfor /R C:\ %%f in (*.txt) do (
  findstr /I "%PATTERNS%" "%%f" >nul && echo Found in %%f
)

echo \nPowerShell recursive search:\nPowerShell -Command "Get-ChildItem -Path C:\ -Include *%PATTERNS%* -File -Recurse -ErrorAction SilentlyContinue"
```

**_Example Usage_**:
```bat
:: Edit and run
set DRIVE=D
find_flags.bat
```

---

**Common Flag Filenames**:
- proof.txt, proof.md
- flag.txt, flag.pdf
- local.txt, local.md
- root.txt, root.pdf
- user.txt, user.md
- FLAG.jpg, flag.png

*Tailor patterns above to search additional extensions as needed.*
