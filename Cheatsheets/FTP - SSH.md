lftp -> https://linux.die.net/man/1/lftp
```
#FTP using SSL
lftp -u username ip 
lftp web1@240.0.0.1 -> set ssl:verify-certificate off
```

|Command/Option|Example|Description|
|---|---|---|
|`ftp host`|`ftp ftp.example.com`|Connect to an FTP server|
|`open host`|`open ftp.example.com`|Connect to an FTP server|
|`user`|`user username password`|Log in with username and password|
|`ls`|`ls`|List files in the current directory|
|`cd`|`cd /path/to/dir`|Change remote directory|
|`get`|`get file.txt`|Download a file from the server|
|`put`|`put file.txt`|Upload a file to the server|
|`mget`|`mget *.txt`|Download multiple files|
|`mput`|`mput *.txt`|Upload multiple files|
|`delete`|`delete file.txt`|Delete a file on the server|
|`mkdir`|`mkdir newdir`|Create a new directory on the server|
|`rmdir`|`rmdir olddir`|Remove a directory on the server|
|`bye`|`bye`|Close the connection and exit|
## Options [#](https://www.cheatsoverview.com/cheatsheets/userland-tools/gnu/ftp/#options)

|Command/Option|Example|Description|
|---|---|---|
|`-n`|`ftp -n`|Disable auto-login to the server|
|`-v`|`ftp -v`|Enable verbose mode for debugging|

#ftp client commands
binary - set binary transfer type
cd - change remote working directory
lcd - change local working directory
get - recieve file
mget - get multiple files
passive - enter passive transfer mode
ls - list contents of remote directory

|   |   |
|---|---|
|`ssh pi@raspberry -p 3344`|Connect to the device `raspberry` on a specific port 3344 as user `pi`|
|`ssh -i /path/file.pem admin@192.168.1.1`|Connect to `root@192.168.1.1` via the key file `/path/file.pem` as user `admin`|
|`ssh root@192.168.2.2 'ls -l'`|Execute remote command `ls -l` on `192.168.2.2` as user `root`|
|`$ ssh user@192.168.3.3 bash < script.sh`|Invoke the script `script.sh` in the current working directory spawning the SSH session to `192.168.3.3` as user `user`|
|`ssh friend@Best.local "tar cvzf - ~/ffmpeg" > output.tgz`|Compress the `~/ffmpeg` directory and download it from a server `Best.local` as user `friend`|
|**`ssh-keygen`**|**Generate SSH keys (follow the prompts)**|
|`ssh-keygen -F [ip/hostname]`|Search for some IP address or hostname from `~/.ssh/known_hosts` (logged-in host)|
|`ssh-keygen -R [ip/hostname]`|Remove some IP address or hostname from `~/.ssh/known_hosts` (logged-in host)|
|`ssh-keygen -f ~/.ssh/filename`|Specify file name|
|`ssh-keygen -y -f private.key > public.pub`|Generate public key from private key|
|`ssh-keygen -c -f ~/.ssh/id_rsa`|Change the comment of the key file `~/.ssh/id_rsa`|
|`ssh-keygen -p -f ~/.ssh/id_rsa`|Change passphrase of private key `~/.ssh/id_rsa`|
|`ssh-keygen -t rsa -b 4096 -C "my@email.com"`|Generate an RSA 4096-bit key with “`my@email.com`” as a comment:  <br>`-t`: Type of key (`rsa, ed25519, dsa, ecdsa`)  <br>`-b`: The number of bits in the key  <br>`-C`: Provides a new comment|
|**`scp`**|**Copy files securely between servers**|
|`scp user@server:/folder/file.ext dest/`|Copy from remote to local destination `dest/`|
|`scp dest/file.ext user@server:/folder`|Copy from local to remote|
|`scp user1@server1:/file.ext user2@server2:/folder`|Copy between two different servers|
|`scp user@server:/folder/* .`|Copies from a server folder to the current folder on the local machine|
|`scp -r`|Recursively copy entire directories|
|`scp -r user@server:/folder dest/`|Copy the entire folder to the local destination `dest/`|
|`scp user@server:/folder/* dest/`|Copy all files from a folder to the local destination `dest/`|
|`scp -C`|Option to compress data|
|`scp -v`|Option to print verbose info|
|`scp -p`|Option to preserve the last modification timestamps of the transferred files|
|`scp -P 8080`|Option to connect to remote host port 8080|
|`scp -B`|Option for [batch mode](https://www.thegeekstuff.com/2009/10/how-to-execute-ssh-and-scp-in-batch-mode-only-when-passwordless-login-is-enabled/) and prevent you from entering passwords or passphrases|
|**`sftp`**|**Securely transfer files between servers**|
|`sftp -p`|Option to preserve the last modification timestamps of the transferred files|
|`sftp -P 8080`|Option to connect to remote host port 8080|
|`sftp -r`|Recursively copy entire directories when uploading and downloading. SFTP doesn’t follow symbolic links encountered in the tree traversal.|
