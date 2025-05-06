## Chisel ##
Start an reverse listening server on your local machine:
`chisel server --reverse -p 9001`
Upload chisel to infected machine: 
`scp chisel user@host:/path/to/chisel`
Start chisel client on infected machine:
`chisel client 10.10.16.7:9001 R:8111:127.0.0.1:8111`

### SSH ###
```
# $LOCAL_IP: 'localhost' or machine from local network
# $LOCAL_PORT: open port on local machine
# $REMOTE_IP: remote localhost or IP from remote network
# $REMOTE_PORT: open port on remote site

# Forward Tunnel: map port from remote machine/network on local machine
ssh -L $LOCAL_PORT:$REMOTE_IP:$REMOTE_PORT $USER@$SERVER

# Reverse Tunnel: make local port accessable to remote machine
ssh -R $REMOTE_PORT:$LOCAL_IP:$LOCAL_PORT $USER@$SERVER
```
