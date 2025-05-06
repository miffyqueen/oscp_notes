When enumerating an box with certain ports open it could occur to be an active Chrome session. To see what's going on in the session forward the ports using #chisel, and add the device to the chrome devices:
chrome://inspect/#devices
Add device, set port forwarding on, and if you see an connection click on inspect to see what's happening.

https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/