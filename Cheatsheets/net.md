User and Group Management
net user [username]					View details of a user account.
net user [username] [password] /add			Create a new user with a password.
net user [username] /delete				Delete a user.
net user [username] * /domain				Change password (prompted) on domain.
net group [groupname] /domain				View group members (domain group).
net localgroup						List local groups.
net localgroup [groupname]				View members of a local group.
net localgroup [groupname] [username] /add		Add user to local group.
net localgroup [groupname] [username] /delete		Remove user from local group.

Domain & Computer Management
net accounts /domain							View domain password policy.
net config workstation							View workstation config.
net config server							View server config.
net time /domain							View time from domain controller.
net time \\[DC-name] /set /yes						Sync time with a DC.
netdom join %computername% /domain:[domain] /userd:[user] /passwordd:*	Join a domain (using netdom, not net).
netdom remove [computername] /domain:[domain]				Remove a computer from domain.

Network and Session Info
net view						List computers in current domain/workgroup.
net view \\[computername]				View shared resources on a remote computer.
net use							Show active network connections.
net use [drive:] \\[computer]\[share]			Map a network drive.
net use [drive:] /delete				Remove mapped drive.
net session						View local sessions.
net file						List open files over the network.

Service and Logon Management
net start						List running services.
net start [service]					Start a service.
net stop [service]					Stop a service.
net logon						Manage logon service (e.g., force secure channel refresh).
net stop netlogon / net start netlogon			Restart Netlogon service.
net use \\[domaincontroller]\IPC$ /user:[domain]\[user]	Connect to DC using alternate credentials.

Troubleshooting AD
netdiag /v						Network diagnostics (legacy).
nltest /dsgetdc:[domain]				Find a domain controller.
nltest /sc_verify:[domain]				Verify secure channel to a domain.
net group "Domain Admins" /domain			View domain admins.
