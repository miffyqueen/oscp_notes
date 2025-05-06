List all Databases:
```sql
SELECT name, database_id, create_date FROM sys.databases;
```

List all tables inside database TestDB:
```sql
SELECT table_name, table_schema, table_type FROM information_schema.tables WHERE table_catalog = 'orcharddb' ORDER BY table_name ASC;
```

List all tables on all databases:
```sql
SELECT * FROM information_schema.tables ORDER BY table_name ASC;
```

Describe tables:
```sql
EXEC sp_columns @table_name = N'spt_fallback_db';
```

🔐 **Authentication and User Info**
```sql
-- Current user
SELECT SYSTEM_USER;

-- Connected login and user context
SELECT SUSER_NAME(), USER_NAME();

-- List all logins (requires sufficient permissions)
SELECT name, type_desc, is_disabled FROM sys.server_principals;

-- List database users
SELECT name, type_desc FROM sys.database_principals;

-- Check roles of current user
SELECT IS_SRVROLEMEMBER('sysadmin'); -- returns 1 if sysadmin

-- Show server roles and members
SELECT role_principal.name AS RoleName, member_principal.name AS MemberName
FROM sys.server_role_members
JOIN sys.server_principals AS role_principal ON role_principal.principal_id = server_role_members.role_principal_id
JOIN sys.server_principals AS member_principal ON member_principal.principal_id = server_role_members.member_principal_id;

```

🗄️ **Database and Table Discovery**
```sql
-- List all databases
SELECT name FROM sys.databases;

-- Switch database
USE <database_name>;

-- List all schemas in the current database
SELECT name FROM sys.schemas;

-- List all tables in the current database
SELECT * FROM information_schema.tables;

-- List all columns in a specific table
SELECT * FROM information_schema.columns WHERE table_name = '`managed_backup`';

-- Get row count of all tables
SELECT t.NAME AS TableName, p.rows AS RowCounts
FROM sys.tables t
JOIN sys.partitions p ON t.object_id = p.object_id
WHERE p.index_id IN (0,1)
GROUP BY t.NAME, p.rows;

```

📜 **Stored Procedures, Triggers, and Views**
```sql
-- List all stored procedures
SELECT * FROM information_schema.routines WHERE routine_type = 'PROCEDURE';

-- List all views
SELECT * FROM information_schema.views;

-- List all triggers
SELECT name, object_id, parent_id, type_desc FROM sys.triggers;

```

⚙️ **Linked Servers & xp_cmdshell (Privilege Escalation)**
```sql
-- Check for linked servers
EXEC sp_linkedservers;

-- List logins on linked servers
EXEC sp_helpserver;

-- Check if xp_cmdshell is enabled
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';

-- Enable xp_cmdshell (if you're sysadmin)
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

-- Run OS command via xp_cmdshell
EXEC xp_cmdshell 'whoami';

```

🧠 **System Info & Fingerprinting**
```sql
-- SQL Server version
SELECT @@VERSION;

-- Server name & domain
SELECT SERVERPROPERTY('MachineName'), SERVERPROPERTY('InstanceName'), SERVERPROPERTY('IsClustered');

-- Host OS information
EXEC xp_cmdshell 'systeminfo';

-- Network config
EXEC xp_cmdshell 'ipconfig /all';

-- List local users (Windows)
EXEC xp_cmdshell 'net user';
```

🧰 **Optional Impacket Tips**
```
# Connect
python3 mssqlclient.py <user>:<pass>@<target> -windows-auth

# Enable xp_cmdshell if sysadmin
enable_xp_cmdshell

# Run commands directly
xp_cmdshell whoami

```