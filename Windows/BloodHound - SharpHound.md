#windows #enumeration #ad-enum 
When some credentials are obtained Bloodhound can be an very useful tool. 
Install using pip install bloodhound / apt install bloodhound
Start neo4j console: sudo neo4j console
start ./ or bloodhound 

First run the bloodhound-python module to get data:
		`./bloodhound.py -u support -p#00^BlackKnight -d blackfield.local -ns 10.10.10.192 -c DcOnly`

Then upload data 

### SharpHound
One thing to note is that SharpHound also supports _looping_, which means that the collector will run cyclical queries of our choosing over a period. While the collection method we used above created a _snapshot_ over the domain, running it in a loop may gather additional data as the environment changes. The cache file speeds up the process. For example, if a user logged on after we collected a snapshot, we would have missed it in our analysis. We will not use the looping functionality, but we recommend experimenting with it in the training labs and inspecting the results in BloodHound.

Import SharpHound module `Import-Module .\Sharphound.ps1`
Run sharphound to gather data `Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"`


Bloodhound CE
https://www.centralinfosec.com/blog/bloodhound-kali-install