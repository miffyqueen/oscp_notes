# Let me consolidate the information and create an analysis of the current OSCP notes vs TJ Null list coverage
import pandas as pd
import json

# Define what the attached notes contain
current_notes = {
    "01-enumeration-master.md": {
        "covers": ["nmap scanning", "service enumeration", "web enumeration", "SMB enumeration", "common services"],
        "strengths": ["comprehensive port coverage", "copy-paste ready commands", "time management strategy"],
        "gaps": ["advanced web fuzzing", "API testing", "NoSQL injection", "SSRF", "XXE"]
    },
    "02-windows-privesc.md": {
        "covers": ["basic enumeration", "automated tools", "service exploits", "token impersonation", "registry abuse"],
        "strengths": ["WinPEAS integration", "clear methodology", "multiple escalation paths"],
        "gaps": ["advanced UAC bypass", "AppLocker bypass", "modern Windows 11 techniques", "AMSI bypass"]
    },
    "03-linux-privesc.md": {
        "covers": ["SUID binaries", "sudo misconfig", "kernel exploits", "cron jobs", "capabilities"],
        "strengths": ["LinPEAS integration", "comprehensive SUID checks", "manual techniques"],
        "gaps": ["container escapes", "modern systemd abuse", "advanced LD_PRELOAD", "Python library hijacking"]
    },
    "04-webapp-testing.md": {
        "covers": ["directory enumeration", "SQLi", "LFI/RFI", "XSS", "command injection", "file uploads"],
        "strengths": ["multiple tools coverage", "manual testing", "comprehensive payloads"],
        "gaps": ["SSTI advanced", "JWT attacks", "GraphQL", "WebSocket attacks", "HTTP smuggling"]
    },
    "05-active-directory.md": {
        "covers": ["domain enumeration", "Kerberoasting", "ASREPRoast", "lateral movement", "DCSync"],
        "strengths": ["BloodHound integration", "attack paths", "post-exploitation"],
        "gaps": ["ADCS attacks", "modern delegation attacks", "Azure AD integration", "cross-forest attacks"]
    },
    "06-exam-strategy.md": {
        "covers": ["time management", "exam format", "methodology", "mental preparation"],
        "strengths": ["comprehensive strategy", "point allocation", "common scenarios"],
        "gaps": ["2024-2025 format updates", "new AD emphasis", "specific box difficulties"]
    },
    "07-post-exploitation.md": {
        "covers": ["pivoting", "lateral movement", "persistence", "credential harvesting"],
        "strengths": ["multiple pivot methods", "comprehensive credential hunting", "cleanup techniques"],
        "gaps": ["cloud pivoting", "modern AV evasion", "living-off-the-land binaries", "memory-only attacks"]
    }
}

# Common OSCP candidate struggles from research
common_struggles = {
    "enumeration": [
        "Missing non-standard ports",
        "Insufficient web directory enumeration", 
        "Not checking all HTTP methods",
        "Skipping version-specific exploits",
        "Not fuzzing parameters thoroughly",
        "Missing backup/old files",
        "Not checking robots.txt, sitemap.xml",
        "Insufficient SMB enumeration"
    ],
    "web_exploitation": [
        "Manual SQL injection over SQLMap dependency",
        "Local File Inclusion to RCE chains", 
        "File upload bypasses",
        "Command injection in parameters",
        "SSTI identification and exploitation",
        "API endpoint discovery and abuse",
        "Custom web application logic flaws",
        "Authentication bypass techniques"
    ],
    "privilege_escalation": [
        "Kernel exploits on older systems",
        "Service misconfigurations",
        "Scheduled tasks/cron job abuse", 
        "SUID/sudo misconfiguration",
        "Token impersonation (Windows)",
        "Path hijacking",
        "DLL hijacking",
        "Capabilities abuse (Linux)"
    ],
    "active_directory": [
        "Initial domain foothold",
        "Password spraying techniques",
        "Kerberoasting service accounts",
        "ASREPRoasting accounts",
        "Lateral movement with credentials",
        "BloodHound attack path analysis",
        "Pivoting between domains",
        "DCSync and golden ticket attacks"
    ],
    "time_management": [
        "Getting stuck in rabbit holes",
        "Not moving between machines",
        "Poor documentation during exam",
        "Insufficient breaks leading to fatigue",
        "Not using timers effectively"
    ]
}

# TJ Null list scenarios from research
tj_null_scenarios = {
    "easy_boxes": [
        "Basic web app exploits (SQLi, LFI, file upload)",
        "Simple privilege escalation (sudo -l, SUID)",
        "Default credentials",
        "Obvious service exploits (SMB, FTP anonymous)",
        "Basic enumeration wins"
    ],
    "medium_boxes": [
        "Chained exploits",
        "Custom web applications", 
        "Kernel exploits",
        "Service configuration issues",
        "Multiple privilege escalation vectors"
    ],
    "hard_boxes": [
        "Advanced web exploitation",
        "Custom exploit development",
        "Complex privilege escalation chains",
        "Uncommon services",
        "Reverse engineering components"
    ],
    "active_directory": [
        "Domain enumeration from external",
        "Password spraying", 
        "Kerberoasting",
        "ASREPRoast",
        "Lateral movement",
        "Domain controller compromise",
        "Golden/Silver ticket attacks"
    ]
}

print("=== OSCP NOTES ANALYSIS vs TJ NULL LIST & CANDIDATE STRUGGLES ===")
print("\n1. CURRENT NOTES COVERAGE ANALYSIS:")
for note, details in current_notes.items():
    print(f"\n{note}:")
    print(f"  Strengths: {', '.join(details['strengths'])}")
    print(f"  Gaps: {', '.join(details['gaps'])}")

print("\n\n2. COMMON CANDIDATE STRUGGLE AREAS:")
for category, struggles in common_struggles.items():
    print(f"\n{category.upper().replace('_', ' ')}:")
    for struggle in struggles:
        print(f"  - {struggle}")

print("\n\n3. TJ NULL LIST SCENARIO COVERAGE:")
for difficulty, scenarios in tj_null_scenarios.items():
    print(f"\n{difficulty.upper().replace('_', ' ')} SCENARIOS:")
    for scenario in scenarios:
        print(f"  - {scenario}")