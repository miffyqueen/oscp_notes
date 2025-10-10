<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# Common Default and Weak Credentials for OSCP Exam Preparation

**Main Takeaway:**
Before launching brute-force tools like Hydra, trying a concise set of known default and weak credential pairs can often yield quick wins on OSCP exam machines. The following list compiles the most frequently encountered user–password combinations reported by OSCP candidates across Reddit, CSDN, Medium, and various community write-ups.

## 1. Generic Service Logins

These credentials apply to web applications, CMS platforms, and general service accounts:


| Username | Password | Notes |
| :-- | :-- | :-- |
| admin | admin | Very common default on web admin panels[^1] |
| admin | password | Baseline weak password trial[^2] |
| username | username | Default placeholder credential[^1] |
| user | user | Often used in demo or tutorial setups |
| guest | guest | Common for demo accounts |
| test | test | Test accounts on various services |
| root | toor | Classic Linux default root password |
| root | root | Some internal builds use same username/pw |

## 2. CMS-Specific Credentials

During web application enumeration (e.g., WordPress, Joomla), these default logins frequently appear:


| CMS Platform | Username | Password | Source |
| :-- | :-- | :-- | :-- |
| WordPress | wordpress | wordpress | Default installer credentials[^2] |
| WordPress | admin | wordpress | Common weak admin password[^2] |
| Automattic-Admin | automattic | automattic | Automattic platform defaults[^2] |
| Joomla | admin | admin123 | Frequently documented in exploits |

## 3. Exam-Specific Machine Accounts

Some Proving Grounds/OSCP machines use unique credentials mentioned by multiple candidates:


| Username | Password | Context |
| :-- | :-- | :-- |
| empireadmin | exegol4thewin | Reported on “All Things OSCP” machine[^3] |
| student | pwnme123 | Educational lab exercises |

## 4. Windows Service Defaults

For Windows-based services and appliances encountered in OSCP labs:


| Service | Username | Password | Remarks |
| :-- | :-- | :-- | :-- |
| VNC | administrator | admin | Default VNC server credential |
| RDP | administrator | admin123 | Lab appliance defaults |
| Fortinet SSLVPN | fortinet | fortinet | Common VPN portal default |


***

**Usage Strategy:**

1. **Light enumeration:** Attempt these pairs manually in Burp Intruder or via service-specific login pages.
2. **Wordlist creation:** Build a minimal wordlist (e.g., admin, user, test, password, toor, wordpress, automattic) and pair each with itself and with “password” and “123”, then script Hydra or Medusa against this list.
3. **Contextual adjustments:** Tailor the username list based on discovered service/product names (e.g., use `cmsname:cmsname` if you identify a CMS).

Running through this curated list prior to full brute-forcing often uncovers default or intentionally weak credentials swiftly, saving time during OSCP exam engagements.
<span style="display:none">[^10][^11][^12][^13][^14][^15][^16][^17][^18][^4][^5][^6][^7][^8][^9]</span>

<div align="center">⁂</div>

[^1]: https://www.hack-notes.pro/your-path-to-the-oscp+

[^2]: https://www.reddit.com/r/oscp/comments/tjz1k2/find_credentials_for_web_application_login_and_rce/

[^3]: https://www.reddit.com/r/oscp/best/

[^4]: https://blog.csdn.net/qq_34935231/article/details/115086729

[^5]: https://elhacker.info/ebooks Joas/OSCP NOTES.pdf

[^6]: https://systemweakness.com/6-vs-1-battle-my-oscp-strategy-dd23cc0e912b

[^7]: https://www.scribd.com/document/900194871/内网渗透-最全的内网凭据密码收集方法和技巧总结-LaoKey-s-Blog

[^8]: https://infosecwriteups.com/how-i-achieved-100-points-in-oscp-in-just-3-4-months-my-2025-journey-795a7f6f05e5

[^9]: https://oscp-certification.certs-study.com/password-attacks/default-credentials

[^10]: https://hackmd.io/@lMbQj6JRTiqzvaJFzewN2w/HyNt3pS0o

[^11]: https://github.com/RajChowdhury240/OSCP-CheatSheet

[^12]: https://github.com/0ps/security_w1k1?search=1

[^13]: https://github.com/saisathvik1/OSCP-Cheatsheet

[^14]: https://blog.csdn.net/m0_52545432/article/details/131236695

[^15]: https://www.cnblogs.com/ylist/p/19043537

[^16]: https://gist.github.com/OTaKuHP/6673b3655c720334262df7fe44d1f256

[^17]: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/identity_management_guide/logging-in

[^18]: https://www.scribd.com/document/917858238/域渗透攻防指南原稿目录

