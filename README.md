![things](/img/precrime.gif?raw=true "text")  
## Intrusion Prediction

A repo for publishing the output of an experimental intrusion prediction project. Output is posted here where it is timestamped so that any correct predictions can be verified in linear time without creating a causality loop.  A rating of 'hot' means the CVE will land on one or more watchlists due to significance, exploitation and / or impact.

Contents:

2024: CVEs from calendar 2024 that came out of the model rated 'hot.' 

2025: CVEs from calendar 2025 that came out of the model rated 'hot.'

The 2024 set has not been through search space reduction yet but it will be soon. Predictions will be output here for 2025 CVEs at least monthly, maybe weekly, as the year goes on.

Predictions so far:

March 3: CVE-2024-4885 was added to the KEV. It was rated hot in the Jan 3 run, a prediction time of two months, the longest so far. (18)
```CVE-2024-4885 hot	Progress Software Corporation	WhatsUp Gold	"In WhatsUp Gold versions released before 2023.1.3 an unauthenticated Remote Code Execution vulnerability in Progress WhatsUpGold. WhatsUp.ExportUtilities.Export.GetFileWithoutZip allows execution of commands with iisapppool\nmconsole privileges.```

Feb 25: CVE 2024-49035 was added to the KEV. It was rated hot in the Jan 3 run. 
```25614	CVE-2024-49035	Microsoft	Microsoft Partner Center	An improper access control vulnerability in Partner.Microsoft.com allows an a unauthenticated attacker to elevate privileges over a network.	neutral	hot```

Feb 20: CVE-2025-0111 was added to the KEV, rated hot in the Feb 15 run. (16)
```CVE-2025-0111	Palo Alto Networks	Cloud NGFW	"An authenticated file read vulnerability in the Palo Alto Networks PAN-OS software enables an authenticated attacker with network access to the management web interface to read files on the PAN-OS filesystem that are readable by the “nobody” user.```

Feb 18: CVE 2024-53704 was added to the KEV today. This one was predicted to go hot by the model in the Jan 17 run which is 31 days early warning. It could have been in the Jan 3 run but some CVEs were not in the data then because my loader was missing a few.**

```CVE-2024-53704	hot	SonicWall	SonicOS	An Improper Authentication vulnerability in the SSLVPN authentication mechanism allows a remote attacker to bypass authentication.```

Feb 18: CVE 2025-0108 was added to the KEV today. This one was predicted to go hot by the model in the Feb 15 run. It could have been predicted Feb 12 but I am not running the model daily yet.**

```CVE-2025-0108	Palo Alto Networks	Cloud NGFW	"An authentication bypass in the Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to bypass the authentication otherwise required by the PAN-OS management web interface and invoke certain PHP scripts. While invoking these PHP scripts does not enable remote code execution, it can negatively impact integrity and confidentiality of PAN-OS. You can greatly reduce the risk of this issue by restricting access to the management web interface to only trusted internal IP addresses according to our recommended  best practices deployment guidelines https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431. This issue does not affect Cloud NGFW or Prisma Access software."	hot ```

Feb 12: CVE 2024-41710 was added to the KEV today. This one was predicted to go hot by the model in the Jan 7 run which is the longest lead time so far at 51 days!**
```CVE-2024-41710			"A vulnerability in the Mitel 6800 Series, 6900 Series, and 6900w Series SIP Phones, including the 6970 Conference Unit, through R6.4.0.HF1 (R6.4.0.136) could allow an authenticated attacker with administrative privilege to conduct an argument injection attack, due to insufficient parameter sanitization during the boot process. A successful exploit could allow an attacker to execute arbitrary commands within the context of the system."	hot```

Feb 6: CVE 2024-21413 was added to the KEV today. This one was predicted to go hot by the model in the Jan 3 run which is the longest lead time so far at 35 days! (12)
https://github.com/cyberdyne-ventures/predictions/blob/main/2024/2024-predictions.txt

```8317	CVE-2024-21413	Microsoft	Microsoft Office 2019	Microsoft Outlook Remote Code Execution Vulnerability	neutral	hot```

Feb 5: CVE 2024-53104 was added to the KEV today. This one was predicted to go hot by the model in the Jan 3 run which is the longest lead time so far at 34 days!
https://github.com/cyberdyne-ventures/predictions/blob/main/2024/2024-predictions.txt

```17109	CVE-2024-53104	Linux	Linux	"In the Linux kernel, the following vulnerability has been resolved:```
```media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format```
```This can lead to out of bounds writes since frames of this type were not taken into account when calculating the size of the frames buffer in uvc_parse_streaming."	neutral	hot```

CVE 2024-29059 was added to the KEV on Feb 4. It was predicted hot in the Jan 17 run of the 2024 CVEs, 18 days ago. It should have been in the Jan 3 output but a few of the 2024 CVEs were not in the dataframe then.
```CVE-2024-29059	hot	Microsoft	Microsoft .NET Framework 4.8	.NET Framework Information Disclosure Vulnerability	```

CVE-2024-12686 was added to the KEV on January 13. It was classified 'hot' by my model on January 3 - ten days prior to the KEV addition - in this output file which was committed to Github on that day (https://github.com/cyberdyne-ventures/predictions/blob/main/2024/2024-predictions.txt) Commit history: https://github.com/cyberdyne-ventures/predictions/compare/ca99f27cd91bc6251ffd5c22aa1b18f1dab0d214...40cc5c07883f41762139050820d40ebe787dce4c
```18609	CVE-2024-12686	BeyondTrust	Remote Support(RS) & Privileged Remote Access(PRA)	A vulnerability has been discovered in Privileged Remote Access (PRA) and Remote Support (RS) which can allow an attacker with existing administrative privileges to inject commands and run as a site user.	neutral	hot```

These predictions were made by the January 3 run, around three weeks ahead of being added to the other KEV (not CISA, the *other* KEV.) (8)

Jan22 	CVE-2024-6205	Unknown	PayPlus Payment Gateway	"The PayPlus Payment Gateway WordPress plugin before 6.6.9 does not properly sanitise and escape a parameter before using it in a SQL statement via a WooCommerce API route available to unauthenticated users, leading to an SQL injection vulnerability."	hot

Jan22	CVE-2024-32735	CyberPower	CyberPower PowerPanel Enterprise	"An issue regarding missing authentication for certain utilities exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can access the PDNU REST APIs, which may result in compromise of the application."	neutral	hot

Jan22	CVE-2024-32737	CyberPower	CyberPower PowerPanel Enterprise	"A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can leak sensitive information via the ""query_contract_result"" function within MCUDBHelper."	neutral	hot

Jan22	CVE-2024-32738	CyberPower	CyberPower PowerPanel Enterprise	"A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can leak sensitive information via the ""query_ptask_lean"" function within MCUDBHelper."	neutral	hot

Jan22	CVE-2024-32736	CyberPower	CyberPower PowerPanel Enterprise	"A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can leak sensitive information via the ""query_utask_verbose"" function within MCUDBHelper."	neutral	hot

Jan22	CVE-2024-32739	CyberPower	CyberPower PowerPanel Enterprise	"A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can leak sensitive information via the ""query_ptask_verbose"" function within MCUDBHelper."	neutral	hot

Rated hot January 3, mentioned in VulnVerse Jan 5: (https://www.linkedin.com/pulse/security-week-review-vulnverse-23-marko-%25C5%25BEivanovi%25C4%2587-4sstf/)
CVE-2024-12856	Four-Faith	F3x24	The Four-Faith router models F3x24 and F3x36 are affected by an operating system (OS) command injection vulnerability.

Rated hot & added to the KEV Jan 8:

CVE-2025-0282	Ivanti	Connect Secure	"A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution."	hot

Rated hot & added to the KEV Jan 7:

CVE-2024-55550			"Mitel MiCollab through 9.8 SP2 could allow an authenticated attacker with administrative privilege to conduct a local file read, due to insufficient input sanitization. A successful exploit could allow the authenticated admin attacker to access resources that are constrained to the admin access level, and the disclosure is limited to non-sensitive system information. This vulnerability does not allow file modification or privilege escalation."	hot

CVE-2024-41713			"A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A successful exploit could allow unauthorized access, enabling the attacker to view, corrupt, or delete users' data and system configurations."	hot
