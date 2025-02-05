![things](/img/precrime.gif?raw=true "text")  
## Intrusion Prediction

A repo for publishing the output of an experimental intrusion prediction project. Output is posted here where it is timestamped so that any correct predictions can be verified in linear time without creating a causality loop.  A rating of 'hot' means the CVE will land on one or more watchlists due to significance, exploitation and / or impact.

Contents:

2024: CVEs from calendar 2024 that came out of the model rated 'hot.' 

2025: CVEs from calendar 2025 that came out of the model rated 'hot.'

The 2024 set has not been through search space reduction yet but it will be soon. Predictions will be output here for 2025 CVEs at least monthly, maybe weekly, as the year goes on.

Predictions so far:

**NEW: CVE 2024-53104 was added to the KEV today. This one was predicted to go hot by the model in the Jan 3 run which is the longest lead time so far at 32 days!**
https://github.com/cyberdyne-ventures/predictions/blob/main/2024/2024-predictions.txt

```17109	CVE-2024-53104	Linux	Linux	"In the Linux kernel, the following vulnerability has been resolved:```
```media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format```
```This can lead to out of bounds writes since frames of this type were not taken into account when calculating the size of the frames buffer in uvc_parse_streaming."	neutral	hot```

**NEW: CVE 2024-29059 was added to the KEV on Feb 4. It was predicted hot in the Jan 17 run of the 2024 CVEs, 18 days ago. It should have been in the Jan 3 output but a few of the 2024 CVEs were not in the dataframe then.**

CVE-2024-29059	hot	Microsoft	Microsoft .NET Framework 4.8	.NET Framework Information Disclosure Vulnerability	

NEW: CVE-2024-12686 was added to the KEV on January 13. It was classified 'hot' by my model on January 3 - ten days prior to the KEV addition - in this output file which was committed to Github on that day (https://github.com/cyberdyne-ventures/predictions/blob/main/2024/2024-predictions.txt) Commit history: https://github.com/cyberdyne-ventures/predictions/compare/ca99f27cd91bc6251ffd5c22aa1b18f1dab0d214...40cc5c07883f41762139050820d40ebe787dce4c
```18609	CVE-2024-12686	BeyondTrust	Remote Support(RS) & Privileged Remote Access(PRA)	A vulnerability has been discovered in Privileged Remote Access (PRA) and Remote Support (RS) which can allow an attacker with existing administrative privileges to inject commands and run as a site user.	neutral	hot```

These predictions were made by the January 3 run, around three weeks ahead of being added to the other KEV (not CISA, the *other* KEV.)

Jan22 	CVE-2024-6205	Unknown	PayPlus Payment Gateway	"The PayPlus Payment Gateway WordPress plugin before 6.6.9 does not properly sanitise and escape a parameter before using it in a SQL statement via a WooCommerce API route available to unauthenticated users, leading to an SQL injection vulnerability."	hot

Jan22	CVE-2024-32735	CyberPower	CyberPower PowerPanel Enterprise	"An issue regarding missing authentication for certain utilities exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can access the PDNU REST APIs, which may result in compromise of the application."	neutral	hot

Jan22	CVE-2024-32737	CyberPower	CyberPower PowerPanel Enterprise	"A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can leak sensitive information via the ""query_contract_result"" function within MCUDBHelper.
"	neutral	hot

Jan22	CVE-2024-32738	CyberPower	CyberPower PowerPanel Enterprise	"A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can leak sensitive information via the ""query_ptask_lean"" function within MCUDBHelper.
"	neutral	hot

Jan22	CVE-2024-32736	CyberPower	CyberPower PowerPanel Enterprise	"A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can leak sensitive information via the ""query_utask_verbose"" function within MCUDBHelper.
"	neutral	hot

Jan22	CVE-2024-32739	CyberPower	CyberPower PowerPanel Enterprise	"A sql injection vulnerability exists in CyberPower PowerPanel Enterprise prior to v2.8.3.Â An unauthenticated remote attacker can leak sensitive information via the ""query_ptask_verbose"" function within MCUDBHelper.
"	neutral	hot

**Rated hot January 3, mentioned in VulnVerse Jan 5: (https://www.linkedin.com/pulse/security-week-review-vulnverse-23-marko-%25C5%25BEivanovi%25C4%2587-4sstf/)
CVE-2024-12856	Four-Faith	F3x24	The Four-Faith router models F3x24 and F3x36 are affected by an operating system (OS) command injection vulnerability.**

Rated hot & added to the KEV Jan 8:

CVE-2025-0282	Ivanti	Connect Secure	"A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution."	hot

Rated hot & added to the KEV Jan 7:

CVE-2024-55550			"Mitel MiCollab through 9.8 SP2 could allow an authenticated attacker with administrative privilege to conduct a local file read, due to insufficient input sanitization. A successful exploit could allow the authenticated admin attacker to access resources that are constrained to the admin access level, and the disclosure is limited to non-sensitive system information. This vulnerability does not allow file modification or privilege escalation."	hot

CVE-2024-41713			"A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A successful exploit could allow unauthorized access, enabling the attacker to view, corrupt, or delete users' data and system configurations."	hot
