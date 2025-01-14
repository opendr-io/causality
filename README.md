![things](/img/precrime.gif?raw=true "text")  
## Intrusion Prediction

A repo for publishing the output of an experimental intrusion prediction project. Output is posted here where it is timestamped so that any correct predictions can be verified in linear time without creating a causality loop.  A rating of 'hot' means the CVE will land on one or more watchlists due to significance, exploitation and / or impact.

Contents:

2024: CVEs from calendar 2024 that came out of the model rated 'hot.' 

2025: CVEs from calendar 2025 that came out of the model rated 'hot.'

The 2024 set has not been through search space reduction yet but it will be soon. Predictions will be output here for 2025 CVEs at least monthly, maybe weekly, as the year goes on.

Predictions so far:

NEW: CVE-2024-12686 was added to the KEV on January 13. It was classified 'hot' by my model on January 7 - seven days prior to the KEV addition - in this output file which was committed to Github on that day (https://github.com/cyberdyne-ventures/predictions/blob/main/2024/predictions-jan-7-run.txt)

CVE-2024-12686	BeyondTrust	Remote Support(RS) & Privileged Remote Access(PRA)	A vulnerability has been discovered in Privileged Remote Access (PRA) and Remote Support (RS) which can allow an attacker with existing administrative privileges to inject commands and run as a site user.	hot

Rated hot January 3, mentioned in VulnVerse Jan 5: (https://www.linkedin.com/pulse/security-week-review-vulnverse-23-marko-%25C5%25BEivanovi%25C4%2587-4sstf/)
CVE-2024-12856	Four-Faith	F3x24	The Four-Faith router models F3x24 and F3x36 are affected by an operating system (OS) command injection vulnerability.

Rated hot & added to the KEV Jan 8:

CVE-2025-0282	Ivanti	Connect Secure	"A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution."	hot

Rated hot & added to the KEV Jan 7:

CVE-2024-55550			"Mitel MiCollab through 9.8 SP2 could allow an authenticated attacker with administrative privilege to conduct a local file read, due to insufficient input sanitization. A successful exploit could allow the authenticated admin attacker to access resources that are constrained to the admin access level, and the disclosure is limited to non-sensitive system information. This vulnerability does not allow file modification or privilege escalation."	hot

CVE-2024-41713			"A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A successful exploit could allow unauthorized access, enabling the attacker to view, corrupt, or delete users' data and system configurations."	hot
