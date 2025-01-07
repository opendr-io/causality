![things](/img/precrime.gif?raw=true "text")  
## Intrusion Prediction

A repo for publishing the output of an experimental intrusion prediction project. Output is posted here where it is timestamped so that any correct predictions can be verified in linear time without creating a causality loop.  A rating of 'hot' means the CVE will land on one or more watchlists due to significance, exploitation and / or impact.

Contents:

2024: The first batch with CVEs for 2024 that came out of the model rated 'hot.' This set has not been through search space reduction yet but it will be soon. Predictions will be output here for 2025 CVEs at least monthly, maybe weekly, as the year goes on.

Predictions so far:

Rated hot January 3, mentioned in VulnVerse Jan 5: (https://www.linkedin.com/pulse/security-week-review-vulnverse-23-marko-%25C5%25BEivanovi%25C4%2587-4sstf/)
CVE-2024-12856	Four-Faith	F3x24	The Four-Faith router models F3x24 and F3x36 are affected by an operating system (OS) command injection vulnerability.

Rated hot & added to the KEV Jan 7 (I can't prove the time sequence here because these were not in the Jan 3 run, a bunch of 2024 CVEs were not in that run due to error. But the prediction is valid b/c it used data prior to 2024 and they were rated hot:)

CVE-2024-55550			"Mitel MiCollab through 9.8 SP2 could allow an authenticated attacker with administrative privilege to conduct a local file read, due to insufficient input sanitization. A successful exploit could allow the authenticated admin attacker to access resources that are constrained to the admin access level, and the disclosure is limited to non-sensitive system information. This vulnerability does not allow file modification or privilege escalation."	hot

CVE-2024-41713			"A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A successful exploit could allow unauthorized access, enabling the attacker to view, corrupt, or delete users' data and system configurations."	hot
