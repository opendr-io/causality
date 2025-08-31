        
<table>
  <tr>
    <td><img src="/img/august.png" alt="things" height=4000 width=4000"></td>
    <td>
      <div style="font-size:32px; line-height:2;">
      CAUSALITY is an intrusion prediction model that is successfully predicting CVEs being watchlisted with early warning times as long as 137 days in order to actually shift "left of boom" and live our best lives. Every incident response we turn into incident avoidance gives time back to busy DevOPS teams while removing business risk. In calendar 2205 it has made 58 verifiable perdictions forward in time. 
        Contents:

2025: CVEs from calendar 2025 that have been rated. Starting with the August run, in that folder, there are two raing levels now, hot and warm. 

Hot CVEs have more potential to become something that blows up. Warms still have potential but they're less likely to become a major problem. Everything not in these files was rated cold by the model, meaning it has some non-zero potential, but probably won't be the ones that we hear about.

2024: CVEs from calendar 2024 that came out of the model rated 'hot.' 
BASC: A project presentation and accompanying notebook from the OWASP 2025 Boston Appication Security Conference. 
    </td>
  </tr>
</table>



### Updates:

Provable predictions so far (total 58) - provable meanining the prediction was publshed here some time - days or months - before the CVE went 'hot' meaning it was added to a watchlist of exploited vulns. I suspect that many of the 'hot' rated vulns are also being exploited but we have yet to observe or measure the activity.

August 25: CVEs 2024-8068 and 2024-8096 were added to the KEV. These were rated hot in the Jan 7 run which makes them the longest lead time so far at more than seven and one half months.

```CVE-2024-8068	Citrix	Citrix Session Recording	Privilege escalation to NetworkService Account accessÂ in Citrix Session Recording when an attacker is an authenticated user in the same Windows Active Directory domain as the session recording server domain```

```CVE-2024-8069	Citrix Session Recording	Citrix Session Recording	Limited remote code execution with privilege of a NetworkService Account accessÂ inÂ Citrix Session Recording if the attacker is an authenticated user on the same intranet as the session recording server```

August 19: Shadowserver Reported Expliotation of these CVEs rated hot earlier this year:

```CVE-2024-7029	hot	AVTech	AVM1203 (IP Camera)	Commands can be injected over the network and executed without authentication.	```

```CVE-2024-22024	hot	Ivanti	ICS	"An XML external entity or XXE vulnerability in the SAML component of Ivanti Connect Secure (9.x, 22.x), Ivanti Policy Secure (9.x, 22.x) and ZTA gateways which allows an attacker to access certain restricted resources without authentication."	```

```CVE-2024-5827	hot	vanna-ai	vanna-ai/vanna	"Vanna v0.3.4 is vulnerable to SQL injection in its DuckDB integration exposed to its Flask Web APIs. Attackers can inject malicious SQL training data and generate corresponding queries to write arbitrary files on the victim's file system, such as backdoor.php with contents `<?php system($_GET[0]); ?>`. This can lead to command execution or the creation of backdoors."	```

```CVE-2024-48307	hot			JeecgBoot v3.7.1 was discovered to contain a SQL injection vulnerability via the component /onlDragDatasetHead/getTotalData.```

```CVE-2024-6893	hot	Journyx	Journyx (jtime)	"The ""soap_cgi.pyc"" API handler allows the XML body of SOAP requests to contain references to external entities. This allows an unauthenticated attacker to read local files, perform server-side request forgery, and overwhelm the web server resources."	```

```CVE-2024-1561	hot	gradio-app	gradio-app/gradio	"An issue was discovered in gradio-app/gradio, where the `/component_server` endpoint improperly allows the invocation of any method on a `Component` class with attacker-controlled arguments. Specifically, by exploiting the `move_resource_to_block_cache()` method of the `Block` class, an attacker can copy any file on the filesystem to a temporary directory and subsequently retrieve it. This vulnerability enables unauthorized local file read access, posing a significant risk especially when the application is exposed to the internet via `launch(share=True)`, thereby allowing remote attackers to read files on the host machine. Furthermore, gradio apps hosted on `huggingface.co` are also affected, potentially leading to the exposure of sensitive information such as API keys and credentials stored in environment variables."		```

```CVE-2024-25852	hot			"Linksys RE7000 v2.0.9, v2.0.11, and v2.0.15 have a command execution vulnerability in the ""AccessControlList"" parameter of the access control function point. An attacker can use the vulnerability to obtain device administrator rights."	```e

```9832	CVE-2025-0674	Elber	Cleber/3 Broadcast Multi-Purpose Platform; ESE DVB-S/S2 Satellite Receiver; Reble610 M/ODU XPIC IP-ASI-SDH; Signum DVB-S/S2 IRD; Wayber Analog/Digital Audio STL	"Multiple Elber products are affected by an authentication bypass ```

```CVE-2024-8752	hot	Smart HMI	WebIQ	The Windows version of WebIQ 2.15.9 is affected by a directory traversal vulnerability that allows remote attackers to read any file on the system.	```

```CVE-2024-28255	hot	open-metadata	OpenMetadata	"OpenMetadata is a unified platform for discovery, observability, and governance powered by a central metadata repository, in-depth lineage, and seamless team collaboration. The `JwtFilter` handles the API authentication by requiring and verifying JWT tokens. When a new request comes in, the request's path is checked against this list. When the request's path contains any of the excluded endpoints the filter returns without validating the JWT. Unfortunately, an attacker may use Path Parameters to make any path contain any arbitrary strings. For example, a request to `GET /api/v1;v1%2fusers%2flogin/events/subscriptions/validation/condition/111` will match the excluded endpoint condition and therefore will be processed with no JWT validation allowing an attacker to bypass the authentication mechanism and reach any arbitrary endpoint, including the ones listed above that lead to arbitrary SpEL expression injection. This bypass will not work when the endpoint uses the `SecurityContext.getUserPrincipal()` since it will return `null` and will throw an NPE. This issue may lead to authentication bypass and has been addressed in version 1.2.4. Users are advised to upgrade. There are no known workarounds for this vulnerability. This issue is also tracked as `GHSL-2023-237`."	```

August 18: Shadowserver Reported Expliotation of these CVEs rated hot earlier this year:

```CVE-2024-38653	hot	Ivanti	Avalanche	XXE in SmartDeviceServer in Ivanti Avalanche 6.3.1 allows a remote unauthenticated attacker to read arbitrary files on the server.```

```CVE-2024-38289	hot			"A boolean-based SQL injection issue in the Virtual Meeting Password (VMP) endpoint in R-HUB TurboMeeting through 8.x allows unauthenticated remote attackers to extract hashed passwords from the database, and authenticate to the application, via crafted SQL input."```

```CVE-2024-31750	hot			SQL injection vulnerability in f-logic datacube3 v.1.0 allows a remote attacker to obtain sensitive information via the req_id parameter.```

```CVE-2024-34257	hot			"TOTOLINK EX1800T V9.1.0cu.2112_B20220316 has a vulnerability in the apcliEncrypType parameter that allows unauthorized execution of arbitrary commands, allowing an attacker to obtain device administrator privileges."```

```CVE-2024-29973	hot	Zyxel	NAS326 firmware	** UNSUPPORTED WHEN ASSIGNED **	"The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request."""```

```CVE-2024-54763	hot			An access control issue in the component /login/hostinfo.cgi of ipTIME A2004 v12.17.0 allows attackers to obtain sensitive information without authentication.```

```CVE-2024-54764	hot			An access control issue in the component /login/hostinfo2.cgi of ipTIME A2004 v12.17.0 allows attackers to obtain sensitive information without authentication.```

```CVE-2024-50334	hot	Erudika	scoold	"Scoold is a Q&A and a knowledge sharing platform for teams. A semicolon path injection vulnerability was found on the /api;/config endpoint. By appending a semicolon in the URL, attackers can bypass authentication and gain unauthorised access to sensitive configuration data. Furthermore, PUT requests on the /api;/config endpoint while setting the Content-Type: application/hocon header allow unauthenticated attackers to file reading via HOCON file inclusion. This allows attackers to retrieve sensitive information such as configuration files from the server, which can be leveraged for further exploitation. The vulnerability has been fixed in Scoold 1.64.0. A workaround would be to disable the Scoold API with scoold.api_enabled = false."```

July 21: Shadowserver

```CVE-2024-34193	hot			"smanga 3.2.7 does not filter the file parameter at the PHP/get file flow.php interface, resulting in a path traversal vulnerability that can cause arbitrary file reading."```	

```10684	CVE-2025-28137			The TOTOLINK A810R V4.1.2cu.5182_B20201026 were found to contain a pre-auth remote command execution vulnerability in the setNoticeCfg function through the NoticeUrl parameter.	hot```

```10750	CVE-2025-28036			TOTOLINK A950RG V4.1.2cu.5161_B20200903 was found to contain a pre-auth remote command execution vulnerability in the setNoticeCfg function through the NoticeUrl parameter.	hot```

```CVE-2024-51211	hot			"SQL injection vulnerability exists in OS4ED openSIS-Classic Version 9.1, specifically in the resetuserinfo.php file. The vulnerability is due to improper input validation of the $username_stn_id parameter, which can be manipulated by an attacker to inject arbitrary SQL commands."```

July 10: Shadowserver

```CVE-2024-7399	hot	Samsung Electronics	MagicINFO 9 Server	Improper limitation of a pathname to a restricted directory vulnerability in Samsung MagicINFO 9 Server version before 21.1050 allows attackers to write arbitrary file as system authority.```	


June 10: CVE-2025-24016 was added to the KEV. It was rated hot in the Feb 15 run, almost four months ago.
```CVE-2025-24016	wazuh	wazuh	"Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix."	hot```

June 9: CVE-2025-32433 was added to the KEV. It was rated hot in the May 8 run one month prior.
```CVE-2025-32433	erlang	otp	"Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules."	hot```

May 19: CVE-2024-11182 was added to the KEV. It was rated hot in the Jan 7 run which is the longest lead time yet at 135 days.

```CVE-2024-11182	hot	MDaemon	Email Server	An XSS issue was discovered in MDaemon Email Server before version 24.5.1c. An attacker can send an HTML e-mail message with JavaScript in an img tag. This could allow a remote attacker to load arbitrary JavaScript code in the context of a webmail user's browser window.```

May 13: Today's five MS CVEs reserved in March and released today are rated HOT!! https://github.com/cyberdyne-ventures/predictions/blob/main/2025/may-13-o4.txt

May 7: CVE-2024-6047 was added to the KEV. It was rated hot in the Jan 3 run, a lead time opf almost four months.
```1710	CVE-2024-6047	GeoVision	GV_DSP_LPR_V2	** UNSUPPPORTED WHEN ASSIGNED ** Certain EOL GeoVision devices fail to properly filter user input for the specific functionality. Unauthenticated remote attackers can exploit this vulnerability to inject and execute arbitrary system commands on the device.	neutral	hot```

May 7: 2024-11120 was added to the KEV. It was rated hot in the Jan 3 run, a lead time of almost four months.
```CVE-2024-11120	hot	GeoVision	GV-VS12	"Certain EOL GeoVision devices have an OS Command Injection vulnerability. Unauthenticated remote attackers can exploit this vulnerability to inject and execute arbitrary system commands on the device. Moreover, this vulnerability has already been exploited by attackers, and we have received related reports."	```

May 1: 2024-38475 was added to the KEV. It was rated hot on the Jan 3 run, a lead time just shy of four months.
```CVE-2024-38475	Apache Software Foundation	Apache HTTP Server	Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that areÂ permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure.```

April 9: Two Linux CVEs were added to the KEV, 2024-53150 and 2024-53197.
Both were rated hot in the January 7 run which is the longest lead time yet at 92 days.

March 31: CVE-2024-20439 was added to the KEV. It was was rated hot in the January 3 run which is the longest lead time yet at 87 days.
```CVE-2024-20439	Cisco	Cisco Smart License Utility	"A vulnerability in Cisco Smart Licensing Utility could allow an unauthenticated, remote attacker to log in to an affected system by using a static administrative credential.```


March 18: CVE-2025-24472  was added to the KEV. It was rated hot in the Feb 15 run, another 31 day lead time.
```CVE-2025-24472	Fortinet	FortiOS	"An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS 7.0.0 through 7.0.16 and FortiProxy 7.2.0 through 7.2.12, 7.0.0 through 7.0.19 may allow a remote attacker to gain super-admin privileges via crafted CSF proxy requests."	hot```

March 10: CVE-2025-25151 was added to the KEV. It was rated hot in the Feb 15 run. (23)

```CVE-2025-25181	Advantive	VeraCore	A SQL injection vulnerability in timeoutWarning.asp in Advantive VeraCore through 2025.1.0 allows remote attackers to execute arbitrary SQL commands via the PmSess1 parameter.	hot```

March 10: CVE-2024-13159 was added to the KEV. It was rated hot in the Jan 17 run.

```CVE-2024-13159	hot	Ivanti	Endpoint Manager	Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.```

March 10: CVE-2024-13160 was added to the KEV. It was rated hot in the Jan 17 run.

```CVE-2024-13160	hot	Ivanti	Endpoint Manager	Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.```

March 10: 	CVE-2024-13151 was added to the KEV. It was rated hot in the Jan 17 run.

```CVE-2024-13161	hot	Ivanti	Endpoint Manager Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.```

March 4: CVE-2024-50302 was added to the KEV. It was rated hot in the Jan 7 run.

```CVE-2024-50302 In the Linux kernel, the following vulnerability has been resolved: HID: core: zero-initialize the report buffer. Since the report buffer is used by all kinds of drivers in various ways, let's zero-initialize it during allocation to make sure that it can't be ever used to leak kernel memory via specially-crafted report.```

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
