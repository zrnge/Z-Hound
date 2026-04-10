# Z-Hound — Reforged

[![Live Demo](https://img.shields.io/badge/Live_Demo-zrnge.github.io%2FZ--Hound-0ea5e9?style=for-the-badge&logo=github&logoColor=white)](https://zrnge.github.io/Z-Hound/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/zrnge/Z-Hound?style=for-the-badge&logo=github&color=fbbf24)](https://github.com/zrnge/Z-Hound/stargazers)
[![Single File](https://img.shields.io/badge/Single_File-HTML-e34c26?style=for-the-badge&logo=html5&logoColor=white)](index.html)
[![No Install](https://img.shields.io/badge/No_Install-Required-22c55e?style=for-the-badge&logo=checkmarx&logoColor=white)](https://zrnge.github.io/Z-Hound/)
[![Offline Ready](https://img.shields.io/badge/Offline-Ready-8b5cf6?style=for-the-badge&logo=googlechrome&logoColor=white)](index.html)
[![SharpHound](https://img.shields.io/badge/SharpHound-v3%20%7C%20v4%20%7C%20v5-c0392b?style=for-the-badge)](https://github.com/BloodHoundAD/SharpHound)
[![AzureHound](https://img.shields.io/badge/AzureHound-Supported-0078d4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://github.com/BloodHoundAD/AzureHound)

> **Single-file, browser-based Active Directory attack graph tool for SharpHound and AzureHound collection data.**  
> No server. No install. No Neo4j. Upload a ZIP, get an interactive attack graph.

Built by [zrnge](https://www.github.com/zrnge)

---

## Try It Now

**Use it online — no download required:**  
**[https://zrnge.github.io/Z-Hound/](https://zrnge.github.io/Z-Hound/)**

Or download `index.html` and open it locally for fully offline use. All processing happens in the browser — no data ever leaves your machine either way.

---

## What is it?

Z-Hound is a single HTML file that parses SharpHound and AzureHound ZIPs and renders an interactive attack graph of an Active Directory / Azure environment. It replaces the need to spin up Neo4j and BloodHound for quick triage, portable assessments, and client-site work where you cannot install tooling.

Built for pentesters, red teamers, and defenders who need fast, offline AD analysis with zero infrastructure.

---

## Quick Start

| Option | Steps |
|---|---|
| **Online** | Go to [zrnge.github.io/Z-Hound](https://zrnge.github.io/Z-Hound/) → click **Upload ZIP / JSON** → select your SharpHound output |
| **Offline** | Download `index.html` → open in browser → click **Upload ZIP / JSON** → select your SharpHound output |

> After the CDN scripts load once (Cytoscape.js, JSZip, Tailwind), the page works fully offline on subsequent opens.

---

## Features

### Data Ingestion
- Upload a **SharpHound ZIP** (all JSON files processed automatically) or individual JSON files
- Upload **AzureHound ZIP** for full Azure / Entra ID analysis
- Supports SharpHound **v3 / v4 / v5** output formats and BloodHound CE graph exports
- Parses `Sessions`, `PrivilegedSessions`, and `RegistrySessions`
- Resolves SIDs and GUIDs from both `Properties.objectsid` and `item.ObjectIdentifier`
- Auto-synthesises well-known built-in domain groups that SharpHound does not explicitly collect
- 500 MB uncompressed / 100,000 node limit per session

### Graph Visualisation
- Interactive graph powered by [Cytoscape.js](https://cytoscape.js.org/)
- Five layout modes: **Concentric** (default), Hierarchical (Dagre), Breadth-First, Force-Directed, Grid
- Node colour and shape coding by type: Users, Groups, Computers, Domains, OUs, GPOs, Cert Templates, and all Azure object types
- Node size and border glow scale with **risk score** — the most dangerous objects stand out instantly
- DCSync-capable principals render in red; high-value targets in gold
- Click any node to focus and reveal its neighbourhood
- Box-select, zoom (0.02×–12×), full pan support
- Short / Full / Type-only label modes; SID overlay toggle

### Filters & Quick Views
- Toggle: Hide Orphans, Structure edges, ACL edges, Exec/Admin edges
- **Quick View dropdown** with auto-built categories:
  - Special Analysis: DCSync Principals, High Value Targets + Paths
  - **NTLM Relay**: SMB Relay Targets, WebClient Hosts, Coerce → Relay Chains *(appears automatically when signing/webclient props are present)*
  - High-Risk ACLs, Privilege & Exec, Delegation & Trust, ADCS, GPO
  - Vulnerable Attributes (Kerberoastable, AS-REP, Unconstrained Delegation, etc.)
  - **Azure / Entra ID** group *(appears automatically when AzureHound data is loaded)*
  - Dynamic "Other Edges" group for unknown edge types

### Attack Path Analysis

#### Pre-built Quick Queries (Paths tab)
| Button | What it finds |
|---|---|
| Kerberoastable | All Kerberoastable users → shortest path to DA |
| AS-REP | AS-REP Roastable accounts → DA |
| Unconstrained Deleg | Computers with unconstrained delegation → DA |
| Constrained Deleg | Constrained delegation targets |
| RBCD | WriteAccountRestrictions / AddAllowedToAct on computers |
| Shadow Cred | AddKeyCredentialLink edges |
| LAPS | ReadLAPSPassword edges |
| GMSA | ReadGMSAPassword edges |
| DCSync | All DCSync-capable principals |
| Writable ACLs | GenericAll / WriteDacl / WriteOwner / GenericWrite |
| Forest Trusts | Cross-forest trust edges and cross-domain DA paths |
| ADCS ESC | ESC1–ESC6 certificate template vulnerabilities |
| **Azure GA** | Azure Global Admin / Privileged Role Admin holders + on-prem → Azure GA hybrid paths |
| **Relay Targets** | SMB signing-disabled computers → DA paths |
| **WebClient** | WebClient-running computers (HTTP coerce candidates) → DA paths |
| **⚡ Relay Chain** | Full coerce → NTLMRelay → target → DA chains |
| ☠ From Owned | Paths from all nodes marked as compromised |

#### Manual Path Finding
- **Find DA Path** — BFS shortest path from any searched node to Domain Admins
- **All Paths** — enumerate every User/Computer → DA path, sorted by hop count (Critical ≤2 hops, High ≤4, Medium 5+)
- Click any path row to highlight it on the graph in red

### Risk Scoring
Every node is scored **0–100** automatically:

| Flag | Score |
|---|---|
| DCSync capability | +95 |
| Admin / High Value | +50 |
| Unconstrained Delegation | +60 |
| Constrained Delegation | +30 |
| AS-REP Roastable | +45 |
| Kerberoastable (SPN) | +40 |
| SID History present | +35 |
| **WebClient Running** | +25 |
| **SMB Relay Target** | +30 |
| **SMBv1 Enabled** | +20 |
| Password Never Expires | +20 |
| AdminCount = 1 | +15 |
| Account Disabled | −40 |
| Deleted / Tombstoned | −50 |

### Risk Detection
- **DCSync** — `GetChanges` + `GetChangesAll` or `AllExtendedRights` on the domain object
- **Kerberoastable** — `hasspn = true`, account enabled
- **AS-REP Roastable** — `dontreqpreauth = true`
- **Unconstrained Delegation** — computers with unrestricted delegation
- **Critical ACLs** — `GenericAll`, `WriteDacl`, `WriteOwner`, `Owns`, `AllExtendedRights` on high-value targets
- **SID History** abuse paths
- **NTLM Relay Target** — `signing = false` or `signingrequired = false` on computer objects
- **WebClient Running** — `webclient = true` on computer objects (HTTP coerce surface)
- **SMBv1 Enabled** — `smb1enabled = true`

### NTLM Relay Path Analysis
When SharpHound collects SMB signing and WebClient properties:

- **Relay Targets** — computers where SMB signing is not required, visualised with `RELAY TARGET` badge in node details
- **WebClient Hosts** — computers with WebDAV WebClient service running, visualised with `WEBCLIENT` badge
- **Relay Chain synthesis** — constructs full `coerce → NTLMRelay → target → DA` paths including direct `AdminTo` relay chains
- Relay surface shown in Computer node details panel: SMB Signing, SMB Signing Required, SMBv1, WebClient status — all colour-coded
- `NTLMRelay` virtual edge type mapped to MITRE **T1557.001** (Adversary-in-the-Middle: SMB Relay)

### ADCS Vulnerability Detection
Automatic detection of ESC vulnerabilities from certificate template properties:

| ESC | Condition |
|---|---|
| ESC1 | Enrollee-supplied SAN + Client Auth EKU + no manager approval |
| ESC2 | Any Purpose EKU or empty EKU, no approval |
| ESC3 | Certificate Request Agent EKU |
| ESC4 | Write access to template (GenericWrite / WriteProperty / WriteDacl) |
| ESC6 | CA with `EDITF_ATTRIBUTESUBJECTALTNAME2` flag |

### Azure / Entra ID Support (Full)
Load AzureHound output alongside or separately for hybrid AD + Azure analysis.

**Parsed relationship types** (from AzureHound arrays):
`GlobalAdmins`, `PrivilegedRoleAdmins`, `Owners`, `Contributors`, `UserAccessAdmins`, `AddMembers`, `AddOwners`, `ResetPasswords`, `AddSecrets`, `GetSecretUsers`, `GetKeyUsers`, `GetCertificateUsers`, `VMAdmins`, `RunCommandAdmins`, `GrantAppRoles`, `AppRoleAssignments`, `InboundTransitiveRoles`

**Azure node types supported:**
`AZUser`, `AZGroup`, `AZDevice`, `AZApp`, `AZServicePrincipal`, `AZTenant`, `AZSubscription`, `AZResourceGroup`, `AZVM`, `AZKeyVault`, `AZMgmtGroup`

**Azure-specific features:**
- `AZTenant` marked as high value (Azure equivalent of Domain root)
- **Azure GA** quick query — surfaces Global Admin and Privileged Role Admin holders; finds on-prem → Azure GA hybrid attack paths
- Azure node details panel: Tenant ID, App ID, Object ID, SP Type, roles held/granted, inbound high-risk permissions (AZAddSecret, AZExecuteCommand, AZResetPassword, AZOwns)
- Azure section in Report panel: object inventory, GA list, Priv Role Admins, app secret access, VM execution, password resets
- Azure findings included in HTML report export

### Node Details Panel

**Computer nodes:**
- **NTLM Relay Surface** — SMB Signing, SMB Signing Required, SMBv1, WebClient status with colour-coded risk badges
- Local Admins (Explicit / Unrolled / Foreign)
- Inbound Execution Rights — RDP / DCOM (direct and group-delegated)
- SQL Admins
- Active Sessions *(clickable)*

**User nodes:**
- Sessions observed *(clickable)*
- Sibling objects in same OU
- Reachable High Value Targets *(clickable)*
- Effective Inbound GPOs
- Outbound / Inbound Object Control
- Risk flags: Kerberoastable, AS-REP Roastable, Unconstrained Delegation, SID History

**Group nodes:**
- Sessions of group members *(clickable)*
- Reachable High Value Targets *(clickable)*
- Direct / Transitive / Foreign members *(clickable)*
- Execution Rights (RDP / DCOM)
- Outbound / Inbound Object Control

**Azure nodes:**
- Tenant ID, App ID, Object ID, SP Type
- Roles held and roles granted to this object
- Inbound AZAddSecret / AZExecuteCommand / AZResetPassword / AZOwns counts
- Outbound high-risk permission count
- Reachable High Value Targets

**OU / GPO / Domain nodes:** Full BloodHound-style details including trusts, DCSync principals, effective GPOs, cert templates.

### Stats Bar
Live metrics on data load:
```
Objects | Edges | Kerberoastable | AS-REP | DCSync Risk | Critical ACLs | Unconstrained Deleg | Cert Templates | Relay Targets | WebClient | Paths to DA
```

### Export

| Format | Contents |
|---|---|
| **PNG** | Graph snapshot at 2× resolution |
| **CSV** | Three-section: Nodes (name, type, risk score, flags, SID, domain) + Edges (from, to, label, isACL, riskWeight, MITRE) + ADCS findings |
| **HTML** | Full self-contained assessment report — Executive Summary, Critical Findings, Credential Theft, Delegation, ADCS, NTLM Relay, Azure/Entra ID, Top High-Risk Nodes, Attack Paths. Light theme, printable, no external dependencies. |

---

## Edge Types Recognized (50+)

| Category | Edge Labels |
|---|---|
| Membership / Structure | MemberOf, Contains, GPLink |
| ACL | GenericAll, WriteDacl, WriteOwner, Owns, ForceChangePassword, AddMember, AddKeyCredentialLink, ReadLAPSPassword, AllExtendedRights, GenericWrite, WriteProperty, AddSelf, WriteAccountRestrictions, WriteSPN, ReadGMSAPassword, AddAllowedToAct, AddMembers |
| Execution | AdminTo, CanRDP, ExecuteDCOM, CanPSRemote, SQLAdmin, HasSession, CanAbuseGPO |
| Delegation | AllowedToDelegate, AllowedToAct, SPNTarget |
| DCSync | GetChanges, GetChangesAll |
| ADCS | Enroll, ManageCA, ManageCertificates, ADCSESC1–ADCSESC13 |
| Trust | TrustedBy |
| **NTLM Relay** | **NTLMRelay** (synthetic — T1557.001) |
| Azure | AZGlobalAdmin, AZPrivilegedRoleAdmin, AZOwns, AZContributor, AZAddMembers, AZAddOwner, AZAddSecret, AZGetSecrets, AZGetKeys, AZGetCertificates, AZExecuteCommand, AZVMAdminLogin, AZVMContributor, AZResetPassword, AZUserAccessAdmin, AZGrantAppRoles, AZHasRole, AZMGAddMember, AZMGAddOwner, AZMGAddSecret, AZMGGrantAppRoles, AZMGGrantRole |
| Misc | SyncLAPSPassword, WriteGPLink, CoerceToTGT, SyncedToEntraUser, HostsCAService |

Unknown edge types are caught automatically and added to Quick Views.

---

## Supported Input Files

| File pattern | Content |
|---|---|
| `*computers*.json` | Computer objects, sessions, local admins, SMB properties |
| `*users*.json` | User objects, SPNs, properties |
| `*groups*.json` | Group memberships |
| `*domains*.json` | Domain trusts, ACLs |
| `*ous*.json` | Organisational unit structure, GPLinks |
| `*gpos*.json` | Group Policy Objects |
| `*containers*.json` | Container objects |
| `*certtemplates*.json` / `*cas*.json` | ADCS certificate templates |
| AzureHound `Az_*.json` | Azure / Entra ID objects and relationships |

---

## Tech Stack

| Library | Version | Purpose |
|---|---|---|
| [Cytoscape.js](https://cytoscape.js.org/) | 3.28.1 | Graph rendering |
| [cytoscape-dagre](https://github.com/cytoscape/cytoscape.js-dagre) | 2.5.0 | Hierarchical layout |
| [dagre](https://github.com/dagrejs/dagre) | 0.8.5 | Layout engine |
| [JSZip](https://stuk.github.io/jszip/) | 3.10.1 | Client-side ZIP extraction |
| [Tailwind CSS](https://tailwindcss.com/) | CDN | Styling |

Single HTML file — no build step, no backend, no framework, no install.

---

## Requirements

- A modern browser (Chrome 90+, Firefox 88+, Edge 90+)
- Internet connection on first load only (CDN scripts cached after that — full offline use thereafter)
- SharpHound collection output — ZIP or individual JSON files
- AzureHound output — ZIP (optional, for Azure analysis)

---

## vs. BloodHound / PlumHound

| | Z-Hound | BloodHound CE | PlumHound |
|---|---|---|---|
| Zero install | ✅ | ❌ | ❌ |
| Offline / air-gapped | ✅ | Partial | ❌ |
| Interactive graph | ✅ | ✅ | ❌ |
| HTML report export | ✅ | ❌ | ✅ |
| Risk scoring (0–100) | ✅ | ❌ | Partial |
| NTLM relay paths | ✅ | ❌ | ❌ |
| ADCS ESC detection | ✅ | Partial | Partial |
| MITRE ATT&CK on edges | ✅ | ❌ | ❌ |
| Azure / Entra ID | ✅ Full | ✅ | Partial |
| Persistent data store | ❌ | ✅ (Neo4j) | ✅ |
| Custom Cypher queries | ❌ | ✅ | ✅ |
| Multi-million object scale | ❌ | ✅ | ✅ |

---

## Known Limitations

- Datasets with >50 k edges may slow the browser — use Quick View filters to scope the graph down
- No session persistence — page reload requires re-uploading the collection
- NTLM relay features require SharpHound to have collected `signing`, `signingrequired`, and `webclient` properties (available in extended / BloodHound CE collections); standard collections will not show relay data
- Foreign domain objects may appear as unresolved SIDs if their JSON files are not included in the upload

---

## Disclaimer

Z-Hound is intended for **authorized security assessments, penetration testing, and defensive security work only**. Only use it against environments you have explicit written permission to test.

---

## License

MIT
