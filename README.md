# Z-Hound — Reforged

> **Single-file, browser-based Active Directory attack graph tool for SharpHound collection data.**  
> No server. No install. No Neo4j. Upload a ZIP, get an interactive attack graph.

Built by [zrnge](https://www.github.com/zrnge)

---

## What is it?

Z-Hound is a single HTML file that parses SharpHound ZIPs and renders an interactive attack graph of an Active Directory environment. Everything runs in your browser — no data ever leaves your machine.

Built for pentesters, red teamers, and defenders who need fast, offline AD analysis without spinning up a database.

---

![screen1](https://github.com/zrnge/Z-Hound/blob/main/Screens/zhound1.png)

## Features

### Data Ingestion
- Upload a **SharpHound ZIP** (all JSON files processed automatically) or individual JSON files
- Supports SharpHound **v3 / v4 / v5** output formats
- Handles both `{Results: [...]}` and direct-array session formats across SharpHound versions
- Parses `Sessions`, `PrivilegedSessions`, and `RegistrySessions`
- Resolves SIDs and GUIDs from both `Properties.objectsid` and `item.ObjectIdentifier`
- Auto-synthesises well-known built-in domain groups (Domain Admins, Domain Controllers, Enterprise Admins, Schema Admins, etc.) that SharpHound does not explicitly collect

### Graph Visualisation
- Interactive graph powered by [Cytoscape.js](https://cytoscape.js.org/)
- Five layout modes: **Concentric** (default), Hierarchical (Dagre), Breadth-First, Force-Directed, Grid
- Node type colour coding: Users, Groups, Computers, Domains, OUs, GPOs, Cert Templates
- Node size and border glow scale with **risk score** — the most dangerous objects stand out instantly
- DCSync-capable principals render in red with a `DCSYNC` badge
- Click any node to focus and reveal its neighbourhood
- Box-select, zoom, pan fully supported
- Export PNG at 2× resolution; Export full edge list as CSV

![screen2](https://github.com/zrnge/Z-Hound/blob/main/Screens/zhound2.png)

### Filters & Quick Views
- Toggle: Hide Orphans, Structure edges (MemberOf/Contains/GPLink), ACL edges, Exec/Admin edges
- Quick View filter per edge category: High-Risk ACLs, Privilege/Exec, Delegation, ADCS, Vulnerable Attributes
- Short / Full / Type-only label modes; SID overlay toggle
- "Fit View" and "Clear Highlight" controls

### Attack Path Analysis
- **Find DA Path** — BFS shortest path from any selected node to Domain Admins
- **All Paths** — enumerate every User → DA path in the dataset, sorted by hop count (Critical ≤2, High ≤4, Medium 5+)
- Click any path row in the Paths panel to highlight it on the graph

### Risk Scoring
Every node is scored **0–100** automatically:

| Flag | Score Impact |
|---|---|
| DCSync capability | +95 |
| Unconstrained Delegation | +60 |
| AS-REP Roastable | +45 |
| Kerberoastable (SPN) | +40 |
| SID History present | +35 |
| Password Never Expires | +20 |
| AdminCount = 1 | +15 |
| Account Disabled | −40 |

### Risk Detection
- **DCSync** — `GetChanges` + `GetChangesAll` or `AllExtendedRights` on the domain object
- **Kerberoastable** — `hasspn = true`, account enabled
- **AS-REP Roastable** — `dontreqpreauth = true`
- **Unconstrained Delegation** — computers with unrestricted delegation
- **Critical ACLs** — `GenericAll`, `WriteDacl`, `WriteOwner`, `Owns`, `AllExtendedRights` on high-value targets
- **SID History** abuse paths

### Node Details Panel (BloodHound-style)

**Computer nodes:**
- Local Admins (Explicit / Unrolled / Foreign)
- Inbound Execution Rights — RDP / DCOM (direct and group-delegated)
- SQL Admins
- Active Sessions *(clickable — shows session paths in Paths panel)*

**User nodes:**
- Sessions logons observed *(clickable — shows which computers)*
- Sibling objects in same OU
- Reachable High Value Targets *(clickable)*
- Effective Inbound GPOs
- Outbound Object Control (first-degree and group-delegated)
- Inbound Control Rights (explicit and unrolled)
- Kerberoastable / AS-REP Roastable / Unconstrained Delegation / SID History flags

**Group nodes:**
- Sessions of group members *(clickable)*
- Reachable High Value Targets *(clickable)*
- Direct / Transitive / Foreign members *(clickable)*
- Execution Rights (RDP / DCOM — direct and group-delegated)
- Outbound Object Control
- Inbound Control Rights

**OU nodes:**
- Direct and inherited Affecting GPOs
- Contained users, computers, groups, child OUs *(all clickable)*

**Domain nodes:**
- Trusts, DCSync-capable principals *(clickable)*
- Cert Templates and ADCS exposure

### Stats Bar
Live metrics shown on data load:
```
Objects | Edges | Kerberoastable | AS-REP | DCSync Risk | Critical ACLs | Unconstrained Deleg | Cert Templates | Paths to DA
```

---

## Usage

1. **Open** `Z-Hound.html` in any modern browser (Chrome, Firefox, Edge)
2. **Click** `Upload ZIP / JSON` and select your SharpHound collection (ZIP recommended)
3. **Explore** — the graph renders automatically
4. **Click a node** to inspect its properties, risk flags, and BloodHound-style stats
5. **Search** for a user/computer and hit **Find DA Path** to trace the shortest attack path
6. **Hit All Paths** to enumerate every route to Domain Admins
7. **Use Quick Views** to isolate specific attack vectors (ACLs, Delegation, ADCS…)
8. **Export PNG / CSV** when done

> No data is ever sent to any server. All processing happens entirely in your browser.

---

## Edge Types Recognized

| Category | Edge Labels |
|---|---|
| Membership / Structure | MemberOf, Contains, GPLink |
| ACL | GenericAll, WriteDacl, WriteOwner, Owns, ForceChangePassword, AddMember, AddKeyCredentialLink, ReadLAPSPassword, AllExtendedRights, GenericWrite, WriteProperty, AddSelf, WriteAccountRestrictions |
| Execution | AdminTo, CanRDP, ExecuteDCOM, CanPSRemote, SQLAdmin, HasSession, CanAbuseGPO |
| Delegation | AllowedToDelegate, AllowedToAct |
| DCSync | GetChanges, GetChangesAll |
| ADCS | Enroll, ManageCA, ManageCertificates |
| Trust | TrustedBy |

Unknown edge types are caught automatically and added to Quick Views.

---

## Supported SharpHound File Types

| File pattern | Content |
|---|---|
| `*computers*.json` | Computer objects, sessions, local admins |
| `*users*.json` | User objects, SPNs, properties |
| `*groups*.json` | Group memberships |
| `*domains*.json` | Domain trusts, ACLs |
| `*ous*.json` | Organisational unit structure, GPLinks |
| `*gpos*.json` | Group Policy Objects |
| `*containers*.json` | Container objects |
| `*certtemplates*.json` / `*cas*.json` | ADCS certificate templates |

---

## Tech Stack

| Library | Version | Purpose |
|---|---|---|
| [Cytoscape.js](https://cytoscape.js.org/) | 3.28.1 | Graph rendering |
| [cytoscape-dagre](https://github.com/cytoscape/cytoscape.js-dagre) | 2.5.0 | Hierarchical layout |
| [dagre](https://github.com/dagrejs/dagre) | 0.8.5 | Layout engine |
| [JSZip](https://stuk.github.io/jszip/) | 3.10.1 | Client-side ZIP extraction |
| [Tailwind CSS](https://tailwindcss.com/) | CDN | Styling |

Single HTML file — no build step, no backend, no framework.

---

## Requirements

- A modern browser (Chrome 90+, Firefox 88+, Edge 90+)
- Internet connection on first load (CDN scripts loaded once, then cached)
- SharpHound collection output — ZIP or individual JSON files

---

## Known Limitations

- Large datasets (>50k edges) may slow the browser — use Quick View filters to scope the graph
- Foreign domain objects may appear as unresolved SIDs if their JSON files are not included in the upload
- Deleted or non-collected accounts remain as SID-only ghost nodes with an advisory notice

---

## Disclaimer

Z-Hound is intended for **authorized security assessments, penetration testing, and defensive security work only**. Only use it against environments you have explicit written permission to test.

---

## License

MIT
