# Z-Hound — Reforged

> **Client-side Active Directory attack path visualizer for SharpHound / BloodHound data.**
> No server. No install. Drop in a ZIP, get an interactive graph.

![Z-Hound Screenshot](https://raw.githubusercontent.com/zrnge/Z-Hound/refs/heads/main/Z-Hound.png)

---

## What is it?

Z-Hound is a single-file web app that parses SharpHound collection ZIPs and renders an interactive attack graph of your Active Directory environment. It runs entirely in your browser — nothing leaves your machine.

Built for pentesters, red teamers, and defenders who need fast, offline AD analysis without spinning up a Neo4j instance.

---

## Features

### Graph Engine
- Powered by **Cytoscape.js** with Dagre, Force-Directed, Breadth-First, Concentric, and Grid layouts
- Node size and border scale with **risk score** — the most dangerous objects stand out instantly
- Node shapes by type: users `●`, computers `■`, domains `◆`, GPO/OU `⬡`, certs `★`
- Pan, zoom, box-select, click-to-inspect
- **Export PNG** — full graph at 2× resolution, dark background

### Risk Scoring Engine
Every node is scored **0–100** automatically based on:

| Flag | Score Impact |
|---|---|
| Unconstrained Delegation | +60 |
| DCSync capability | +95 |
| AS-REP Roastable | +45 |
| Kerberoastable (SPN) | +40 |
| SID History present | +35 |
| AdminCount = 1 | +15 |
| Password Never Expires | +20 |
| Account Disabled | −40 |

### Attack Path Finding
- **Find DA Path** — BFS shortest path from any object to Domain Admins
- **All Paths** — enumerates every User → DA path in the dataset, sorted by hop count (Critical ≤2, High ≤4, Medium 5+)
- Click any path in the panel to highlight it on the graph
- Paths panel shows source → destination with hop count badge

### DCSync Auto-Detection
Automatically identifies principals that can perform a DCSync attack:
- `GetChanges` + `GetChangesAll` on a Domain object
- `AllExtendedRights` on a Domain object

Flagged nodes render in **red** with a `DCSYNC` badge.

### Node Details Panel
Click any node to see:
- Full properties: SID, DN, domain, enabled status, last logon, password last set, OS, email, description
- SPN list (Kerberoastable targets)
- SID History entries
- All incoming and outgoing edges with clickable neighbors
- Risk flags and score breakdown

### Risk Report Panel
Ranked attack surface overview:
- DCSync principals
- Critical ACLs (GenericAll / WriteDacl / WriteOwner)
- Kerberoastable accounts
- AS-REP Roastable accounts
- Unconstrained Delegation targets
- SID History accounts
- Top 25 highest-risk nodes

### Stats Bar
Live metrics on data load:

```
Objects | Edges | Kerberoastable | AS-REP | DCSync Risk | Critical ACLs | Paths to DA
```

### Quick Views
Dynamically generated from your data:

- **Special Analysis** — DCSync Principals, High Value Targets
- **High-Risk ACLs** — GenericAll, WriteDacl, WriteOwner, AddKeyCredentialLink, ForceChangePassword, ReadLAPSPassword…
- **Privilege & Exec** — AdminTo, CanRDP, ExecuteDCOM, CanPSRemote, SQLAdmin, GetChangesAll
- **Delegation & Trust** — AllowedToDelegate, AllowedToAct, TrustedBy
- **ADCS** — Enroll, ManageCA, ManageCertificates
- **Vulnerable Attributes** — Kerberoastable, AS-REP, Unconstrained Delegation, SID History, AdminCount…

---

## Supported Data Formats

| Format | Support |
|---|---|
| SharpHound ZIP (v2/v3) | ✅ Full |
| BloodHound v4/v5 JSON (`graph.nodes` / `graph.edges`) | ✅ Full |
| Raw BloodHound JSON files | ✅ Full |
| Multiple files at once | ✅ Drop multiple ZIPs/JSONs |

Parsed file types: `users`, `groups`, `computers`, `domains`, `gpos`, `ous`, `certtemplates`, `containers`

---

## Edge Types Recognized

| Category | Edges |
|---|---|
| Membership | MemberOf |
| ACL | GenericAll, WriteDacl, WriteOwner, Owns, ForceChangePassword, AddMember, AddKeyCredentialLink, ReadLAPSPassword, AllExtendedRights, GenericWrite, WriteProperty, AddSelf, WriteAccountRestrictions |
| Execution | AdminTo, CanRDP, ExecuteDCOM, CanPSRemote, SQLAdmin, HasSession, CanAbuseGPO |
| Delegation | AllowedToDelegate, AllowedToAct |
| DCSync | GetChanges, GetChangesAll |
| ADCS | Enroll, ManageCA, ManageCertificates |
| GPO | GPLink |
| Trust | TrustedBy |

Unknown/new edge types are caught automatically and added to Quick Views.

---

## Usage

1. **Open** `index.html` in any modern browser (Chrome, Firefox, Edge)
2. **Click** `Upload ZIP / JSON` and select your SharpHound collection
3. **Explore** — the graph renders automatically
4. **Click a node** to inspect its properties and risk flags
5. **Search** for a user and hit `Find DA Path` to trace the attack path
6. **Hit `All Paths`** to enumerate every route to Domain Admins
7. **Use Quick Views** to isolate specific attack vectors
8. **Export PNG** when done

> Nothing is sent to any server. All processing happens in your browser.

---

## Filters & Controls

| Control | Description |
|---|---|
| Hide Orphans | Remove nodes with no visible connections |
| MemberOf | Toggle group membership edges |
| ACLs | Toggle all ACL/permission edges |
| Exec/Admin | Toggle AdminTo, RDP, DCOM, PSRemote edges |
| Layout | Switch between 5 graph layout algorithms |
| Labels | Short name / Full name / Type only |
| Fit View | Reset zoom and pan to fit all nodes |
| Clear Highlight | Remove path highlights |

---

## Requirements

- A modern browser (Chrome 90+, Firefox 88+, Edge 90+)
- A SharpHound collection ZIP or BloodHound JSON export
- No internet connection required after first load (all libraries are CDN-loaded once)

---

## Tech Stack

| Library | Purpose |
|---|---|
| [Cytoscape.js](https://cytoscape.org/) | Graph rendering and interaction |
| [Cytoscape-Dagre](https://github.com/cytoscape/cytoscape.js-dagre) | Hierarchical layout engine |
| [JSZip](https://stuk.github.io/jszip/) | Client-side ZIP parsing |
| [Tailwind CSS](https://tailwindcss.com/) | UI styling |

---

## Disclaimer

Z-Hound is intended for **authorized security assessments, penetration testing, and defensive security work only**. Only use it against environments you have explicit written permission to test. The authors are not responsible for misuse.

---

## License

MIT
