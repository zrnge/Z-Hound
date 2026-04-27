# Z-Hound — M365 Defender ExposureGraphEdges Module

Adds Microsoft 365 Defender exposure-graph data as first-class graph objects inside Z-Hound, on the same canvas as SharpHound AD data.

---

## Files

| File | Purpose |
|---|---|
| `defender-module.js` | Main integration module |
| `defender-module.css` | Toast, drag-overlay, and focus-panel styles |

Both files sit in the repo root alongside `index.html`. The two lines already added to `index.html` load them:

```html
<!-- in <head>, after the dagre script tag -->
<link rel="stylesheet" href="defender-module.css">

<!-- just before </body> -->
<script src="defender-module.js"></script>
```

---

## KQL query to run in Microsoft 365 Defender Advanced Hunting

```kusto
ExposureGraphEdges
| where Timestamp > ago(7d)
| project SourceNodeName, SourceNodeLabel,
          EdgeLabel,
          TargetNodeName, TargetNodeLabel,
          EdgeProperties
| take 5000
```

Export as **CSV** from the Advanced Hunting results panel. The module accepts the exact column names the portal exports; no transformation needed.

---

## Loading Defender data into Z-Hound

Three supported input paths:

| Method | How |
|---|---|
| **File picker** | Click **📊 Defender CSV** button in the header |
| **Drag-and-drop** | Drop a `.csv` file anywhere onto the graph canvas |
| **Paste** | Copy the CSV text, click somewhere on the canvas (not in a text field), press **Ctrl+V** |

The module auto-detects a Defender CSV by sniffing the header row for `SourceNodeName`, `EdgeLabel`, and `TargetNodeName`. If those columns are absent it shows an error toast listing exactly which columns are missing.

---

## Hooks into Z-Hound (functions extended by name)

| Z-Hound function | What the module adds |
|---|---|
| `buildElements` | Tags Defender edges with `isDefender=true` in Cytoscape element data |
| `initCytoscape` | Applies dashed-blue style to Defender edges and two-tone border to merged nodes after each render |
| `computeStats` | Updates the **Exposure Edges** counter in the stats bar |
| `buildQuickViews` | Adds *CVE-Exposed Assets*, *Credential Exposure*, and *Role Assignments* quick-view options |
| `renderGraph` | Handles the three Defender quick-view values before delegating to the original; also short-circuits to focus-mode render when focus is active |
| `showNodeDetails` | Appends an **Exposure** section to the details pane for any node that has Defender edges |
| `exportCSV` | Replaces the CSV export when Defender data is present, adding a `Source` column (`sharphound` / `defender` / `sharphound+defender`) |
| `clearGraph` | Resets all Defender state (node set, adjacency maps, focus mode) alongside the SharpHound clear |

All hooks use the standard browser monkey-patch pattern: the module saves the original function, replaces the global binding, and calls the original inside the wrapper. No edits to Z-Hound's core logic are required.

---

## Feature summary

### Graph integration
- Defender nodes are added to `adNodes` using Z-Hound's existing type system. New types (`App`, `Role`, `CVE`, `AzureResource`, `DefenderNode`) are registered in `NODE_COLORS` and `NODE_SHAPES`.
- Nodes that match an existing SharpHound node by exact name (case-insensitive) are **merged** rather than duplicated. Merged nodes get a purple border in Cytoscape.
- Defender edges are added to `adEdges` and rendered with a **dashed blue stroke** so they are visually distinct from SharpHound edges without being garish.

### Defender Focus panel (Filter tab)
Handles large Defender exports (5 000+ edges) by rendering only one entity's neighborhood at a time:

- **Entity type selector** — populated from loaded data (User, Computer, CVE, …).
- **Sort**: Exposure degree (default) or Name A→Z.
- **Hops**: 1 Direct / 2 Transitive / 3 Deep.
- **Focus card**: name, type, outbound/inbound edge counts, Merged badge.
- **Navigation**: ⏮ ◀ [n / total] ▶ ⏭ — also responds to **PageDown / →** and **PageUp / ←** (Home / End to jump to first/last).
- Focused entity is pinned at canvas center with a larger dashed accent ring.
- SharpHound edges between visible neighbor nodes are included in the focus view for context.

### Attack-path integration
`bfsPath` already traverses `adEdges`, so Defender edges are automatically included in **Find DA Path**, **All Paths**, and all Quick Query results. A path can chain SharpHound edges (`AdminTo`, `GenericAll`, …) with Defender edges (`has credentials of`, `can authenticate as`, …) transparently.

### Exposure section in Details pane
Selecting any Defender-sourced or merged node appends an **Exposure** block below the standard details, showing outbound and inbound Defender edges with parsed `EdgeProperties` key/value pairs. Each edge target is clickable to navigate to that node.

### Search
Defender nodes appear in Z-Hound's existing search (name mode) immediately after loading, because they are stored in `adNodes`. New types are also added to the type-filter dropdown.

### Quick views added
| Value | Shows |
|---|---|
| `defender_cve_exposed` | Devices with at least one `affected by` edge to a CVE node |
| `defender_hascreds` | `has credentials of` edges and their endpoints |
| `defender_roles` | `has role` edges and their endpoints |

### Keyboard shortcuts
| Key | Action |
|---|---|
| `Ctrl+K` / `Cmd+K` | Focus the search box |
| `PageDown` / `→` | Next entity (focus mode) |
| `PageUp` / `←` | Previous entity (focus mode) |
| `Home` | First entity (focus mode) |
| `End` | Last entity (focus mode) |

### Export
When Defender data is loaded, CSV export gains a `Source` column on both the Node and Edge sheets:
- `sharphound` — object from SharpHound only
- `defender` — object from Defender only
- `sharphound+defender` — merged node seen by both collectors

---

## Known limitations

| Limitation | Detail |
|---|---|
| Name-only merging | Nodes are merged by exact case-insensitive name match. Two tenants or forests that share hostnames (e.g. `DC01`) will produce false-positive merges. |
| No live API | The module reads exported CSV only. It cannot call the Defender API from the browser due to CORS and auth constraints. |
| Focus-mode filters | The panel checkboxes (Hide Orphans, Structure, ACLs, Exec/Admin) are not applied inside the focus-mode neighborhood view; they continue to apply when focus mode is off. |
| 5 000-row KQL limit | The `take 5000` in the KQL query caps results. Remove the limit and use multiple exports if your environment has more exposure edges. |
| EdgeProperties depth | Nested JSON objects in `EdgeProperties` are shown one level deep in the Details pane. |
