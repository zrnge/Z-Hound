// defender-module.js
// M365 Defender ExposureGraphEdges integration for Z-Hound Reforged
// Hooks into Z-Hound's global graph engine. Load AFTER index.html's <script> block.

(function (global) {
    'use strict';

    // ================================================================
    // DEFENDER DATA STATE
    // ================================================================
    const defenderNodeIds = new Set();   // adNodes keys sourced from Defender
    let   defenderAdjOut  = new Map();   // nodeKey → adEdge[]  (outbound Defender edges)
    let   defenderAdjIn   = new Map();   // nodeKey → adEdge[]  (inbound  Defender edges)
    let   defenderLoaded  = false;
    let   defenderEdgeCount = 0;

    // Deduplication set: exact (from,to,label) triple for Defender edges
    const defenderEdgeKeys = new Set();

    // Focus mode state
    const dfs = {
        active:     false,
        entityType: 'all',
        sortBy:     'degree',
        hops:       1,
        entities:   [],
        idx:        0,
    };

    // ================================================================
    // NEW NODE TYPES — extend Z-Hound's global lookup tables
    // ================================================================
    const DEF_NODE_COLORS = {
        App:           '#f59e0b',   // amber
        Role:          '#ef4444',   // red
        CVE:           '#dc2626',   // darker red
        AzureResource: '#3b82f6',   // blue
        DefenderNode:  '#6b7280',   // grey
    };
    const DEF_NODE_SHAPES = { CVE: 'diamond' };

    // NODE_COLORS / NODE_SHAPES are const objects but their contents are mutable
    Object.assign(NODE_COLORS, DEF_NODE_COLORS);
    Object.assign(NODE_SHAPES, DEF_NODE_SHAPES);

    // ================================================================
    // DEFENDER EDGE RISK WEIGHTS — extend global EDGE_RISK
    // ================================================================
    const DEF_EDGE_RISK = {
        'has credentials of':  85,
        'can authenticate as': 90,
        'contains':            15,
        'affected by':         70,
        'member of':           10,
        'has role':            60,
        'exposes':             65,
        'can access':          55,
        'runs as':             75,
        'manages':             70,
        'linked to':           30,
        'hosts':               45,
    };
    Object.assign(EDGE_RISK, DEF_EDGE_RISK);

    // ================================================================
    // LABEL → Z-HOUND TYPE MAPPING
    // ================================================================
    function defLabelToType(label) {
        const l = (label || '').toLowerCase().trim();
        if (l === 'user' || l === 'identity') return 'User';
        if (l === 'aad-user') return 'AZUser';
        if (l === 'device' || l === 'computer' ||
            l === 'microsoft.compute/virtualmachines') return 'Computer';
        if (l === 'group') return 'Group';
        if (l === 'aad-group') return 'AZGroup';
        if (l === 'application' || l === 'aad-app' || l === 'app') return 'App';
        if (l === 'role' || l === 'role-definition' || l === 'directoryrole') return 'Role';
        if (l === 'vulnerability' || l === 'cve') return 'CVE';
        if (l === 'subscription' || l === 'azure-resource' || l === 'azureresource' ||
            l === 'managedidentity' || l.includes('microsoft.') ||
            l === 'resourcegroup') return 'AzureResource';
        if (l.startsWith('aad-')) return 'AZUser';
        if (l.includes('azure')) return 'AzureResource';
        return 'DefenderNode';
    }

    function isHighValueName(name) {
        const n = (name || '').toLowerCase();
        return n.includes('global administrator') || n.includes('global admin') ||
               n.includes('domain admin') || n.includes('enterprise admin') ||
               n.includes('privileged role admin') ||
               n.includes('exchange administrator') || n.includes('exchange admin') ||
               n.includes('sharepoint administrator') || n.includes('sharepoint admin') ||
               n.includes('cloud application administrator') || n.includes('cloud application admin') ||
               n.includes('authentication administrator') || n.includes('authentication admin') ||
               n.includes('privileged authentication administrator') ||
               n.includes('user administrator') || n.includes('helpdesk administrator') ||
               n.includes('intune administrator') || n.includes('endpoint administrator');
    }

    // ================================================================
    // MINIMAL RFC-4180 CSV PARSER
    // Handles: quoted fields, embedded commas, "" escape, CRLF/LF, UTF-8 BOM
    // ================================================================
    function parseCSV(text) {
        text = text.replace(/^\uFEFF/, ''); // strip BOM
        const rows = [];
        let row = [], field = '', inQ = false;

        for (let i = 0; i < text.length; i++) {
            const ch   = text[i];
            const next = text[i + 1];

            if (inQ) {
                if (ch === '"' && next === '"') { field += '"'; i++; } // escaped quote
                else if (ch === '"')             { inQ = false; }      // close quote
                else                             { field += ch; }
            } else {
                if      (ch === '"') { inQ = true; }
                else if (ch === ',') { row.push(field); field = ''; }
                else if (ch === '\r' && next === '\n') {
                    row.push(field); field = '';
                    rows.push(row);  row = []; i++;
                }
                else if (ch === '\n' || ch === '\r') {
                    row.push(field); field = '';
                    rows.push(row);  row = [];
                }
                else { field += ch; }
            }
        }
        if (field || row.length) { row.push(field); rows.push(row); }
        // Strip trailing blank rows
        while (rows.length && rows[rows.length - 1].every(f => !f.trim())) rows.pop();
        return rows;
    }

    // ================================================================
    // CSV HEADER VALIDATION
    // ================================================================
    const REQUIRED_COLS = ['sourcenodename','sourcenodelabel','edgelabel',
                           'targetnodename','targetnodelabel'];

    function validateHeaders(headerRow) {
        const lc = headerRow.map(h => h.trim().toLowerCase());
        const missing = REQUIRED_COLS.filter(r => !lc.includes(r));
        return { valid: !missing.length, missing, lc };
    }

    // Sniff first line to auto-detect Defender CSV (used by drag-drop / paste)
    function isDefenderCSV(text) {
        const first = text.replace(/^\uFEFF/, '').split(/[\r\n]/)[0] || '';
        const lc = first.toLowerCase();
        return lc.includes('sourcenodename') && lc.includes('edgelabel') &&
               lc.includes('targetnodename');
    }

    // ================================================================
    // INGEST DEFENDER CSV → adNodes / adEdges
    // ================================================================
    function ingestDefenderCSV(csvText, filename) {
        const rows = parseCSV(csvText);
        if (rows.length < 2) { showToast(`${filename}: CSV has no data rows`, 'error'); return; }

        const { valid, missing, lc } = validateHeaders(rows[0]);
        if (!valid) {
            showToast(`${filename}: Missing columns — ${missing.join(', ')}`, 'error');
            return;
        }

        const col = name => lc.indexOf(name.toLowerCase());
        const iSN = col('sourcenodename'), iSL = col('sourcenodelabel');
        const iEL = col('edgelabel');
        const iTN = col('targetnodename'), iTL = col('targetnodelabel');
        const iEP = col('edgeproperties');

        let edgesAdded = 0, mergedCount = 0;
        const newEdges = [];

        for (let r = 1; r < rows.length; r++) {
            const row = rows[r];
            if (!row || row.length < 5) continue;

            const srcName  = (row[iSN] || '').trim();
            const srcLabel = (row[iSL] || '').trim();
            const edgeLbl  = (row[iEL] || '').trim();
            const tgtName  = (row[iTN] || '').trim();
            const tgtLabel = (row[iTL] || '').trim();
            const epRaw    = iEP >= 0 ? (row[iEP] || '').trim() : '';

            if (!srcName || !tgtName || !edgeLbl) continue;

            const srcKey = srcName.toUpperCase();
            const tgtKey = tgtName.toUpperCase();

            if (ingestNode(srcKey, srcName, srcLabel)) mergedCount++;
            if (ingestNode(tgtKey, tgtName, tgtLabel)) mergedCount++;

            let edgeProps = null;
            if (epRaw) { try { edgeProps = JSON.parse(epRaw); } catch (_) {} }

            // Exact dedup: same from/to/label using NUL delimiter
            const edgeKey = `${srcKey}\x00${tgtKey}\x00${edgeLbl}`;
            if (!defenderEdgeKeys.has(edgeKey)) {
                defenderEdgeKeys.add(edgeKey);
                const e = {
                    from: srcKey, to: tgtKey, label: edgeLbl,
                    isAcl: false,
                    riskWeight: EDGE_RISK[edgeLbl] || DEF_EDGE_RISK[edgeLbl.toLowerCase()] || 30,
                    _defenderSource: true,
                    _edgeProps: edgeProps,
                };
                adEdges.push(e);
                newEdges.push(e);
                edgesAdded++;
            }
        }

        defenderEdgeCount += edgesAdded;
        defenderLoaded = true;
        addToAdjacency(newEdges);
        afterLoad(filename, edgesAdded, mergedCount);
    }

    // Returns true if merged with an existing SharpHound node
    function ingestNode(key, displayName, label) {
        const type = defLabelToType(label);
        const isHV = isHighValueName(displayName);

        if (adNodes[key]) {
            if (!adNodes[key]._sources) adNodes[key]._sources = ['sharphound'];
            if (!adNodes[key]._sources.includes('defender'))
                adNodes[key]._sources.push('defender');
            defenderNodeIds.add(key);
            return true;
        }

        adNodes[key] = {
            name: key, type,
            isAdmin: isHV,
            props: { name: displayName, _defLabel: label },
            _sources: ['defender'],
            _defenderSource: true,
        };
        defenderNodeIds.add(key);
        return false;
    }

    // ================================================================
    // ADJACENCY MAPS — built once on load, O(1) lookup
    // ================================================================
    function buildAdjacency() {
        defenderAdjOut = new Map();
        defenderAdjIn  = new Map();
        for (const e of adEdges) {
            if (!e._defenderSource) continue;
            if (!defenderAdjOut.has(e.from)) defenderAdjOut.set(e.from, []);
            if (!defenderAdjIn.has(e.to))    defenderAdjIn.set(e.to,   []);
            defenderAdjOut.get(e.from).push(e);
            defenderAdjIn.get(e.to).push(e);
        }
    }

    // Incremental adjacency update for the edges just added (used after bulk load)
    function addToAdjacency(edges) {
        for (const e of edges) {
            if (!e._defenderSource) continue;
            if (!defenderAdjOut.has(e.from)) defenderAdjOut.set(e.from, []);
            if (!defenderAdjIn.has(e.to))    defenderAdjIn.set(e.to,   []);
            defenderAdjOut.get(e.from).push(e);
            defenderAdjIn.get(e.to).push(e);
        }
    }

    // ================================================================
    // AFTER-LOAD ORCHESTRATION
    // ================================================================
    function afterLoad(filename, edgesAdded, merged) {
        updateExposureStat();
        buildQuickViews();          // triggers our wrapped version
        populateFocusTypeSelector(true); // preserve current selection if still valid
        buildFocusEntityList();
        addDefenderSearchTypes();
        addLegendEntries();
        renderGraph();              // re-render with Defender data
        document.getElementById('defFocusPanel')?.classList.remove('hidden');
        document.getElementById('btnDefReport')?.classList.remove('hidden');
        switchTab('filter');
        showToast(
            `Loaded ${edgesAdded} Defender edge${edgesAdded !== 1 ? 's' : ''} from ${filename}` +
            (merged ? ` · ${merged} node${merged !== 1 ? 's' : ''} merged` : ''),
            'success'
        );
    }

    // ================================================================
    // FOCUS MODE — ENTITY LIST
    // ================================================================
    function buildFocusEntityList() {
        const type = dfs.entityType;
        let entities = [...defenderNodeIds].filter(id => {
            const n = adNodes[id];
            if (!n) return false;
            return type === 'all' || (n.type || '').toLowerCase() === type.toLowerCase();
        });

        if (dfs.sortBy === 'degree') {
            entities.sort((a, b) => {
                const da = (defenderAdjOut.get(a)?.length || 0) + (defenderAdjIn.get(a)?.length || 0);
                const db = (defenderAdjOut.get(b)?.length || 0) + (defenderAdjIn.get(b)?.length || 0);
                return db - da;
            });
        } else {
            entities.sort((a, b) => a.localeCompare(b));
        }

        dfs.entities = entities;
        dfs.idx = 0;
        updateNavLabel();
    }

    // ================================================================
    // N-HOP NEIGHBORHOOD BFS (Defender adjacency only)
    // ================================================================
    function getNeighborhood(nodeId, hops) {
        const visited = new Set([nodeId]);
        const edgeSet = new Set();
        let frontier  = [nodeId];
        const MAX_NEIGHBORHOOD = 2000; // hard cap to avoid canvas meltdown

        for (let h = 0; h < hops; h++) {
            const next = [];
            for (const nid of frontier) {
                for (const e of (defenderAdjOut.get(nid) || [])) {
                    edgeSet.add(e);
                    if (!visited.has(e.to)) { visited.add(e.to); next.push(e.to); }
                }
                for (const e of (defenderAdjIn.get(nid) || [])) {
                    edgeSet.add(e);
                    if (!visited.has(e.from)) { visited.add(e.from); next.push(e.from); }
                }
            }
            frontier = next;
            if (visited.size > MAX_NEIGHBORHOOD) {
                console.warn(`[DefenderModule] Neighborhood cap hit at ${MAX_NEIGHBORHOOD} nodes; truncating.`);
                break;
            }
            if (!frontier.length) break;
        }
        return { nodeIds: [...visited], edges: [...edgeSet] };
    }

    // ================================================================
    // FOCUS MODE — RENDER (< 200 ms target)
    // ================================================================
    function renderFocused() {
        if (!dfs.active || !dfs.entities.length) return;
        const entityId = dfs.entities[dfs.idx];
        if (!entityId) return;

        const t0 = performance.now();
        const { nodeIds, edges } = getNeighborhood(entityId, dfs.hops);

        // Also include SharpHound edges between the visible nodes (structural context)
        const nodeSet  = new Set(nodeIds);
        const allEdges = [...edges];
        for (const e of adEdges) {
            if (!e._defenderSource && nodeSet.has(e.from) && nodeSet.has(e.to))
                allEdges.push(e);
        }

        const elements = buildElements(nodeIds, allEdges);   // uses our wrapped version
        initCytoscape(elements);                              // uses our wrapped version

        // Style focused entity after Cytoscape layout has finished
        const finishFocus = () => {
            if (!cy) return;
            const focusEl = cy.getElementById(entityId);
            if (focusEl.length) {
                focusEl.style({
                    width: 54, height: 54,
                    'border-width': 4,
                    'border-color': '#7289da',
                    'border-style': 'dashed',
                });
                cy.animate({ center: { eles: focusEl }, zoom: 2 }, { duration: 150 });
            }
            const dt = Math.round(performance.now() - t0);
            if (dt > 200) console.warn(`[DefenderModule] Focus render took ${dt}ms`);
        };

        if (cy) {
            const layout = cy.layout(getLayoutConfig());
            layout.one('layoutstop', finishFocus);
            layout.run();
        } else {
            finishFocus();
        }

        updateFocusCard(entityId);
        updateNavLabel();
    }

    function updateFocusCard(entityId) {
        const card   = document.getElementById('dfFocusCard');
        const nameEl = document.getElementById('dfFocusName');
        const metaEl = document.getElementById('dfFocusMeta');
        if (!card || !nameEl || !metaEl) return;
        const n = adNodes[entityId];
        if (!n) { card.classList.add('hidden'); return; }
        const displayName = n.props?.name || entityId;
        const outDeg  = defenderAdjOut.get(entityId)?.length || 0;
        const inDeg   = defenderAdjIn.get(entityId)?.length  || 0;
        const isMerged = n._sources?.length > 1;
        nameEl.textContent = displayName.length > 60 ? displayName.slice(0, 57) + '...' : displayName;
        metaEl.textContent = `${n.type} · Out: ${outDeg} · In: ${inDeg}` +
                             (isMerged ? ' · Merged' : '');
        card.classList.remove('hidden');
    }

    function updateNavLabel() {
        const el    = document.getElementById('dfNavLabel');
        const badge = document.getElementById('dfBadge');
        const total = dfs.entities.length;
        if (el)    el.textContent    = `${total ? dfs.idx + 1 : 0} / ${total}`;
        if (badge) badge.textContent = total;
    }

    // ================================================================
    // APPLY DEFENDER EDGE / NODE STYLES TO CYTOSCAPE
    // ================================================================
    function applyDefenderEdgeStyles() {
        if (!cy) return;
        // Use Cytoscape selectors instead of iterating every element
        cy.edges('[?isDefender]').style({
            'line-style':         'dashed',
            'line-dash-pattern':  [4, 2],
            'line-color':         '#60a5fa',
            'target-arrow-color': '#60a5fa',
            'opacity':            0.75,
        });
        // Two-tone border for merged nodes
        cy.nodes().filter(n => {
            const node = adNodes[n.id()];
            return node?._sources?.length > 1;
        }).style({ 'border-color': '#a78bfa', 'border-width': 3 });
    }

    // ================================================================
    // PUBLIC API  (called from inline onclick attributes)
    // ================================================================
    const defenderModule = {
        navFirst() { dfs.idx = 0; renderFocused(); },
        navLast()  { dfs.idx = Math.max(0, dfs.entities.length - 1); renderFocused(); },
        navPrev()  { if (dfs.idx > 0) { dfs.idx--; renderFocused(); } },
        navNext()  { if (dfs.idx < dfs.entities.length - 1) { dfs.idx++; renderFocused(); } },

        toggleFocus() {
            if (!defenderLoaded) { showToast('Load a Defender CSV first', 'error'); return; }
            dfs.active = !dfs.active;
            const btn    = document.getElementById('dfToggleBtn');
            const exitBtn= document.getElementById('dfExitBtn');
            if (dfs.active) {
                buildFocusEntityList();
                renderFocused();
                if (btn) { btn.textContent = 'Focus Mode Active'; btn.classList.replace('bg-indigo-700','bg-indigo-900'); }
                if (exitBtn) exitBtn.classList.remove('hidden');
            } else {
                dfs.active = false;
                renderGraph();
                if (btn) { btn.textContent = 'Enable Focus Mode'; btn.classList.replace('bg-indigo-900','bg-indigo-700'); }
                if (exitBtn) exitBtn.classList.add('hidden');
            }
        },

        exitFocus() {
            dfs.active = false;
            const btn    = document.getElementById('dfToggleBtn');
            const exitBtn= document.getElementById('dfExitBtn');
            if (btn) { btn.textContent = 'Enable Focus Mode'; btn.classList.replace('bg-indigo-900','bg-indigo-700'); }
            if (exitBtn) exitBtn.classList.add('hidden');
            renderGraph();
        },

        onTypeChange() {
            dfs.entityType = document.getElementById('dfTypeSelect')?.value || 'all';
            buildFocusEntityList();
            if (dfs.active) renderFocused();
        },
        onSortChange() {
            dfs.sortBy = document.getElementById('dfSortSelect')?.value || 'degree';
            buildFocusEntityList();
            if (dfs.active) renderFocused();
        },
        onHopsChange() {
            dfs.hops = parseInt(document.getElementById('dfHopsSelect')?.value || '1', 10);
            if (dfs.active) renderFocused();
        },
    };
    global.defenderModule = defenderModule;

    // ================================================================
    // FUNCTION WRAPPERS
    // Top-level function declarations become window properties in classic
    // scripts, so assigning window.fn = wrapper is picked up by callers
    // inside the original script (they resolve through the global object).
    // ================================================================

    // 1. buildElements — tag Defender edges with isDefender=true in element data
    const _origBuildElements = buildElements;
    global.buildElements = function (nodeIds, edges) {
        const elements = _origBuildElements(nodeIds, edges);
        const defKeys = new Set();
        for (const e of edges) {
            if (e._defenderSource)
                defKeys.add(`${e.from}\x00${e.to}\x00${e.label}`);
        }
        if (defKeys.size > 0) {
            for (const el of elements) {
                if (el.group === 'edges') {
                    const k = `${el.data.source}\x00${el.data.target}\x00${el.data.label}`;
                    if (defKeys.has(k)) el.data.isDefender = true;
                }
            }
        }
        return elements;
    };

    // 2. initCytoscape — apply Defender styles after Cytoscape instance is ready
    const _origInitCy = initCytoscape;
    global.initCytoscape = function (elements) {
        _origInitCy(elements);
        if (defenderLoaded) applyDefenderEdgeStyles();
    };

    // 3. computeStats — add Exposure Edges counter
    const _origComputeStats = computeStats;
    global.computeStats = function () {
        _origComputeStats();
        updateExposureStat();
    };

    // 4a. buildFilterPanel — re-inject Defender Focus panel after host rebuilds it
    const _origBuildFilterPanel = buildFilterPanel;
    global.buildFilterPanel = function () {
        _origBuildFilterPanel();
        injectDefenderFocusPanel();
    };

    // 4b. buildQuickViews — add Defender-specific quick views
    const _origBuildQuickViews = buildQuickViews;
    global.buildQuickViews = function () {
        _origBuildQuickViews();
        if (!defenderLoaded) return;
        const select = document.getElementById('quickView');
        if (!select) return;

        // Remove stale Defender options to prevent duplication on reload
        [...select.options].filter(o => o.dataset.defender).forEach(o => o.remove());

        const defGrp = document.createElement('optgroup');
        defGrp.label = 'Defender Exposure';

        const cveCount = [...defenderNodeIds].filter(id => adNodes[id]?.type === 'CVE').length;
        if (cveCount > 0) {
            const o = document.createElement('option');
            o.value = 'defender_cve_exposed'; o.dataset.defender = '1';
            o.textContent = `CVE-Exposed Assets (${cveCount} CVEs)`;
            defGrp.appendChild(o);
        }
        const credEdges = adEdges.filter(e => e._defenderSource && e.label === 'has credentials of').length;
        if (credEdges > 0) {
            const o = document.createElement('option');
            o.value = 'defender_hascreds'; o.dataset.defender = '1';
            o.textContent = `Credential Exposure (${credEdges})`;
            defGrp.appendChild(o);
        }
        const roleEdges = adEdges.filter(e => e._defenderSource && e.label === 'has role').length;
        if (roleEdges > 0) {
            const o = document.createElement('option');
            o.value = 'defender_roles'; o.dataset.defender = '1';
            o.textContent = `Role Assignments (${roleEdges})`;
            defGrp.appendChild(o);
        }
        if (defGrp.children.length > 0) select.appendChild(defGrp);
    };

    // 5. renderGraph — focus mode wins over everything; then Defender quick views; then default
    const _origRenderGraph = renderGraph;
    global.renderGraph = function () {
        // Focus mode short-circuits standard render
        if (dfs.active) { renderFocused(); return; }

        const qv = document.getElementById('quickView')?.value || 'none';

        if (qv === 'defender_cve_exposed') {
            const cveNodes = new Set([...defenderNodeIds].filter(id => adNodes[id]?.type === 'CVE'));
            const exposed  = new Set(adEdges
                .filter(e => e._defenderSource && e.label === 'affected by' && cveNodes.has(e.to))
                .map(e => e.from));
            const visible  = new Set([...exposed, ...cveNodes]);
            const visEdges = adEdges.filter(e => visible.has(e.from) && visible.has(e.to));
            initCytoscape(buildElements([...visible], visEdges));
            return;
        }
        if (qv === 'defender_hascreds') {
            const credEdges = adEdges.filter(e => e._defenderSource && e.label === 'has credentials of');
            const visible   = new Set();
            credEdges.forEach(e => { visible.add(e.from); visible.add(e.to); });
            initCytoscape(buildElements([...visible], credEdges));
            return;
        }
        if (qv === 'defender_roles') {
            const roleEdges = adEdges.filter(e => e._defenderSource && e.label === 'has role');
            const visible   = new Set();
            roleEdges.forEach(e => { visible.add(e.from); visible.add(e.to); });
            initCytoscape(buildElements([...visible], roleEdges));
            return;
        }

        _origRenderGraph();
    };

    // 6. showNodeDetails — append Exposure section for Defender / merged nodes
    const _origShowNodeDetails = showNodeDetails;
    global.showNodeDetails = function (nodeId) {
        _origShowNodeDetails(nodeId);
        if (!defenderLoaded) return;
        const n = adNodes[nodeId];
        if (!n) return;
        const outEdges = defenderAdjOut.get(nodeId) || [];
        const inEdges  = defenderAdjIn.get(nodeId)  || [];
        const isDefNode = n._defenderSource || n._sources?.includes('defender');
        if (!outEdges.length && !inEdges.length && !isDefNode) return;

        const pane = document.getElementById('pane-details');
        if (!pane) return;

        const isMerged = n._sources?.length > 1;

        const edgeRow = (e, dir) => {
            const peer    = dir === 'out' ? e.to : e.from;
            const peerN   = adNodes[peer];
            const display = peerN?.props?.name || peer;
            const short   = display.split('@')[0] || display;
            const tok     = typeof nodeToken === 'function' ? nodeToken(peer) : peer;
            const propsHtml = e._edgeProps
                ? Object.entries(e._edgeProps).slice(0, 4).map(([k, v]) =>
                    `<span class="text-gray-600">${esc(k)}:</span><span class="text-gray-500">${esc(String(v))}</span>`
                  ).join('  ')
                : '';
            return `<div class="flex items-start gap-1 py-0.5 px-1 hover:bg-gray-800/60 rounded cursor-pointer text-xs"
                         onclick="focusNode(_nodeTokens['${tok}'])">
                <span class="${dir === 'out' ? 'text-blue-400' : 'text-orange-400'} shrink-0">${dir === 'out' ? '→' : '←'}</span>
                <span class="text-gray-500 font-mono shrink-0">[${esc(e.label)}]</span>
                <span class="text-gray-200 truncate">${esc(short)}</span>
            </div>${propsHtml ? `<div class="ml-5 text-xs pb-0.5">${propsHtml}</div>` : ''}`;
        };

        let html = `<div class="mt-3 border-t border-gray-700/60 pt-2">
            <div class="text-gray-400 font-semibold text-xs uppercase tracking-wide mb-1.5 flex items-center gap-1.5">
                Exposure
                ${isMerged ? `<span class="px-1.5 py-0 rounded bg-purple-900/60 text-purple-300 border border-purple-700/60 text-xs">Merged</span>` : ''}
            </div>`;

        if (outEdges.length) {
            html += `<div class="text-gray-500 text-xs uppercase tracking-wide font-semibold mb-0.5">
                         Outbound (${outEdges.length})</div>`;
            html += outEdges.slice(0, 20).map(e => edgeRow(e, 'out')).join('');
            if (outEdges.length > 20)
                html += `<div class="text-gray-600 text-xs pl-1">…and ${outEdges.length - 20} more</div>`;
        }
        if (inEdges.length) {
            html += `<div class="text-gray-500 text-xs uppercase tracking-wide font-semibold mb-0.5 mt-1.5">
                         Inbound (${inEdges.length})</div>`;
            html += inEdges.slice(0, 20).map(e => edgeRow(e, 'in')).join('');
            if (inEdges.length > 20)
                html += `<div class="text-gray-600 text-xs pl-1">…and ${inEdges.length - 20} more</div>`;
        }

        html += `</div>`;
        pane.insertAdjacentHTML('beforeend', html);
    };

    // 7. exportCSV — add Source column; full replacement when Defender data present
    const _origExportCSV = exportCSV;
    global.exportCSV = function () {
        if (!defenderLoaded) { _origExportCSV(); return; }

        const rows = [];
        rows.push(['Type','Name','NodeType','RiskScore','RiskLabel','Flags',
                   'SID','Domain','Enabled','Source']);
        Object.values(adNodes).forEach(n => {
            const { score, flags } = calcNodeRisk(n);
            const p   = n.props || {};
            const src = n._sources ? n._sources.join('+')
                       : (n._defenderSource ? 'defender' : 'sharphound');
            rows.push(['Node', n.name, n.type, score, getRiskLabel(score),
                [...new Set([...(n.riskFlags || []), ...flags])].join('; '),
                p.objectsid || p.domainsid || '', p.domain || '',
                p.enabled != null ? String(p.enabled) : '', src]);
        });

        rows.push([]);
        rows.push(['Type','From','EdgeLabel','To','IsACL','RiskWeight','MITRE','Source']);
        adEdges.forEach(e => {
            rows.push(['Edge', e.from, e.label, e.to,
                e.isAcl ? 'true' : 'false', e.riskWeight,
                EDGE_MITRE[e.label] || '',
                e._defenderSource ? 'defender' : 'sharphound']);
        });

        const csv = rows.map(r =>
            r.map(c => {
                const s = String(c == null ? '' : c).replace(/"/g, '""');
                return /[,"\n\r]/.test(s) ? `"${s}"` : s;
            }).join(',')
        ).join('\r\n');

        const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = 'zhound-findings.csv'; a.click();
        URL.revokeObjectURL(url);
    };

    // 8. clearGraph — reset all Defender state alongside SharpHound state
    const _origClearGraph = clearGraph;
    global.clearGraph = function () {
        _origClearGraph();
        defenderNodeIds.clear();
        defenderAdjOut.clear();
        defenderAdjIn.clear();
        defenderEdgeKeys.clear();
        defenderLoaded    = false;
        defenderEdgeCount = 0;
        dfs.active        = false;
        dfs.entities      = [];
        dfs.idx           = 0;
        document.getElementById('defFocusPanel')?.classList.add('hidden');
        const btn = document.getElementById('dfToggleBtn');
        if (btn) { btn.textContent = 'Enable Focus Mode'; btn.classList.replace('bg-indigo-900','bg-indigo-700'); }
        document.getElementById('dfExitBtn')?.classList.add('hidden');
        document.getElementById('btnDefReport')?.classList.add('hidden');
        updateExposureStat();
    };

    // ================================================================
    // STATS BAR — Exposure Edges counter
    // ================================================================
    function updateExposureStat() {
        const el = document.getElementById('statExposureEdges');
        if (el) el.textContent = defenderEdgeCount;
    }

    // ================================================================
    // SEARCH TYPE FILTER — add Defender types
    // ================================================================
    function addDefenderSearchTypes() {
        const sel = document.getElementById('searchTypeFilter');
        if (!sel) return;
        [...sel.options].filter(o => o.dataset.defender).forEach(o => o.remove());
        ['App','Role','CVE','AzureResource','DefenderNode'].forEach(t => {
            if (Object.values(adNodes).some(n => n.type === t)) {
                const o = document.createElement('option');
                o.value = t; o.textContent = t; o.dataset.defender = '1';
                sel.appendChild(o);
            }
        });
    }

    // ================================================================
    // LEGEND — append Defender type entries once
    // ================================================================
    function addLegendEntries() {
        const legend = document.getElementById('defLegend');
        if (!legend || legend.dataset.defenderLegend) return;
        legend.dataset.defenderLegend = '1';

        const divider = document.createElement('div');
        divider.className = 'flex items-center gap-1.5 mt-1 border-t border-gray-700/50 pt-1';
        divider.innerHTML = '<span class="text-gray-500 text-xs">Defender:</span>';
        legend.appendChild(divider);

        const entries = [
            { color: '#f59e0b', label: 'App',           diamond: false },
            { color: '#ef4444', label: 'Role',          diamond: false },
            { color: '#dc2626', label: 'CVE',           diamond: true  },
            { color: '#3b82f6', label: 'AzureResource', diamond: false },
            { color: '#6b7280', label: 'DefenderNode',  diamond: false },
            { color: '#a78bfa', label: 'Merged node',   border: true   },
        ];
        entries.forEach(({ color, label, diamond, border }) => {
            const d = document.createElement('div');
            d.className = 'flex items-center gap-1.5';
            d.style.cssText = 'font-size:11px;color:#d1d5db;margin-bottom:2px';
            if (diamond)
                d.innerHTML = `<span style="display:inline-block;width:10px;height:10px;background:${color};transform:rotate(45deg);flex-shrink:0"></span>${label}`;
            else if (border)
                d.innerHTML = `<span style="display:inline-block;width:12px;height:12px;border-radius:50%;border:2px solid ${color};flex-shrink:0"></span>${label}`;
            else
                d.innerHTML = `<span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:${color};flex-shrink:0"></span>${label}`;
            legend.appendChild(d);
        });
    }

    // ================================================================
    // FOCUS PANEL — type selector population
    // ================================================================
    function populateFocusTypeSelector(preserve = false) {
        const sel = document.getElementById('dfTypeSelect');
        if (!sel) return;
        const prev = preserve ? sel.value : 'all';
        while (sel.options.length > 1) sel.remove(1);

        const counts = {};
        defenderNodeIds.forEach(id => {
            const t = adNodes[id]?.type || 'DefenderNode';
            counts[t] = (counts[t] || 0) + 1;
        });
        Object.entries(counts).sort((a, b) => b[1] - a[1]).forEach(([type, count]) => {
            const o = document.createElement('option');
            o.value = type;
            o.textContent = `${type} (${count})`;
            sel.appendChild(o);
        });

        if ([...sel.options].some(o => o.value === prev)) sel.value = prev;
        else sel.value = 'all';
        if (preserve) dfs.entityType = sel.value;
    }

    // ================================================================
    // FILE UPLOAD — Defender CSV
    // ================================================================
    function handleDefenderFile(file) {
        const reader = new FileReader();
        reader.onload = ev => {
            const text = ev.target.result;
            if (!isDefenderCSV(text)) {
                showToast(`${file.name}: Not a Defender ExposureGraphEdges CSV`, 'error');
                return;
            }
            ingestDefenderCSV(text, file.name);
        };
        reader.onerror = () => showToast(`Failed to read ${file.name}`, 'error');
        reader.readAsText(file, 'UTF-8');
    }

    // ================================================================
    // TOAST NOTIFICATIONS
    // ================================================================
    function showToast(message, type = 'info') {
        let container = document.getElementById('defToastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'defToastContainer';
            container.style.cssText =
                'position:fixed;top:60px;right:16px;z-index:9999;' +
                'display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:360px;';
            document.body.appendChild(container);
        }
        const toast = document.createElement('div');
        toast.className = `def-toast def-toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.classList.add('def-toast-out'), 2800);
        setTimeout(() => toast.remove(), 3350);
    }

    // ================================================================
    // KEYBOARD SHORTCUTS
    // ================================================================
    document.addEventListener('keydown', e => {
        // Ctrl+K / Cmd+K → focus search box
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            document.getElementById('searchInput')?.focus();
            return;
        }
        // Focus navigation (only when in Focus mode and not typing in an input)
        if (!dfs.active) return;
        if (['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)) return;
        if      (e.key === 'PageDown' || e.key === 'ArrowRight') { e.preventDefault(); defenderModule.navNext(); }
        else if (e.key === 'PageUp'   || e.key === 'ArrowLeft')  { e.preventDefault(); defenderModule.navPrev(); }
        else if (e.key === 'Home')  { e.preventDefault(); defenderModule.navFirst(); }
        else if (e.key === 'End')   { e.preventDefault(); defenderModule.navLast(); }
    });

    // ================================================================
    // DOM INJECTION — run once on module load
    // ================================================================
    function injectUI() {
        injectCSVUploadButton();
        injectDefenderFocusPanel();
    }

    function injectCSVUploadButton() {
        const zipLabel = document.getElementById('zhoundUploadLabel');
        const graphWrap = document.getElementById('cy').parentElement;
        if (!zipLabel || document.getElementById('defenderCsvInput')) return;

        const lbl = document.createElement('label');
        lbl.className = 'bg-indigo-700 hover:bg-indigo-600 text-white px-3 py-1.5 rounded ' +
                        'cursor-pointer text-xs font-semibold transition';
        lbl.innerHTML = '&#128202; Defender CSV' +
                        '<input type="file" id="defenderCsvInput" accept=".csv" class="hidden">';
        zipLabel.after(lbl);

        document.getElementById('defenderCsvInput').addEventListener('change', function (e) {
            const file = e.target.files[0];
            if (!file) return;
            handleDefenderFile(file);
            e.target.value = '';
        });

        // Drag-and-drop on the graph canvas
        if (graphWrap) {
            let overlay = null;
            const getOverlay = () => {
                if (!overlay) {
                    overlay = document.createElement('div');
                    overlay.className = 'def-drag-overlay';
                    overlay.innerHTML =
                        '<span style="font-size:32px;margin-bottom:8px">&#128202;</span>' +
                        '<span>Drop Defender CSV here</span>';
                    graphWrap.appendChild(overlay);
                }
                return overlay;
            };
            graphWrap.addEventListener('dragover', e => {
                e.preventDefault();
                e.dataTransfer.dropEffect = 'copy';
                getOverlay().style.display = 'flex';
            });
            graphWrap.addEventListener('dragleave', e => {
                if (!graphWrap.contains(e.relatedTarget))
                    getOverlay().style.display = 'none';
            });
            graphWrap.addEventListener('drop', e => {
                e.preventDefault();
                getOverlay().style.display = 'none';
                const file = [...(e.dataTransfer.files || [])].find(
                    f => f.name.toLowerCase().endsWith('.csv')
                );
                if (file) handleDefenderFile(file);
            });
        }

        // Paste CSV anywhere on the page (not in an input)
        document.addEventListener('paste', e => {
            if (['INPUT','TEXTAREA'].includes(document.activeElement?.tagName)) return;
            const text = e.clipboardData?.getData('text/plain') || '';
            if (isDefenderCSV(text)) {
                e.preventDefault();
                ingestDefenderCSV(text, 'clipboard');
            }
        });
    }

    function injectDefenderFocusPanel() {
        const filterPane = document.getElementById('pane-filter');
        if (!filterPane || document.getElementById('defFocusPanel')) return;

        const panel = document.createElement('div');
        panel.id = 'defFocusPanel';
        panel.className = 'hidden';
        panel.innerHTML = `
<div class="border-t border-gray-700/60 pt-3 mt-2 px-1">
    <div class="font-semibold text-xs text-indigo-400 uppercase tracking-wide mb-2 flex items-center gap-1.5">
        Defender Focus
        <span id="dfBadge" class="px-1.5 py-0 rounded bg-indigo-900/60 text-indigo-300
               border border-indigo-700/60 text-xs font-mono">0</span>
    </div>

    <div class="mb-2">
        <label class="text-gray-500 text-xs block mb-0.5">Entity Type</label>
        <select id="dfTypeSelect" onchange="defenderModule.onTypeChange()"
            class="w-full bg-gray-800 text-white px-2 py-1 rounded text-xs
                   border border-gray-600 focus:outline-none focus:border-indigo-500">
            <option value="all">All Types</option>
        </select>
    </div>

    <div class="mb-2 flex gap-1.5">
        <div class="flex-1">
            <label class="text-gray-500 text-xs block mb-0.5">Sort By</label>
            <select id="dfSortSelect" onchange="defenderModule.onSortChange()"
                class="w-full bg-gray-800 text-white px-2 py-1 rounded text-xs
                       border border-gray-600 focus:outline-none">
                <option value="degree">Exposure (degree)</option>
                <option value="name">Name (A→Z)</option>
            </select>
        </div>
        <div class="flex-1">
            <label class="text-gray-500 text-xs block mb-0.5">Hops</label>
            <select id="dfHopsSelect" onchange="defenderModule.onHopsChange()"
                class="w-full bg-gray-800 text-white px-2 py-1 rounded text-xs
                       border border-gray-600 focus:outline-none">
                <option value="1">1 – Direct</option>
                <option value="2">2 – Transitive</option>
                <option value="3">3 – Deep</option>
            </select>
        </div>
    </div>

    <div id="dfFocusCard" class="mb-2 p-2 bg-gray-800/60 rounded border border-indigo-700/40 hidden">
        <div id="dfFocusName" class="text-white text-xs font-bold truncate"></div>
        <div id="dfFocusMeta" class="text-gray-400 text-xs mt-0.5"></div>
    </div>

    <div class="flex items-center gap-1 mb-2">
        <button onclick="defenderModule.navFirst()" title="First (Home)"
            class="bg-gray-700 hover:bg-gray-600 px-1.5 py-0.5 rounded text-xs transition">⏮</button>
        <button onclick="defenderModule.navPrev()" title="Prev (PageUp / ←)"
            class="bg-gray-700 hover:bg-gray-600 px-2 py-0.5 rounded text-xs transition">◀</button>
        <span id="dfNavLabel"
            class="flex-1 text-center text-gray-400 text-xs font-mono">0 / 0</span>
        <button onclick="defenderModule.navNext()" title="Next (PageDown / →)"
            class="bg-gray-700 hover:bg-gray-600 px-2 py-0.5 rounded text-xs transition">▶</button>
        <button onclick="defenderModule.navLast()" title="Last (End)"
            class="bg-gray-700 hover:bg-gray-600 px-1.5 py-0.5 rounded text-xs transition">⏭</button>
    </div>

    <button onclick="defenderModule.toggleFocus()" id="dfToggleBtn"
        class="w-full py-1.5 rounded text-xs font-bold transition
               bg-indigo-700 hover:bg-indigo-600 text-white mb-1.5">
        Enable Focus Mode
    </button>
    <button onclick="defenderModule.exitFocus()" id="dfExitBtn"
        class="hidden w-full py-1 rounded text-xs text-gray-400 hover:text-white
               transition border border-gray-700 mb-1.5">
        ← Exit Focus / Show Full Graph
    </button>
    <div class="text-gray-600 text-xs">PageDown / ← → to step · Home/End to jump</div>
</div>`;
        filterPane.appendChild(panel);
    }

    // ================================================================
    // DEFENDER HTML REPORT
    // ================================================================
    function exportDefenderReport() {
        if (!defenderLoaded) { showToast('Load a Defender CSV first', 'error'); return; }

        const H  = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        const sh = s => H(String(s ?? '').split('@')[0].split('\\').pop() || s);
        const dateStr = new Date().toLocaleDateString('en-US', { year:'numeric', month:'long', day:'numeric' });

        // ── Data gathering ────────────────────────────────────────────
        const defEdges  = adEdges.filter(e => e._defenderSource);
        const defNodes  = [...defenderNodeIds].map(id => adNodes[id]).filter(Boolean);
        const merged    = defNodes.filter(n => n._sources?.length > 1);

        // Node type counts
        const typeCounts = {};
        defNodes.forEach(n => { typeCounts[n.type] = (typeCounts[n.type] || 0) + 1; });

        // Edge label counts
        const labelCounts = {};
        defEdges.forEach(e => { labelCounts[e.label] = (labelCounts[e.label] || 0) + 1; });
        const topLabels = Object.entries(labelCounts).sort((a,b) => b[1]-a[1]);

        // Category buckets
        const credEdges  = defEdges.filter(e => e.label === 'has credentials of' || e.label === 'can authenticate as');
        const roleEdges  = defEdges.filter(e => e.label === 'has role');
        const cveEdges   = defEdges.filter(e => e.label === 'affected by');
        const cveNodes   = defNodes.filter(n => n.type === 'CVE');
        const roleNodes  = defNodes.filter(n => n.type === 'Role');

        // CVE-exposed devices (unique devices)
        const cveExposed = new Map(); // deviceKey → [CVE names]
        cveEdges.forEach(e => {
            if (!cveExposed.has(e.from)) cveExposed.set(e.from, []);
            const cveName = adNodes[e.to]?.props?.name || e.to;
            cveExposed.get(e.from).push(cveName);
        });

        // High-value exposure: Defender edges that reach admin nodes
        const adminSet = new Set(Object.keys(adNodes).filter(id => adNodes[id]?.isAdmin));
        const hvEdges  = defEdges.filter(e => adminSet.has(e.to));

        // ── CSS ────────────────────────────────────────────────────────
        const css = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:13px;color:#1a1a2e;background:#fff;padding:32px;max-width:1140px;margin:0 auto}
h1{font-size:22px;font-weight:800;color:#1e3a5f;margin-bottom:4px}
.sub{color:#6b7280;font-size:12px;margin-bottom:28px}
h2{font-size:11px;font-weight:700;color:#1e3a5f;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0;text-transform:uppercase;letter-spacing:.07em}
h3{font-size:12px;font-weight:600;color:#374151;margin:14px 0 6px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:14px}
th{background:#f8fafc;color:#374151;text-align:left;padding:7px 10px;border:1px solid #e2e8f0;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}
td{padding:5px 10px;border:1px solid #e2e8f0;vertical-align:top;word-break:break-word;font-size:12px}
tr:nth-child(even) td{background:#fafafa}
.badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:600;white-space:nowrap}
.crit{background:#fee2e2;color:#991b1b}
.high{background:#fef3c7;color:#92400e}
.info{background:#dbeafe;color:#1e40af}
.merged{background:#ede9fe;color:#5b21b6}
.def{background:#e0e7ff;color:#3730a3}
.cve{background:#fee2e2;color:#991b1b}
.role{background:#fce7f3;color:#9d174d}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px;margin-bottom:24px}
.card{border:1px solid #e2e8f0;border-radius:8px;padding:14px 10px;text-align:center;background:#fafafa}
.card .num{font-size:26px;font-weight:800;line-height:1;margin-bottom:4px}
.card .lbl{font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:.05em}
.c-def .num{color:#4f46e5}.c-cve .num{color:#dc2626}.c-role .num{color:#db2777}
.c-merged .num{color:#7c3aed}.c-edge .num{color:#0284c7}.c-cred .num{color:#d97706}
section{margin-bottom:28px}
.empty{color:#9ca3af;font-style:italic;font-size:12px;padding:6px 0}
.chain{font-family:monospace;font-size:11px;color:#374151}
.cedge{color:#4f46e5;font-weight:700}
footer{margin-top:40px;padding-top:14px;border-top:1px solid #e2e8f0;font-size:11px;color:#9ca3af;text-align:center}
@media print{body{padding:14px;font-size:11px}}`.trim();

        // ── Helper: table builder with row limit note ─────────────────
        const tbl = (headers, rows, limit = 300) => {
            if (!rows.length) return `<p class="empty">None found.</p>`;
            const shown = rows.slice(0, limit);
            return `<table><thead><tr>${headers.map(h=>`<th>${H(h)}</th>`).join('')}</tr></thead>
                <tbody>${shown.map(r=>`<tr>${r.map(c=>`<td>${c}</td>`).join('')}</tr>`).join('')}</tbody>
            </table>${rows.length > limit ? `<p class="empty">…and ${rows.length-limit} more rows not shown (export CSV for full data).</p>` : ''}`;
        };

        // ── Summary cards ────────────────────────────────────────────
        const cards = [
            { cls:'c-def',   num: defNodes.length,       lbl:'Defender Nodes' },
            { cls:'c-edge',  num: defEdges.length,        lbl:'Exposure Edges' },
            { cls:'c-cred',  num: credEdges.length,       lbl:'Credential Edges' },
            { cls:'c-role',  num: roleEdges.length,       lbl:'Role Assignments' },
            { cls:'c-cve',   num: cveNodes.length,        lbl:'CVEs' },
            { cls:'c-merged',num: merged.length,          lbl:'Merged Nodes' },
        ].map(c => `<div class="card ${c.cls}"><div class="num">${c.num}</div><div class="lbl">${c.lbl}</div></div>`).join('');

        // ── Node type breakdown ──────────────────────────────────────
        const typeRows = Object.entries(typeCounts).sort((a,b)=>b[1]-a[1])
            .map(([t,n]) => [`<span class="badge def">${H(t)}</span>`, n]);

        // ── Edge label breakdown ─────────────────────────────────────
        const labelRows = topLabels.map(([lbl, cnt]) => [H(lbl), cnt]);

        // ── Credential exposure table ────────────────────────────────
        const credRows = credEdges.map(e => {
            const src = adNodes[e.from]?.props?.name || e.from;
            const tgt = adNodes[e.to]?.props?.name   || e.to;
            const srcType = adNodes[e.from]?.type || '?';
            const tgtType = adNodes[e.to]?.type   || '?';
            const props = e._edgeProps ? Object.entries(e._edgeProps).map(([k,v])=>`${H(k)}: ${H(String(v))}`).join(', ') : '—';
            return [`<span class="badge def">${H(srcType)}</span> ${H(src)}`,
                    `<span class="badge crit">${H(e.label)}</span>`,
                    `<span class="badge def">${H(tgtType)}</span> ${H(tgt)}`,
                    props];
        });

        // ── Role assignment table ────────────────────────────────────
        const roleRows = roleEdges.map(e => {
            const src = adNodes[e.from]?.props?.name || e.from;
            const tgt = adNodes[e.to]?.props?.name   || e.to;
            const isHV = adNodes[e.to]?.isAdmin;
            return [H(src),
                    `${H(tgt)}${isHV ? ' <span class="badge crit">HIGH VALUE</span>' : ''}`,
                    adNodes[e.from]?.type || '?'];
        });

        // ── CVE-exposed assets ────────────────────────────────────────
        const cveRows = [...cveExposed.entries()].sort((a,b)=>b[1].length-a[1].length).map(([devKey, cves]) => {
            const n = adNodes[devKey];
            const name = n?.props?.name || devKey;
            const type = n?.type || '?';
            const isMerged = n?._sources?.length > 1;
            return [
                `${H(name)}${isMerged ? ' <span class="badge merged">Merged</span>' : ''}`,
                `<span class="badge def">${H(type)}</span>`,
                cves.length,
                cves.slice(0, 6).map(c => `<span class="badge cve">${H(c)}</span>`).join(' ') +
                    (cves.length > 6 ? ` +${cves.length - 6}` : ''),
            ];
        });

        // ── High-value exposure ─────────────────────────────────────
        const hvRows = hvEdges.map(e => {
            const src   = adNodes[e.from]?.props?.name || e.from;
            const tgt   = adNodes[e.to]?.props?.name   || e.to;
            const srcT  = adNodes[e.from]?.type || '?';
            return [`<span class="badge def">${H(srcT)}</span> ${H(src)}`,
                    `<span class="badge crit">${H(e.label)}</span>`,
                    `<span class="badge crit">HIGH VALUE</span> ${H(tgt)}`];
        });

        // ── Merged node table ────────────────────────────────────────
        const mergedRows = merged.map(n => {
            const name = n.props?.name || n.name;
            return [H(name), `<span class="badge def">${H(n.type)}</span>`,
                    n._sources?.join(' + ') || '?',
                    n.isAdmin ? '<span class="badge crit">High Value</span>' : '—'];
        });

        // ── Full edge table ──────────────────────────────────────────
        const allEdgeRows = defEdges.map(e => {
            const src  = adNodes[e.from]?.props?.name || e.from;
            const tgt  = adNodes[e.to]?.props?.name   || e.to;
            const srcT = adNodes[e.from]?.type || '?';
            const tgtT = adNodes[e.to]?.type   || '?';
            const props = e._edgeProps
                ? Object.entries(e._edgeProps).slice(0,3).map(([k,v])=>`${H(k)}=${H(String(v))}`).join(', ')
                : '';
            return [H(src), `<span class="badge def">${H(srcT)}</span>`,
                    `<span class="cedge">${H(e.label)}</span>`,
                    H(tgt), `<span class="badge def">${H(tgtT)}</span>`,
                    props || '—'];
        });

        // ── HTML assembly ─────────────────────────────────────────────
        const html = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Z-Hound Defender Exposure Report — ${dateStr}</title>
<style>${css}</style>
</head><body>
<h1>Defender Exposure Report</h1>
<div class="sub">Generated by Z-Hound Reforged &mdash; ${dateStr}</div>

<section>
<h2>Executive Summary</h2>
<div class="grid">${cards}</div>
</section>

<section>
<h2>Node Types</h2>
${tbl(['Type','Count'], typeRows)}
</section>

<section>
<h2>Edge Label Breakdown</h2>
${tbl(['Relationship','Count'], labelRows)}
</section>

${hvRows.length ? `
<section>
<h2>&#128293; High-Value Exposure (${hvRows.length} edges reaching admin targets)</h2>
${tbl(['Source','Relationship','High-Value Target'], hvRows)}
</section>` : ''}

${credRows.length ? `
<section>
<h2>Credential Exposure — has credentials of / can authenticate as (${credEdges.length})</h2>
${tbl(['Source','Relationship','Target','Properties'], credRows)}
</section>` : ''}

${roleRows.length ? `
<section>
<h2>Role Assignments (${roleEdges.length})</h2>
${tbl(['Principal','Role / Target','Source Type'], roleRows)}
</section>` : ''}

${cveRows.length ? `
<section>
<h2>CVE-Exposed Assets (${cveExposed.size} assets, ${cveNodes.length} CVEs)</h2>
${tbl(['Asset','Type','CVE Count','CVEs'], cveRows, 200)}
</section>` : ''}

${mergedRows.length ? `
<section>
<h2>Merged Nodes — seen by both SharpHound &amp; Defender (${merged.length})</h2>
${tbl(['Name','Type','Sources','Flags'], mergedRows)}
</section>` : ''}

<section>
<h2>All Exposure Edges (${defEdges.length})</h2>
${tbl(['Source','Src Type','Relationship','Target','Tgt Type','Properties'], allEdgeRows, 500)}
</section>

<footer>Z-Hound Reforged &mdash; Defender ExposureGraphEdges Report &mdash; ${dateStr}</footer>
</body></html>`;

        const blob = new Blob([html], { type: 'text/html;charset=utf-8;' });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url;
        a.download = `zhound-defender-report-${new Date().toISOString().slice(0,10)}.html`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // Expose on module API
    defenderModule.exportReport = exportDefenderReport;

    // ── Inject Defender Report button alongside the CSV upload button ──
    function injectDefenderReportButton() {
        const csvLabel = document.getElementById('defenderCsvInput')?.parentElement;
        if (!csvLabel || document.getElementById('btnDefReport')) return;
        const btn     = document.createElement('button');
        btn.id        = 'btnDefReport';
        btn.className = 'hidden bg-violet-800 hover:bg-violet-700 text-white px-3 py-1.5 rounded text-xs font-semibold transition';
        btn.textContent = '📄 Defender Report';
        btn.onclick     = exportDefenderReport;
        csvLabel.after(btn);
    }

    // Run DOM injection. Because the host creates tab panes lazily, retry if
    // the required anchors are not present yet.
    function tryInjectUI(retries = 20) {
        injectUI();
        injectDefenderReportButton();
        if ((!document.getElementById('defFocusPanel') ||
             !document.getElementById('btnDefReport')) && retries > 0) {
            setTimeout(() => tryInjectUI(retries - 1), 100);
        }
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => tryInjectUI());
    } else {
        tryInjectUI();
    }

})(window);
