<script>
  import { onMount } from 'svelte'
  import Graph from './lib/Graph.svelte'
  import Sidebar from './lib/Sidebar.svelte'
  import Header from './lib/Header.svelte'
  import Dashboard from './lib/Dashboard.svelte'
  import CommandPalette from './lib/CommandPalette.svelte'
  import FilmMode from './lib/FilmMode.svelte'
  import { DEMO_SBOM, MOCK_VULNS } from './lib/DemoSbom.js'
  
  let sbomData = null
  let baselineSbomData = null
  let diffReport = null
  let selectedNode = null
  let filmMode = false
  let showUpload = true
  let isScanning = false
  let scanProgress = 0
  let currentView = 'DASHBOARD' // DASHBOARD or GRAPH
  let showRulesPanel = false
  let canvas
  
  // VEX (Vulnerability Exploitability eXchange) state
  let ignoredCveIds = new Set()
  
  // Customisable scoring rules state (Foundry standard)
  let rules = {
    cve_weight: 0.60,
    license_weight: 0.40,
    blocked_licenses: ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
    license_unknown_score: 5.0
  }
  
  // Exploits, Threat Intelligence, and Package Age helpers
  let cisaKevSet = new Set();
  
  async function loadCisaKevCatalog() {
    try {
      const cached = localStorage.getItem('cisa_kev_catalog');
      const cachedTime = localStorage.getItem('cisa_kev_time');
      const now = Date.now();
      if (cached && cachedTime && (now - parseInt(cachedTime) < 24 * 60 * 60 * 1000)) {
        cisaKevSet = new Set(JSON.parse(cached));
        return;
      }
      const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      if (response.ok) {
        const data = await response.json();
        const ids = data.vulnerabilities?.map(v => v.cveID) || [];
        cisaKevSet = new Set(ids);
        localStorage.setItem('cisa_kev_catalog', JSON.stringify(ids));
        localStorage.setItem('cisa_kev_time', now.toString());
      }
    } catch (err) {
      console.warn("Could not load CISA KEV catalog:", err);
    }
  }

  async function fetchEpssScores(cveIds) {
    const cleanCveIds = [...new Set(cveIds.filter(id => id.startsWith('CVE-')))];
    if (cleanCveIds.length === 0) return {};
    
    const epssMap = {};
    const chunkSize = 50;
    for (let i = 0; i < cleanCveIds.length; i += chunkSize) {
      const chunk = cleanCveIds.slice(i, i + chunkSize);
      try {
        const response = await fetch(`https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`);
        if (response.ok) {
          const resJson = await response.json();
          resJson.data?.forEach(item => {
            const val = parseFloat(item.epss);
            if (!isNaN(val)) {
              epssMap[item.cve] = val;
            }
          });
        }
      } catch (err) {
        console.warn("EPSS API query failed:", err);
      }
    }
    return epssMap;
  }

  async function checkPackageStaleness(name, version) {
    try {
      // NPM Registry lookup
      const res = await fetch(`https://registry.npmjs.org/${name}`, { mode: 'cors' });
      if (res.ok) {
        const data = await res.json();
        const time = data.time?.[version];
        if (time) {
          const releaseDate = new Date(time);
          const yearsDiff = (Date.now() - releaseDate.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
          return {
            releaseDate: releaseDate.toLocaleDateString(),
            ageYears: yearsDiff,
            stale: yearsDiff > 2.0,
            ancient: yearsDiff > 5.0
          };
        }
      }
    } catch (err) {
      // fail silently
    }
    return null;
  }

  // SPDX License Expression Evaluator (Fixed AST Parser & Evaluator)
  function tokenizeLicenseExpression(expr) {
    const regex = /\s*(\(|\)|\bAND\b|\bOR\b)\s*/gi;
    return expr.split(regex).map(p => p.trim()).filter(p => p.length > 0);
  }

  function parseLicenseTokens(tokens) {
    let index = 0;
    const peek = () => tokens[index];
    const consume = () => tokens[index++];
    
    function parseFactor() {
      const token = peek();
      if (token === '(') {
        consume();
        const node = parseExpr();
        if (peek() === ')') consume();
        return node;
      }
      return { type: 'license', name: consume() };
    }
    
    function parseTerm() {
      let node = parseFactor();
      while (peek() && peek().toUpperCase() === 'AND') {
        consume();
        const right = parseFactor();
        if (node.type === 'and') {
          node.operands.push(right);
        } else {
          node = { type: 'and', operands: [node, right] };
        }
      }
      return node;
    }
    
    function parseExpr() {
      let node = parseTerm();
      while (peek() && peek().toUpperCase() === 'OR') {
        consume();
        const right = parseTerm();
        if (node.type === 'or') {
          node.operands.push(right);
        } else {
          node = { type: 'or', operands: [node, right] };
        }
      }
      return node;
    }
    return parseExpr();
  }

  function auditSingleLicense(name, blockedList) {
    const norm = name.toUpperCase().trim();
    const isBlocked = blockedList.some(bl => {
      const blNorm = bl.toUpperCase().trim();
      return norm === blNorm || norm.startsWith(blNorm + '-') || norm.startsWith(blNorm + '_');
    });
    
    if (isBlocked) return { risk: 'critical', text: name };
    if (norm.includes('AGPL') || norm.includes('SSPL') || norm.includes('GPL')) return { risk: 'warning', text: name };
    if (norm.includes('MIT') || norm.includes('APACHE') || norm.includes('BSD') || norm.includes('ISC')) return { risk: 'ok', text: name };
    return { risk: 'unknown', text: name };
  }

  function evaluateLicenseAST(node, blockedList) {
    if (!node) return { risk: 'unknown' };
    if (node.type === 'license') return auditSingleLicense(node.name, blockedList);
    
    const riskRank = { 'ok': 0, 'unknown': 1, 'warning': 2, 'critical': 3 };
    if (node.type === 'or') {
      const outcomes = node.operands.map(op => evaluateLicenseAST(op, blockedList));
      let safest = outcomes[0];
      for (let i = 1; i < outcomes.length; i++) {
        if (riskRank[outcomes[i].risk] < riskRank[safest.risk]) safest = outcomes[i];
      }
      return { risk: safest.risk };
    }
    if (node.type === 'and') {
      const outcomes = node.operands.map(op => evaluateLicenseAST(op, blockedList));
      let worst = outcomes[0];
      for (let i = 1; i < outcomes.length; i++) {
        if (riskRank[outcomes[i].risk] > riskRank[worst.risk]) worst = outcomes[i];
      }
      return { risk: worst.risk };
    }
    return { risk: 'unknown' };
  }

  function auditLicenseExpression(expr, blockedList) {
    if (!expr) return { risk: 'unknown', text: 'No License' };
    const cleaned = expr.trim();
    if (cleaned === '') return { risk: 'unknown', text: 'No License' };
    
    try {
      const tokens = tokenizeLicenseExpression(cleaned);
      if (tokens.length === 0) return { risk: 'unknown', text: expr };
      const ast = parseLicenseTokens(tokens);
      const result = evaluateLicenseAST(ast, blockedList);
      return { risk: result.risk, text: expr };
    } catch (err) {
      return auditSingleLicense(cleaned, blockedList);
    }
  }

  function normalizeSbom(data) {
    // Detect SPDX format
    if (data.spdxVersion || data.packages) {
      return {
        bomFormat: 'SPDX',
        specVersion: data.spdxVersion || '2.3',
        components: data.packages?.map(p => ({
          name: p.name,
          version: p.versionInfo || 'unknown',
          component_type: 'library',
          licenses: p.licenseConcluded ? [{ license: { id: p.licenseConcluded } }] : undefined,
          purl: p.SPDXID,
          publisher: p.supplier?.replace('Person: ', '').replace('Organization: ', ''),
          description: p.downloadLocation
        })) || [],
        dependencies: data.relationships
          ?.filter(r => r.relationshipType === 'DEPENDS_ON')
          ?.map(r => ({
            ref: r.spdxElementId,
            dependsOn: [r.relatedSpdxElement]
          })) || []
      }
    }
    return data
  }

  // Calculate dependency blast radius and cascading exposure scores
  function calculateTransitiveMetrics(components, dependencies) {
    const adj = {};
    const revAdj = {};
    
    const compMap = new Map();
    const purlMap = new Map();
    
    components.forEach(c => {
      adj[c.name] = new Set();
      revAdj[c.name] = new Set();
      compMap.set(c.name, c);
      if (c.purl) purlMap.set(c.purl, c);
    });
    
    function getComponentByRef(ref) {
      if (!ref) return null;
      if (purlMap.has(ref)) return purlMap.get(ref);
      for (let i = 0; i < components.length; i++) {
        const c = components[i];
        if (ref === c.purl || ref.includes(c.name)) {
          return c;
        }
      }
      return null;
    }
    
    dependencies.forEach(dep => {
      const parent = getComponentByRef(dep.ref);
      if (parent && dep.dependsOn) {
        dep.dependsOn.forEach(targetRef => {
          const child = getComponentByRef(targetRef);
          if (child && parent.name !== child.name) {
            adj[parent.name].add(child.name);
            revAdj[child.name].add(parent.name);
          }
        });
      }
    });
    
    function getTransitiveSet(nodeName, map) {
      const visited = new Set();
      const queue = [nodeName];
      while (queue.length > 0) {
        const curr = queue.shift();
        if (map[curr]) {
          map[curr].forEach(neigh => {
            if (!visited.has(neigh)) {
              visited.add(neigh);
              queue.push(neigh);
            }
          });
        }
      }
      return visited;
    }
    
    components.forEach(c => {
      const downstream = getTransitiveSet(c.name, adj);
      const upstream = getTransitiveSet(c.name, revAdj);
      
      c.dependenciesCount = downstream.size;
      c.blastRadius = upstream.size;
      
      // Calculate score based on self + inherited transitive vulnerability exposure
      let worstDownstreamCVSS = 0;
      downstream.forEach(childName => {
        const childComp = compMap.get(childName);
        if (childComp && childComp.cves && childComp.cves.length > 0) {
          const maxCVSS = Math.max(...childComp.cves.map(v => v.cvss_score || 0));
          if (maxCVSS > worstDownstreamCVSS) {
            worstDownstreamCVSS = maxCVSS;
          }
        }
      });
      
      // Cascading score formula
      let selfScore = c.score || 0;
      if (c.score === undefined) {
        let selfCveScore = 0;
        if (c.cves && c.cves.length > 0) {
          const activeCves = c.cves.filter(v => !ignoredCveIds.has(v.id));
          if (activeCves.length > 0) {
            selfCveScore = Math.max(...activeCves.map(v => {
              let base = v.cvss_score || 0;
              // Boost score based on exploit likelihood (+2.0 max) and active exploitation (+2.5)
              if (v.epss_score) base += v.epss_score * 2.0;
              if (v.is_cisa_kev) base += 2.5;
              return Math.min(10.0, base);
            }));
          }
        }
        
        let licenseScore = rules.license_unknown_score || 5;
        const licExpr = (c.license || (c.licenses && c.licenses[0]?.license?.id) || c.licenses?.[0]?.license?.name || '');
        const audit = auditLicenseExpression(licExpr, rules.blocked_licenses);
        if (audit.risk === 'critical') licenseScore = 10;
        else if (audit.risk === 'warning') licenseScore = 8;
        else if (audit.risk === 'ok') licenseScore = 0;
        
        let stalePenalty = 0;
        if (c.staleInfo) {
          if (c.staleInfo.ancient) stalePenalty = 1.5;
          else if (c.staleInfo.stale) stalePenalty = 0.5;
        }
        
        selfScore = selfCveScore * rules.cve_weight + licenseScore * rules.license_weight + stalePenalty;
      }
      
      c.score = Math.min(10.0, selfScore);
      c.cascadingScore = Math.min(10.0, selfScore + worstDownstreamCVSS * 0.22);
    });
  }

  async function fetchOsvBatch(purls) {
    if (purls.length === 0) return { results: [] };
    const queries = purls.map(purl => ({ package: { purl } }));
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries })
    });
    if (!response.ok) {
      throw new Error('OSV API batch query failed');
    }
    return await response.json();
  }

  async function processSbom(raw) {
    isScanning = true
    scanProgress = 0
    
    if (raw.vex_triaged_cves) {
      ignoredCveIds = new Set(raw.vex_triaged_cves)
    } else {
      ignoredCveIds = new Set()
    }
    
    let normalized = normalizeSbom(raw)
    
    if (normalized.vex_triaged_cves && ignoredCveIds.size === 0) {
      ignoredCveIds = new Set(normalized.vex_triaged_cves)
    }
    
    // Check if pre-analyzed Zertree report
    if (normalized.overall_score !== undefined && normalized.components) {
      calculateTransitiveMetrics(normalized.components, normalized.dependencies || [])
      sbomData = normalized
      isScanning = false
      showUpload = false
      return
    }
    
    const components = normalized.components || []
    const purls = components.filter(c => c.purl).map(c => c.purl)
    
    let osvResults = []
    
    try {
      const chunkSize = 500;
      for (let i = 0; i < purls.length; i += chunkSize) {
        const chunk = purls.slice(i, i + chunkSize);
        scanProgress = Math.round((i / purls.length) * 100);
        const batchRes = await fetchOsvBatch(chunk);
        if (batchRes.results) {
          osvResults = [...osvResults, ...batchRes.results];
        }
      }
    } catch (err) {
      console.warn("OSV API fetch error, applying mock telemetry data:", err);
      osvResults = purls.map(purl => {
        if (MOCK_VULNS[purl]) {
          return {
            vulns: MOCK_VULNS[purl].map(v => ({
              id: v.id,
              aliases: [v.id],
              summary: v.description,
              severity: [{ type: 'CVSS_V3', score: `CVSS:3.0/.../${v.cvss_score}` }],
              database_specific: { severity: v.severity }
            }))
          };
        }
        return {};
      });
    }
    
    let mappedComponents = components.map(c => {
      let cves = []
      if (c.purl) {
        const purlIndex = purls.indexOf(c.purl)
        const osvRes = osvResults[purlIndex]
        if (osvRes && osvRes.vulns) {
          cves = osvRes.vulns.map(v => {
            const id = v.aliases?.find(a => a.startsWith('CVE-')) || v.id
            const description = v.summary || v.details || 'No description available'
            
            let severity = 'UNKNOWN'
            let cvss_score = 0.0
            let epss_score = 0.01 // default
            
            if (v.database_specific && v.database_specific.severity) {
              severity = v.database_specific.severity.toUpperCase()
              if (severity === 'CRITICAL') cvss_score = 9.5
              else if (severity === 'HIGH') cvss_score = 7.5
              else if (severity === 'MODERATE' || severity === 'MEDIUM') cvss_score = 5.0
              else if (severity === 'LOW') cvss_score = 2.5
            } else if (v.severity) {
              const cvssSec = v.severity.find(s => s.type.startsWith('CVSS_V3'))
              if (cvssSec) {
                const parts = cvssSec.score.split('/')
                const num = parseFloat(parts[parts.length - 1])
                if (!isNaN(num)) {
                  cvss_score = num
                  if (cvss_score >= 9.0) severity = 'CRITICAL'
                  else if (cvss_score >= 7.0) severity = 'HIGH'
                  else if (cvss_score >= 4.0) severity = 'MEDIUM'
                  else if (cvss_score > 0) severity = 'LOW'
                }
              }
            }
            
            return { id, severity, cvss_score, epss_score, description }
          })
        }
      }
      return {
        ...c,
        cves
      }
    })
    
    // Batch query FIRST EPSS scores
    const cveIds = [];
    mappedComponents.forEach(c => {
      c.cves?.forEach(v => {
        if (v.id) cveIds.push(v.id);
      });
    });
    
    if (cveIds.length > 0) {
      try {
        const epssScoresMap = await fetchEpssScores(cveIds);
        mappedComponents.forEach(c => {
          c.cves?.forEach(v => {
            if (epssScoresMap[v.id] !== undefined) {
              v.epss_score = epssScoresMap[v.id];
            }
            v.is_cisa_kev = cisaKevSet.has(v.id);
          });
        });
      } catch (err) {
        console.warn("EPSS/KEV enrichment failed:", err);
      }
    }
    
    calculateTransitiveMetrics(mappedComponents, normalized.dependencies || [])
    
    sbomData = {
      ...normalized,
      components: mappedComponents
    }
    
    // Asynchronously fetch package release dates to audit package freshness
    mappedComponents.forEach(async (c) => {
      if (c.purl && c.purl.startsWith('pkg:npm/')) {
        const parts = c.purl.split('@');
        const nameAndScope = parts[0].replace('pkg:npm/', '');
        const version = parts[1];
        const staleInfo = await checkPackageStaleness(nameAndScope, version);
        if (staleInfo) {
          c.staleInfo = staleInfo;
          calculateTransitiveMetrics(mappedComponents, normalized.dependencies || []);
          sbomData = { ...sbomData, components: mappedComponents };
        }
      }
    });
    
    isScanning = false
    showUpload = false
  }

  // SBOM Comparison and Diffing Engine (Commercial Telemetry Feature)
  function generateDiffReport() {
    if (!baselineSbomData || !sbomData) {
      diffReport = null
      return
    }
    
    const baseMap = new Map(baselineSbomData.components.map(c => [c.name, c]))
    const targetMap = new Map(sbomData.components.map(c => [c.name, c]))
    
    const added = []
    const removed = []
    const upgraded = []
    
    // Find added and upgraded
    sbomData.components.forEach(tNode => {
      const bNode = baseMap.get(tNode.name)
      if (!bNode) {
        added.push(tNode)
      } else if (bNode.version !== tNode.version) {
        upgraded.push({
          name: tNode.name,
          fromVersion: bNode.version,
          toVersion: tNode.version,
          fromScore: bNode.cascadingScore || bNode.score || 0,
          toScore: tNode.cascadingScore || tNode.score || 0
        })
      }
    })
    
    // Find removed
    baselineSbomData.components.forEach(bNode => {
      if (!targetMap.has(bNode.name)) {
        removed.push(bNode)
      }
    })
    
    // Find vulnerability delta
    const baseCves = new Set()
    baselineSbomData.components.forEach(c => c.cves?.forEach(v => baseCves.add(v.id)))
    
    const targetCves = new Set()
    sbomData.components.forEach(c => c.cves?.forEach(v => targetCves.add(v.id)))
    
    const introducedCves = []
    const resolvedCves = []
    
    sbomData.components.forEach(c => {
      c.cves?.forEach(v => {
        if (!baseCves.has(v.id)) {
          introducedCves.push({ cve: v, component: c.name })
        }
      })
    })
    
    baselineSbomData.components.forEach(c => {
      c.cves?.forEach(v => {
        if (!targetCves.has(v.id)) {
          resolvedCves.push({ cve: v, component: c.name })
        }
      })
    })
    
    const baseAvgScore = baselineSbomData.components.reduce((acc, c) => acc + c.cascadingScore, 0) / (baselineSbomData.components.length || 1)
    const targetAvgScore = sbomData.components.reduce((acc, c) => acc + c.cascadingScore, 0) / (sbomData.components.length || 1)
    const scoreDelta = targetAvgScore - baseAvgScore
    
    diffReport = {
      added,
      removed,
      upgraded,
      introducedCves,
      resolvedCves,
      baseAvgScore,
      targetAvgScore,
      scoreDelta
    }
  }

  async function processBaselineSbom(raw) {
    let normalized = normalizeSbom(raw)
    
    if (normalized.overall_score !== undefined && normalized.components) {
      calculateTransitiveMetrics(normalized.components, normalized.dependencies || [])
      baselineSbomData = normalized
      generateDiffReport()
      return
    }
    
    const components = normalized.components || []
    const purls = components.filter(c => c.purl).map(c => c.purl)
    
    let osvResults = []
    
    try {
      const chunkSize = 500;
      for (let i = 0; i < purls.length; i += chunkSize) {
        const chunk = purls.slice(i, i + chunkSize);
        const batchRes = await fetchOsvBatch(chunk);
        if (batchRes.results) {
          osvResults = [...osvResults, ...batchRes.results];
        }
      }
    } catch (err) {
      osvResults = purls.map(purl => {
        if (MOCK_VULNS[purl]) {
          return {
            vulns: MOCK_VULNS[purl].map(v => ({
              id: v.id,
              aliases: [v.id],
              summary: v.description,
              severity: [{ type: 'CVSS_V3', score: `CVSS:3.0/.../${v.cvss_score}` }],
              database_specific: { severity: v.severity }
            }))
          };
        }
        return {};
      });
    }
    
    let mappedComponents = components.map(c => {
      let cves = []
      if (c.purl) {
        const purlIndex = purls.indexOf(c.purl)
        const osvRes = osvResults[purlIndex]
        if (osvRes && osvRes.vulns) {
          cves = osvRes.vulns.map(v => {
            const id = v.aliases?.find(a => a.startsWith('CVE-')) || v.id
            const description = v.summary || v.details || 'No description available'
            let severity = 'UNKNOWN'
            let cvss_score = 0.0
            let epss_score = 0.01
            
            if (v.database_specific && v.database_specific.severity) {
              severity = v.database_specific.severity.toUpperCase()
              if (severity === 'CRITICAL') cvss_score = 9.5
              else if (severity === 'HIGH') cvss_score = 7.5
              else if (severity === 'MODERATE' || severity === 'MEDIUM') cvss_score = 5.0
              else if (severity === 'LOW') cvss_score = 2.5
            } else if (v.severity) {
              const cvssSec = v.severity.find(s => s.type.startsWith('CVSS_V3'))
              if (cvssSec) {
                const parts = cvssSec.score.split('/')
                const num = parseFloat(parts[parts.length - 1])
                if (!isNaN(num)) {
                  cvss_score = num
                  if (cvss_score >= 9.0) severity = 'CRITICAL'
                  else if (cvss_score >= 7.0) severity = 'HIGH'
                  else if (cvss_score >= 4.0) severity = 'MEDIUM'
                  else if (cvss_score > 0) severity = 'LOW'
                }
              }
            }
            return { id, severity, cvss_score, epss_score, description }
          })
        }
      }
      return { ...c, cves }
    })
    
    const cveIds = [];
    mappedComponents.forEach(c => {
      c.cves?.forEach(v => {
        if (v.id) cveIds.push(v.id);
      });
    });
    
    if (cveIds.length > 0) {
      try {
        const epssScoresMap = await fetchEpssScores(cveIds);
        mappedComponents.forEach(c => {
          c.cves?.forEach(v => {
            if (epssScoresMap[v.id] !== undefined) {
              v.epss_score = epssScoresMap[v.id];
            }
            v.is_cisa_kev = cisaKevSet.has(v.id);
          });
        });
      } catch (err) {
        // ignore
      }
    }
    
    calculateTransitiveMetrics(mappedComponents, normalized.dependencies || [])
    
    baselineSbomData = {
      ...normalized,
      components: mappedComponents
    }
    
    generateDiffReport()
  }

  async function handleFileUpload(event) {
    const file = event.detail
    if (!file) return
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const raw = JSON.parse(e.target.result)
        processSbom(raw)
      } catch (err) {
        alert('Invalid SBOM JSON file')
      }
    }
    reader.readAsText(file)
  }

  async function scanLocalDirectory() {
    try {
      // @ts-ignore
      const dirHandle = await window.showDirectoryPicker()
      isScanning = true
      scanProgress = 0
      
      const packages = new Map() // Collect unique packages
      
      // Recursive function to scan for package.json
      async function scanDir(handle, depth = 0) {
        if (depth > 5) return; // Prevent infinite recursion
        for await (const entry of handle.values()) {
          if (entry.kind === 'directory' && entry.name !== 'node_modules' && entry.name !== '.git' && entry.name !== 'dist' && entry.name !== 'build') {
            await scanDir(entry, depth + 1)
          } else if (entry.kind === 'file' && entry.name === 'package.json') {
            try {
              const file = await entry.getFile()
              const text = await file.text()
              const json = JSON.parse(text)
              
              const extractDeps = (deps) => {
                if (!deps) return
                Object.entries(deps).forEach(([name, version]) => {
                  let cleanVersion = version.replace(/[^0-9.]/g, '')
                  if (!cleanVersion || cleanVersion.split('.').length < 2) cleanVersion = "1.0.0"
                  packages.set(`pkg:npm/${name}`, { 
                    name, 
                    version: cleanVersion, 
                    purl: `pkg:npm/${name}@${cleanVersion}` 
                  })
                })
              }
              extractDeps(json.dependencies)
              extractDeps(json.devDependencies)
            } catch(e) {
              console.warn("Failed to parse", entry.name, e)
            }
          }
        }
      }
      
      await scanDir(dirHandle)
      
      const generatedSbom = {
        bomFormat: "CycloneDX",
        specVersion: "1.4",
        metadata: {
          component: {
            name: dirHandle.name,
            type: "application"
          }
        },
        components: Array.from(packages.values()).map(p => ({
          type: "library",
          name: p.name,
          version: p.version,
          purl: p.purl
        }))
      }
      
      if (generatedSbom.components.length === 0) {
        alert("No NPM dependencies found in the selected directory.")
        isScanning = false
        return
      }
      
      processSbom(generatedSbom)
      
    } catch (err) {
      isScanning = false
      if (err.name !== 'AbortError') {
        console.error("Directory scan error:", err)
        alert("Failed to scan directory. " + err.message)
      }
    }
  }

  function handleTryDemo() {
    isScanning = true
    scanProgress = 30
    setTimeout(() => {
      scanProgress = 70
      setTimeout(() => {
        const components = DEMO_SBOM.components.map(c => {
          let cves = []
          if (c.purl && MOCK_VULNS[c.purl]) {
            cves = MOCK_VULNS[c.purl].map(v => ({
              id: v.id,
              severity: v.severity,
              cvss_score: v.cvss_score,
              epss_score: v.epss_score,
              description: v.description,
              fixed_version: v.fixed_version,
              is_cisa_kev: v.id === 'CVE-2023-45857' // Mark critical Axios SSRF as CISA KEV
            }))
          }
          let staleInfo = null;
          if (c.name === 'lodash') {
            staleInfo = { releaseDate: '12/05/2021', ageYears: 5.1, stale: true, ancient: true };
          } else if (c.name === 'moment') {
            staleInfo = { releaseDate: '25/06/2022', ageYears: 4.0, stale: true, ancient: false };
          }
          return {
            ...c,
            cves,
            staleInfo
          }
        })
        
        calculateTransitiveMetrics(components, DEMO_SBOM.dependencies || [])
        
        sbomData = {
          ...DEMO_SBOM,
          components
        }
        isScanning = false
        showUpload = false
      }, 400)
    }, 300)
  }
  
  function handleNodeSelect(event) {
    selectedNode = event.detail
  }
  
  function handleCloseSidebar() {
    selectedNode = null
  }
  
  function toggleFilmMode() {
    filmMode = !filmMode
  }
  
  function handleReset() {
    sbomData = null
    baselineSbomData = null
    diffReport = null
    selectedNode = null
    showUpload = true
    filmMode = false
    currentView = 'DASHBOARD'
    showRulesPanel = false
  }

  function handlePaletteAction(event) {
    const act = event.detail
    if (act.type === 'view') currentView = act.value
    if (act.type === 'rules') showRulesPanel = true
    if (act.type === 'export') {
      const exportData = {
        ...sbomData,
        vex_triaged_cves: Array.from(ignoredCveIds)
      }
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportData, null, 2))
      const downloadAnchor = document.createElement('a')
      downloadAnchor.setAttribute("href", dataStr)
      downloadAnchor.setAttribute("download", "zertree-report.json")
      document.body.appendChild(downloadAnchor)
      downloadAnchor.click()
      downloadAnchor.remove()
    }
    if (act.type === 'export_pdf') {
      window.print()
    }
  }

  function handleToggleIgnoreCve(event) {
    const cveId = event.detail.cveId;
    if (ignoredCveIds.has(cveId)) {
      ignoredCveIds.delete(cveId);
    } else {
      ignoredCveIds.add(cveId);
    }
    // Reassign to trigger Svelte reactivity
    ignoredCveIds = new Set(ignoredCveIds);
    // Recalculate metrics
    if (sbomData && sbomData.components) {
      calculateTransitiveMetrics(sbomData.components, sbomData.dependencies || []);
      sbomData = { ...sbomData };
      if (baselineSbomData) {
        generateDiffReport();
      }
    }
  }

  // Dynamic WebGL 3D Telemetry Grid (representing structural risk map)
  onMount(() => {
    loadCisaKevCatalog()
    if (!canvas) return
    
    const gl = canvas.getContext('webgl')
    if (!gl) {
      // Fallback: simple 2D canvas drawing if WebGL is not supported
      const ctx = canvas.getContext('2d')
      if (!ctx) return
      let width = canvas.width = window.innerWidth
      let height = canvas.height = window.innerHeight
      const draw2D = () => {
        ctx.clearRect(0, 0, width, height)
        ctx.fillStyle = '#020204'
        ctx.fillRect(0, 0, width, height)
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)'
        ctx.lineWidth = 0.5
        for (let x = 0; x < width; x += 40) {
          ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
        }
        for (let y = 0; y < height; y += 40) {
          ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
        }
      }
      draw2D()
      const resize2D = () => {
        width = canvas.width = window.innerWidth
        height = canvas.height = window.innerHeight
        draw2D()
      }
      window.addEventListener('resize', resize2D)
      return () => window.removeEventListener('resize', resize2D)
    }

    // Vertex shader source: implements 3D rotation, projection, and dynamic sine wave calculations
    const vsSource = `
      attribute vec3 aPosition;
      uniform float uTime;
      uniform vec2 uMouse;
      varying float vDepth;
      void main() {
        vec3 pos = aPosition;
        
        // 3D wave calculations representing dynamic threat surfaces
        float dist = length(pos.xz);
        pos.y += sin(dist * 0.06 - uTime * 1.2) * 8.0;
        pos.y += cos(pos.x * 0.04 + uTime * 0.8) * 4.0;
        
        // Eased mouse displacement wave
        float mouseDist = distance(pos.xz, uMouse * 120.0);
        if (mouseDist < 100.0) {
          float force = (1.0 - (mouseDist / 100.0)) * 14.0;
          pos.y += force;
        }

        // Camera rotation variables
        float rx = 0.75 + uMouse.y * 0.2; // Pitch angle
        float ry = uTime * 0.02 + uMouse.x * 0.3; // Yaw angle (slow auto rotation + cursor tilt)
        
        // Rotate along Y (yaw)
        float cy = cos(ry);
        float sy = sin(ry);
        vec3 rot = vec3(
          pos.x * cy - pos.z * sy,
          pos.y,
          pos.x * sy + pos.z * cy
        );
        
        // Rotate along X (pitch)
        float cx = cos(rx);
        float sx = sin(rx);
        float ny = rot.y * cx - rot.z * sx;
        float nz = rot.y * sx + rot.z * cx;
        rot.y = ny;
        rot.z = nz;
        
        // Move into depth to render perspective projection
        rot.z -= 200.0;
        
        // Perspective calculation
        float fov = 170.0;
        float scale = fov / (fov - rot.z);
        
        // Shift up slightly to view grid from an premium angle
        rot.y += 25.0;
        
        gl_Position = vec4(rot.x * scale * 0.75, rot.y * scale, 0.0, 1.0);
        gl_PointSize = max(1.0, 3.2 * scale);
        vDepth = scale;
      }
    `;

    // Fragment shader source: draws glowing round points and handles depth alpha-blending
    const fsSource = `
      precision mediump float;
      varying float vDepth;
      uniform vec4 uColor;
      uniform bool uIsPoint;
      void main() {
        if (uIsPoint) {
          // Circular particle mask
          vec2 coord = gl_PointCoord - vec2(0.5);
          if (length(coord) > 0.5) discard;
          gl_FragColor = vec4(uColor.rgb, uColor.a * vDepth * 1.3);
        } else {
          gl_FragColor = vec4(uColor.rgb, uColor.a * vDepth * 0.55);
        }
      }
    `;

    function createShader(gl, type, source) {
      const shader = gl.createShader(type);
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        console.error("Shader compiler error: ", gl.getShaderInfoLog(shader));
        gl.deleteShader(shader);
        return null;
      }
      return shader;
    }

    const vs = createShader(gl, gl.VERTEX_SHADER, vsSource);
    const fs = createShader(gl, gl.FRAGMENT_SHADER, fsSource);
    const program = gl.createProgram();
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    gl.useProgram(program);

    // Grid coordinates array
    const vertices = [];
    const lineIndices = [];
    const rows = 46;
    const cols = 46;
    const spacing = 8.0;
    const startX = -(cols * spacing) / 2;
    const startZ = -(rows * spacing) / 2;

    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        vertices.push(startX + c * spacing, 0.0, startZ + r * spacing);
      }
    }

    // Generate wireframe indices
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const idx = r * cols + c;
        if (c < cols - 1) lineIndices.push(idx, idx + 1);
        if (r < rows - 1) lineIndices.push(idx, idx + cols);
      }
    }

    const vertexBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, vertexBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(vertices), gl.STATIC_DRAW);

    const indexBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, indexBuffer);
    gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, new Uint16Array(lineIndices), gl.STATIC_DRAW);

    const aPosition = gl.getAttribLocation(program, 'aPosition');
    gl.enableVertexAttribArray(aPosition);
    gl.vertexAttribPointer(aPosition, 3, gl.FLOAT, false, 0, 0);

    const uTime = gl.getUniformLocation(program, 'uTime');
    const uMouse = gl.getUniformLocation(program, 'uMouse');
    const uColor = gl.getUniformLocation(program, 'uColor');
    const uIsPoint = gl.getUniformLocation(program, 'uIsPoint');

    let mouseX = 0, mouseY = 0;
    let targetMouseX = 0, targetMouseY = 0;

    const handleMouseMove = (e) => {
      targetMouseX = (e.clientX / window.innerWidth) * 2 - 1;
      targetMouseY = (e.clientY / window.innerHeight) * 2 - 1;
    };
    window.addEventListener('mousemove', handleMouseMove);

    let startTime = Date.now();
    let animId;

    const render = () => {
      animId = requestAnimationFrame(render);
      
      // Interpolate coordinates for smooth mouse dragging effects
      mouseX += (targetMouseX - mouseX) * 0.05;
      mouseY += (targetMouseY - mouseY) * 0.05;

      const elapsed = (Date.now() - startTime) / 1000.0;
      
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clear(gl.COLOR_BUFFER_BIT);

      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

      gl.useProgram(program);
      gl.uniform1f(uTime, elapsed);
      gl.uniform2f(uMouse, mouseX, mouseY);

      // 1. Draw 3D connecting lines (Faint white)
      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, indexBuffer);
      gl.uniform4f(uColor, 1.0, 1.0, 1.0, 0.04);
      gl.uniform1i(uIsPoint, 0);
      gl.drawElements(gl.LINES, lineIndices.length, gl.UNSIGNED_SHORT, 0);

      // 2. Draw 3D coordinate intersections (Glow white)
      gl.uniform4f(uColor, 1.0, 1.0, 1.0, 0.28);
      gl.uniform1i(uIsPoint, 1);
      gl.drawArrays(gl.POINTS, 0, vertices.length / 3);
    };

    const handleResize = () => {
      if (!canvas) return;
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      gl.viewport(0, 0, canvas.width, canvas.height);
    };
    window.addEventListener('resize', handleResize);
    
    handleResize();
    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('resize', handleResize);
    }
  })

  function toggleRulesPanel() {
    showRulesPanel = !showRulesPanel
  }

  function addBlockedLicense(event) {
    if (event.key === 'Enter' && event.target.value.trim() !== '') {
      const val = event.target.value.trim()
      if (!rules.blocked_licenses.includes(val)) {
        rules.blocked_licenses = [...rules.blocked_licenses, val]
        // recalculate metrics
        if (sbomData) calculateTransitiveMetrics(sbomData.components, sbomData.dependencies || [])
      }
      event.target.value = ''
    }
  }

  function removeBlockedLicense(lic) {
    rules.blocked_licenses = rules.blocked_licenses.filter(l => l !== lic)
    if (sbomData) calculateTransitiveMetrics(sbomData.components, sbomData.dependencies || [])
  }
</script>

<!-- Command Palette integration -->
<CommandPalette 
  {sbomData}
  on:viewChange={(e) => currentView = e.detail}
  on:nodeSelect={handleNodeSelect}
  on:action={handlePaletteAction}
/>

<canvas bind:this={canvas} class="background-canvas"></canvas>

{#if showUpload}
  <div class="landing">
    
    <header class="landing-header">
      <div class="logo">
        <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.5" class="logo-icon">
          <path d="M12 2L4 7v10l8 5 8-5V7l-8-5z" stroke-width="1.8"/>
          <path d="M12 2v20 M4 7l8 5 8-5 M4 17l8-5 8 5"/>
          <circle cx="12" cy="2" r="1.5" fill="var(--bg-main)" stroke="currentColor" stroke-width="1.5"/>
          <circle cx="4" cy="7" r="1.5" fill="var(--bg-main)" stroke="currentColor" stroke-width="1.5"/>
          <circle cx="20" cy="7" r="1.5" fill="var(--bg-main)" stroke="currentColor" stroke-width="1.5"/>
          <circle cx="12" cy="12" r="2.0" fill="var(--color-ok)" stroke="var(--color-ok)"/>
          <circle cx="4" cy="17" r="1.5" fill="var(--bg-main)" stroke="currentColor" stroke-width="1.5"/>
          <circle cx="20" cy="17" r="1.5" fill="var(--bg-main)" stroke="currentColor" stroke-width="1.5"/>
          <circle cx="12" cy="22" r="1.5" fill="var(--bg-main)" stroke="currentColor" stroke-width="1.5"/>
        </svg>
        <span class="logo-text">ZertTree <span class="subtext">OPERATIONS CENTER</span></span>
      </div>
      <a href="https://github.com/zertannax/zertree" target="_blank" class="github-link">
        <span class="github-icon"></span> GitHub
      </a>
    </header>
    
    <main class="hero">
      {#if isScanning}
        <div class="scanner-card">
          <div class="cyber-spinner"></div>
          <h2 class="scan-title">INTERROGATING SECURITY REGISTRIES...</h2>
          <div class="progress-bar-container">
            <div class="progress-bar-fill" style="width: {scanProgress}%"></div>
          </div>
          <span class="scan-progress">BATCH_QUERY: {scanProgress}% complete</span>
        </div>
      {:else}
        <div class="landing-content">
          <h1 class="title">SBOM Threat Analytics & Cascading Risk Map</h1>
          <p class="subtitle">Import software asset logs to compute reachability risk and exposure vectors.</p>
          
          <div class="upload-zone"
               on:dragover|preventDefault
               on:drop|preventDefault={(e) => {
                 const files = e.dataTransfer.files
                 if (files.length > 0) handleFileUpload({ detail: files[0] })
               }}
               role="button"
               tabindex="0">
            <input
              type="file"
              accept=".json"
              on:change={(e) => e.target.files[0] && handleFileUpload({ detail: e.target.files[0] })}
              id="file-input"
              style="display: none;"
            />
            <label for="file-input" class="upload-label">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#EDF2F7" stroke-width="1.2">
                <rect x="3" y="3" width="18" height="18" rx="2" stroke-dasharray="3 3"/>
                <path d="M12 8v8M8 12h8"/>
              </svg>
              <span class="upload-text">UPLOAD SBOM PAYLOAD (.JSON)</span>
              <span class="upload-hint">Drag & Drop CycloneDX / SPDX logs</span>
            </label>
          </div>
          
          <div class="demo-trigger-container">
            <button class="scan-pc-btn" on:click={scanLocalDirectory}>
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
              SCAN LOCAL DIRECTORY (AUTO PC SCAN)
            </button>
            <button class="demo-btn" on:click={handleTryDemo}>
              INITIATE INTELLIGENCE DEMO SBOM
            </button>
          </div>
        </div>
      {/if}
    </main>
    
    <footer class="landing-footer">
      <span>PALANTIR-STYLE SECURE SHELL</span>
      <span>•</span>
      <span>EPSS &amp; CASCADING EXPOSURE ENGINE</span>
      <span>•</span>
      <span>V0.3.0</span>
    </footer>
  </div>
{:else}
  <div class="app">
    <Header 
      {sbomData}
      {currentView}
      {baselineSbomData}
      {diffReport}
      on:viewChange={(e) => currentView = e.detail}
      on:reset={handleReset}
      on:toggleFilm={toggleFilmMode}
      on:toggleRules={toggleRulesPanel}
      on:baselineUpload={(e) => processBaselineSbom(e.detail)}
      on:clearDiff={() => { baselineSbomData = null; diffReport = null; }}
      {filmMode}
    />
    
    <div class="main-content">
      <!-- Palantir Left Sidebar: Registry Package List -->
      <aside class="left-registry">
        <div class="registry-header">
          <h3>SBOM REGISTRY</h3>
          <span class="count">{sbomData?.components?.length || 0} ITEMS</span>
        </div>
        <div class="registry-list">
          {#each [...(sbomData?.components || [])].sort((a,b) => b.cascadingScore - a.cascadingScore) as comp}
            <div 
              class="registry-item" 
              class:selected={selectedNode?.name === comp.name}
              on:click={() => selectedNode = comp}
              role="button"
              tabindex="0"
            >
              <span class="dot" style="background: {comp.cascadingScore >= 6.0 ? '#D50000' : comp.cascadingScore >= 3.0 ? '#FFB300' : '#00E676'}"></span>
              <span class="name">{comp.name}</span>
              <span class="score">{comp.cascadingScore.toFixed(1)}</span>
            </div>
          {/each}
        </div>
      </aside>
      
      <div class="viewport">
        {#if currentView === 'DASHBOARD'}
          <Dashboard 
            {sbomData} 
            {rules}
            {diffReport}
            on:nodeSelect={handleNodeSelect}
          />
        {:else}
          <Graph 
            {sbomData}
            {rules}
            on:nodeSelect={handleNodeSelect}
            {filmMode}
          />
        {/if}
      </div>
      
      {#if selectedNode}
        <Sidebar 
          node={selectedNode}
          {rules}
          {ignoredCveIds}
          on:close={handleCloseSidebar}
          on:toggleIgnoreCve={handleToggleIgnoreCve}
        />
      {/if}
    </div>
    
    {#if filmMode}
      <FilmMode />
    {/if}
    
    <!-- Foundry Standard Rules modal config -->
    {#if showRulesPanel}
      <div class="rules-modal-overlay" on:click={toggleRulesPanel}>
        <div class="rules-panel" on:click|stopPropagation>
          <div class="panel-header">
            <h3>⚙️ RISK SCORING ALGORITHM</h3>
            <button class="close-panel" on:click={toggleRulesPanel}>✕</button>
          </div>
          
          <div class="panel-body">
            <div class="rule-group">
              <label>CVE SEVERITY COEFFICIENT ({rules.cve_weight.toFixed(2)})</label>
              <input 
                type="range" 
                min="0" 
                max="1" 
                step="0.05" 
                bind:value={rules.cve_weight}
                on:input={() => {
                  rules.license_weight = 1.0 - rules.cve_weight
                  if (sbomData) calculateTransitiveMetrics(sbomData.components, sbomData.dependencies || [])
                }}
              />
            </div>
            
            <div class="rule-group">
              <label>LICENSE RISK COEFFICIENT ({rules.license_weight.toFixed(2)})</label>
              <input 
                type="range" 
                min="0" 
                max="1" 
                step="0.05" 
                bind:value={rules.license_weight}
                on:input={() => {
                  rules.cve_weight = 1.0 - rules.license_weight
                  if (sbomData) calculateTransitiveMetrics(sbomData.components, sbomData.dependencies || [])
                }}
              />
            </div>
            
            <div class="rule-group">
              <label>UNKNOWN LICENSE PENALTY ({rules.license_unknown_score.toFixed(1)}/10.0)</label>
              <input 
                type="range" 
                min="0" 
                max="10" 
                step="0.5" 
                bind:value={rules.license_unknown_score}
                on:input={() => {
                  if (sbomData) calculateTransitiveMetrics(sbomData.components, sbomData.dependencies || [])
                }}
              />
            </div>
            
            <div class="rule-group">
              <label>BLOCKED LICENSE SIGNATURES</label>
              <div class="blocked-tags">
                {#each rules.blocked_licenses as lic}
                  <span class="blocked-tag">
                    {lic}
                    <button class="remove-lic" on:click={() => removeBlockedLicense(lic)}>✕</button>
                  </span>
                {/each}
              </div>
              <input 
                type="text" 
                placeholder="Enter SPDX identifier to block + Enter"
                on:keydown={addBlockedLicense}
                class="add-lic-input"
              />
            </div>
          </div>
        </div>
      </div>
    {/if}
  </div>
{/if}

<style>
  :global(body) {
    background: #020204;
    margin: 0;
    padding: 0;
  }

  :global(:root) {
    --bg-main: #020204;
    --bg-panel: rgba(10, 10, 12, 0.7);
    --bg-active: rgba(255, 255, 255, 0.05);
    --border-subtle: rgba(255, 255, 255, 0.05);
    --border-hover: rgba(255, 255, 255, 0.12);
    --text-primary: #ffffff;
    --text-secondary: #a1a1aa;
    --text-muted: #52525b;
    
    --color-ok: #34c759;
    --color-warning: #ff9f0a;
    --color-critical: #ff453a;
    
    --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --font-display: "Space Grotesk", var(--font-sans);
    --font-mono: "JetBrains Mono", Menlo, Courier, monospace;
    
    --blur-intensity: 24px;
    --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.6);
  }

  .landing {
    width: 100vw;
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: transparent;
    position: relative;
    overflow: hidden;
  }
  
  .background-canvas {
    position: fixed;
    inset: 0;
    z-index: -1;
    pointer-events: none;
    opacity: 0.55;
  }
  
  .landing-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 18px 40px;
    z-index: 1;
    background: rgba(6, 7, 9, 0.5);
    border-bottom: 1px solid var(--border-subtle);
    backdrop-filter: blur(12px);
  }
  
  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .logo-icon {
    stroke: var(--text-primary);
  }
  
  .logo-text {
    font-family: var(--font-display);
    font-size: 17px;
    font-weight: 700;
    color: var(--text-primary);
    letter-spacing: -0.2px;
  }

  .logo-text .subtext {
    font-size: 9px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-weight: 600;
    margin-left: 8px;
    background: var(--bg-active);
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid var(--border-subtle);
  }
  
  .github-link {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 12px;
    font-family: var(--font-mono);
    transition: color 0.2s, transform 0.2s;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  
  .github-link:hover {
    color: var(--text-primary);
    transform: translateY(-1px);
  }
  
  .hero {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 1;
    padding: 0 20px;
  }

  .landing-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    animation: premiumFadeIn 0.6s cubic-bezier(0.16, 1, 0.3, 1);
  }

  @keyframes premiumFadeIn {
    from { opacity: 0; transform: translateY(16px); }
    to { opacity: 1; transform: translateY(0); }
  }
  
  .title {
    font-family: var(--font-display);
    font-size: 42px;
    font-weight: 700;
    text-align: center;
    color: var(--text-primary);
    letter-spacing: -1px;
    margin-bottom: 12px;
    background: linear-gradient(180deg, #ffffff 0%, #a2a2a7 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  
  .subtitle {
    font-size: 14px;
    color: var(--text-secondary);
    text-align: center;
    margin-bottom: 40px;
    font-family: var(--font-mono);
    max-width: 600px;
    line-height: 1.6;
  }
  
  .upload-zone {
    width: 480px;
    height: 180px;
    border: 1px dashed var(--border-hover);
    border-radius: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    background: var(--bg-panel);
    backdrop-filter: blur(var(--blur-intensity));
    box-shadow: var(--glass-shadow);
  }
  
  .upload-zone:hover {
    border-color: rgba(255, 255, 255, 0.3);
    background: rgba(25, 28, 36, 0.75);
    transform: scale(1.01);
  }
  
  .upload-label {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    cursor: pointer;
  }
  
  .upload-text {
    font-size: 13px;
    color: var(--text-primary);
    font-weight: 600;
    font-family: var(--font-mono);
    letter-spacing: 0.5px;
  }
  
  .upload-hint {
    font-size: 11px;
    color: var(--text-secondary);
    font-family: var(--font-sans);
  }

  .demo-trigger-container {
    margin-top: 32px;
  }

  .demo-btn, .scan-pc-btn {
    background: var(--bg-active);
    border: 1px solid var(--border-subtle);
    color: var(--text-primary);
    padding: 10px 24px;
    border-radius: 12px;
    font-family: var(--font-mono);
    font-weight: 600;
    cursor: pointer;
    font-size: 12px;
    letter-spacing: 0.5px;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    display: inline-flex;
    align-items: center;
    gap: 8px;
    margin: 0 8px;
  }

  .scan-pc-btn {
    background: rgba(48, 176, 199, 0.1);
    border-color: rgba(48, 176, 199, 0.3);
    color: #30b0c7;
  }

  .demo-btn:hover, .scan-pc-btn:hover {
    border-color: rgba(255, 255, 255, 0.4);
    background: rgba(255, 255, 255, 0.12);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    color: white;
  }

  /* Scanner Panel */
  .scanner-card {
    background: var(--bg-panel);
    border: 1px solid var(--border-subtle);
    border-radius: 20px;
    padding: 40px;
    width: 440px;
    display: flex;
    flex-direction: column;
    align-items: center;
    box-shadow: var(--glass-shadow);
    backdrop-filter: blur(var(--blur-intensity));
  }

  .cyber-spinner {
    width: 44px;
    height: 44px;
    border: 3px solid rgba(255, 255, 255, 0.05);
    border-top: 3px solid var(--text-primary);
    border-radius: 50%;
    animation: spin 1s cubic-bezier(0.445, 0.05, 0.55, 0.95) infinite;
    margin-bottom: 24px;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  .scan-title {
    font-family: var(--font-mono);
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 20px;
    letter-spacing: 1px;
    text-align: center;
  }

  .progress-bar-container {
    width: 100%;
    height: 6px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 12px;
  }

  .progress-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, #30b0c7 0%, #34c759 100%);
    transition: width 0.3s ease;
  }

  .scan-progress {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
  }
  
  .stats {
    display: flex;
    gap: 40px;
    margin-top: 48px;
  }
  
  .stat {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  
  .stat-number {
    font-family: var(--font-mono);
    font-size: 24px;
    font-weight: 600;
    color: var(--text-primary);
  }
  
  .stat-label {
    font-size: 10px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    margin-top: 4px;
  }
  
  .landing-footer {
    display: flex;
    justify-content: center;
    gap: 24px;
    padding: 24px;
    font-size: 10px;
    color: var(--text-secondary);
    z-index: 1;
    font-family: var(--font-mono);
    border-top: 1px solid var(--border-subtle);
    background: rgba(6, 7, 9, 0.5);
    backdrop-filter: blur(12px);
  }
  
  .app {
    width: 100vw;
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: transparent;
  }
  
  .main-content {
    flex: 1;
    display: flex;
    overflow: hidden;
    position: relative;
  }

  /* Left Registry Sidebar */
  .left-registry {
    width: 280px;
    background: rgba(10, 10, 12, 0.45);
    border-right: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    backdrop-filter: blur(10px);
  }

  .registry-header {
    padding: 18px 24px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .registry-header h3 {
    margin: 0;
    font-family: var(--font-display);
    font-size: 12px;
    font-weight: 700;
    color: var(--text-secondary);
    letter-spacing: 0.8px;
    text-transform: uppercase;
  }

  .registry-header .count {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-muted);
    background: var(--bg-active);
    padding: 1px 6px;
    border-radius: 4px;
  }

  .registry-list {
    flex: 1;
    overflow-y: auto;
    padding: 12px 8px;
  }

  .registry-item {
    display: flex;
    align-items: center;
    padding: 10px 14px;
    border-radius: 10px;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    margin-bottom: 4px;
    border: 1px solid transparent;
  }

  .registry-item:hover {
    background: rgba(255, 255, 255, 0.03);
    border-color: var(--border-subtle);
  }

  .registry-item.selected {
    background: rgba(255, 255, 255, 0.06);
    border-color: var(--border-hover);
    box-shadow: inset 0 0 12px rgba(255, 255, 255, 0.02);
  }

  .registry-item .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 12px;
    flex-shrink: 0;
    box-shadow: 0 0 8px currentColor;
  }

  .registry-item .name {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    letter-spacing: -0.2px;
  }

  .registry-item.selected .name {
    color: var(--text-primary);
    font-weight: 500;
  }

  .registry-item .score {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-secondary);
    margin-left: 8px;
    background: rgba(255, 255, 255, 0.04);
    padding: 2px 6px;
    border-radius: 6px;
  }

  .viewport {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    background: #101216;
  }

  /* Rules config overlay modal */
  .rules-modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 200;
    display: flex;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(16px);
  }

  .rules-panel {
    width: 440px;
    background: var(--bg-panel);
    border: 1px solid var(--border-hover);
    border-radius: 20px;
    padding: 28px;
    box-shadow: var(--glass-shadow);
    display: flex;
    flex-direction: column;
    backdrop-filter: blur(var(--blur-intensity));
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
    border-bottom: 1px solid var(--border-subtle);
    padding-bottom: 16px;
  }

  .panel-header h3 {
    margin: 0;
    font-family: var(--font-display);
    color: var(--text-primary);
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.5px;
  }

  .close-panel {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 14px;
    cursor: pointer;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    transition: background 0.2s;
  }

  .close-panel:hover {
    color: var(--text-primary);
    background: var(--bg-active);
  }

  .panel-body {
    display: flex;
    flex-direction: column;
    gap: 22px;
  }

  .rule-group {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .rule-group label {
    font-size: 11px;
    color: var(--text-secondary);
    font-weight: 600;
    font-family: var(--font-mono);
    letter-spacing: 0.5px;
  }

  .rule-group input[type="range"] {
    accent-color: var(--text-primary);
    background: var(--bg-active);
    height: 5px;
    border-radius: 3px;
    cursor: pointer;
    appearance: none;
  }

  .blocked-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-bottom: 6px;
  }

  .blocked-tag {
    background: rgba(255, 69, 58, 0.1);
    color: var(--color-critical);
    border: 1px solid rgba(255, 69, 58, 0.2);
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 10px;
    font-family: var(--font-mono);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .remove-lic {
    background: transparent;
    border: none;
    color: var(--color-critical);
    font-size: 10px;
    cursor: pointer;
    padding: 0;
  }

  .add-lic-input {
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 11px;
    padding: 8px 12px;
    font-family: var(--font-mono);
    outline: none;
    transition: border-color 0.2s;
  }

  .add-lic-input:focus {
    border-color: var(--text-secondary);
  }
</style>
