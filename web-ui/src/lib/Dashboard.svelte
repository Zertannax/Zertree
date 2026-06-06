<script>
  import { createEventDispatcher } from 'svelte'
  
  export let sbomData
  export let rules
  export let diffReport = null
  
  const dispatch = createEventDispatcher()
  export let activeSubTab = 'THREATS' // THREATS, COMPLIANCE, COMPARISON, LICENSES

  // Automatically switch tabs if a diff is loaded
  $: if (diffReport && activeSubTab === 'THREATS') {
    activeSubTab = 'COMPARISON'
  }

  // License inventory grouping
  $: licenseGroups = (() => {
    const groups = {};
    components.forEach(c => {
      const lic = getLicenseName(c);
      if (!groups[lic]) {
        groups[lic] = {
          license: lic,
          audit: auditLicense(lic),
          components: []
        };
      }
      groups[lic].components.push(c);
    });
    return Object.values(groups).sort((a, b) => {
      const riskRank = { 'critical': 3, 'warning': 2, 'unknown': 1, 'ok': 0 };
      if (riskRank[b.audit.risk] !== riskRank[a.audit.risk]) {
        return riskRank[b.audit.risk] - riskRank[a.audit.risk];
      }
      return b.components.length - a.components.length;
    });
  })();

  // Compliance Audit Calculations (SOC2, ISO 27001, OWASP A06, License Policy)
  $: complianceChecks = (() => {
    // 1. SOC 2 Trust Services Criteria (CC7.1 / CC7.2)
    // Pass if zero CISA KEV (known exploited vulnerabilities) are present
    const soc2Pass = cisaKevCount === 0;
    
    // 2. ISO 27001 Control A.12.6.1 (Technical Vulnerability Management)
    // Pass if all high-severity CVEs have an upgrade version available
    let iso27001Pass = true;
    components.forEach(c => {
      if (c.cves && c.cves.length > 0) {
        c.cves.forEach(v => {
          if (!v.fixed_version && v.cvss_score >= 7.0) {
            iso27001Pass = false;
          }
        });
      }
    });

    // 3. OWASP Top 10 (A06:2021 - Outdated Components)
    // Pass if average risk is below 4.0 and no ancient libraries (>5 years old) exist
    const avgScore = components.length ? (components.reduce((acc, c) => acc + c.cascadingScore, 0) / components.length) : 0;
    const ancientStaleCount = components.filter(c => c.staleInfo?.ancient).length;
    const owaspPass = avgScore < 4.0 && ancientStaleCount === 0;

    // 4. Corporate Legal License Guardrails
    // Pass if zero blocked licenses are detected
    let licenseAuditPass = true;
    components.forEach(c => {
      const lic = getLicenseName(c);
      const parts = rules.blocked_licenses || [];
      if (parts.some(bl => lic.toUpperCase().includes(bl.toUpperCase()))) {
        licenseAuditPass = false;
      }
    });

    return {
      soc2: {
        id: 'SOC2-CC7',
        name: 'SOC 2 Trust Criteria: CC7.1 & CC7.2',
        desc: 'Requires scanning and immediate remediation of vulnerabilities with active exploits in the wild.',
        status: soc2Pass ? 'PASS' : 'FAIL',
        metric: `${cisaKevCount} active exploit(s) detected`,
        fix: 'Resolve or isolate packages containing CISA KEV CVE signatures immediately.'
      },
      iso: {
        id: 'ISO-A126',
        name: 'ISO 27001 Control: A.12.6.1',
        desc: 'Ensures technical vulnerabilities are identified and patched. Requires remediation pathways for high-severity issues.',
        status: iso27001Pass ? 'PASS' : 'FAIL',
        metric: iso27001Pass ? 'All critical/high CVEs have upgrade versions' : 'Unpatched critical/high CVEs present',
        fix: 'Apply version upgrades indicated in the remediation table for unpatched modules.'
      },
      owasp: {
        id: 'OWASP-A06',
        name: 'OWASP Top 10: A06:2021 Outdated Components',
        desc: 'Restricts importing outdated or unmaintained dependencies to limit attack vectors.',
        status: owaspPass ? 'PASS' : 'FAIL',
        metric: `Avg risk: ${avgScore.toFixed(2)}/10, ${ancientStaleCount} ancient library releases`,
        fix: 'Upgrade stale dependencies published more than 5 years ago (e.g. lodash, moment).'
      },
      license: {
        id: 'LIC-GUARD',
        name: 'Corporate Legal Compliance Guardrail',
        desc: 'Enforces software licensing policies. Verifies no component uses licenses prohibited by legal rules.',
        status: licenseAuditPass ? 'PASS' : 'FAIL',
        metric: licenseAuditPass ? 'Zero blocked licenses detected' : 'Blocked license signatures detected',
        fix: 'Remove or replace dependencies matching corporate blocked license patterns (e.g., GPL-3.0).'
      }
    }
  })()

  // Download Compliance Attestation Report
  function downloadComplianceCertificate() {
    const report = {
      attestation: "ZertTree Security & Compliance Audit Certificate",
      timestamp: new Date().toISOString(),
      sbom_items: components.length,
      overall_risk_index: components.length ? (components.reduce((acc, c) => acc + c.cascadingScore, 0)/components.length).toFixed(4) : "0.0000",
      compliance_audits: complianceChecks
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `compliance-certificate-${Date.now()}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  $: components = sbomData?.components || []
  $: totalComponents = components.length
  
  // Aggregate stats
  $: criticalRiskCount = components.filter(c => (c.cascadingScore || c.score) >= 6.0).length
  $: warningRiskCount = components.filter(c => (c.cascadingScore || c.score) >= 3.0 && (c.cascadingScore || c.score) < 6.0).length
  $: okRiskCount = totalComponents - criticalRiskCount - warningRiskCount
  
  $: totalCves = components.reduce((acc, c) => acc + (c.cves?.length || 0), 0)
  $: maxCVSS = components.reduce((acc, c) => {
    if (c.cves && c.cves.length > 0) {
      const maxSelf = Math.max(...c.cves.map(v => v.cvss_score || 0))
      return maxSelf > acc ? maxSelf : acc
    }
    return acc
  }, 0)

  $: cisaKevCount = components.reduce((acc, c) => acc + (c.cves?.filter(v => v.is_cisa_kev).length || 0), 0)
  $: staleCount = components.filter(c => c.staleInfo?.stale).length
  
  // SPDX expression auditing helper
  function auditLicense(expr) {
    if (!expr) return { risk: 'unknown', text: 'No License' }
    const normalized = expr.toUpperCase().replace(/[()]/g, '')
    
    if (normalized.includes(' OR ')) {
      const parts = normalized.split(' OR ')
      const outcomes = parts.map(p => auditLicense(p.trim()))
      const hasOk = outcomes.some(o => o.risk === 'ok')
      if (hasOk) return { risk: 'ok', text: expr }
      const hasWarning = outcomes.some(o => o.risk === 'warning')
      if (hasWarning) return { risk: 'warning', text: expr }
      return { risk: 'critical', text: expr }
    }
    
    if (normalized.includes(' AND ')) {
      const parts = normalized.split(' AND ')
      const outcomes = parts.map(p => auditLicense(p.trim()))
      const hasCritical = outcomes.some(o => o.risk === 'critical')
      if (hasCritical) return { risk: 'critical', text: expr }
      const hasWarning = outcomes.some(o => o.risk === 'warning')
      if (hasWarning) return { risk: 'warning', text: expr }
      return { risk: 'ok', text: expr }
    }
    
    const name = normalized.trim()
    if (rules.blocked_licenses?.some(bl => name.includes(bl.toUpperCase()))) {
      return { risk: 'critical', text: expr }
    }
    if (name.includes('GPL') || name.includes('AGPL') || name.includes('SSPL')) {
      return { risk: 'warning', text: expr }
    }
    if (name.includes('MIT') || name.includes('APACHE') || name.includes('BSD') || name.includes('ISC')) {
      return { risk: 'ok', text: expr }
    }
    return { risk: 'unknown', text: expr }
  }
  
  // Matrix data for EPSS vs Blast Radius Heatmap
  // Y-axis (EPSS): High (>0.5), Med (0.1-0.5), Low (<0.1)
  // X-axis (Blast Radius): High (>5), Med (2-5), Low (<2)
  $: heatmapData = (() => {
    const matrix = {
      HH: [], HM: [], HL: [],
      MH: [], MM: [], ML: [],
      LH: [], LM: [], LL: []
    }
    
    components.forEach(c => {
      let maxEpss = 0
      if (c.cves && c.cves.length > 0) {
        maxEpss = Math.max(...c.cves.map(v => v.epss_score || 0))
      }
      
      const blast = c.blastRadius || 0
      
      let epssCat = 'L'
      if (maxEpss > 0.5) epssCat = 'H'
      else if (maxEpss > 0.1) epssCat = 'M'
      
      let blastCat = 'L'
      if (blast > 5) blastCat = 'H'
      else if (blast >= 2) blastCat = 'M'
      
      const key = `${epssCat}${blastCat}`
      if (matrix[key]) {
        matrix[key].push(c)
      }
    })
    
    return matrix
  })()
  
  function getComplianceClass(risk) {
    if (risk === 'critical') return 'comp-blocked'
    if (risk === 'warning') return 'comp-restricted'
    if (risk === 'ok') return 'comp-compliant'
    return 'comp-unknown'
  }
  
  function getLicenseName(n) {
    if (n.license) return n.license
    if (n.licenses && n.licenses.length > 0) {
      return n.licenses[0].license.id || n.licenses[0].license.name || 'Unknown'
    }
    return 'Unknown'
  }
  
  function selectItem(comp) {
    dispatch('nodeSelect', comp)
  }
  
  function getScoreColor(val) {
    if (val >= 7.0) return 'var(--color-critical)'
    if (val >= 4.0) return 'var(--color-warning)'
    return 'var(--color-ok)'
  }
</script>

<div class="dashboard">
  <!-- Navigation Sub Tabs -->
  <div class="sub-tab-bar">
    <button class="sub-tab-btn" class:active={activeSubTab === 'THREATS'} on:click={() => activeSubTab = 'THREATS'}>
      🛡️ THREAT AUDITING CENTER
    </button>
    <button class="sub-tab-btn" class:active={activeSubTab === 'COMPLIANCE'} on:click={() => activeSubTab = 'COMPLIANCE'}>
      ⚖️ COMPLIANCE GUARDRAILS
    </button>
    <button class="sub-tab-btn" class:active={activeSubTab === 'LICENSES'} on:click={() => activeSubTab = 'LICENSES'}>
      📜 LICENSE INVENTORY
    </button>
    {#if diffReport}
      <button class="sub-tab-btn diff" class:active={activeSubTab === 'COMPARISON'} on:click={() => activeSubTab = 'COMPARISON'}>
        ⚡ SBOM DIFFERENTIAL
      </button>
    {/if}
  </div>

  {#if activeSubTab === 'THREATS'}
    <div class="dashboard-grid">
      <!-- Matrix Heatmap -->
      <div class="panel heatmap-panel glass-card">
        <div class="panel-header">
          <h4>EXPOSURE MATRIX (EPSS VS BLAST RADIUS)</h4>
        </div>
        <div class="panel-content">
          <div class="matrix-grid">
            <!-- EPSS Y-Axis Labels -->
            <div class="axis-label y-axis">EPSS &gt; 0.5</div>
            <!-- Cells -->
            <div class="matrix-cell HH" class:has-items={heatmapData.HH.length > 0}>
              <span class="cell-count">{heatmapData.HH.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">CRITICAL EXPOSURE (HH)</span>
                {#each heatmapData.HH as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>
            <div class="matrix-cell HM" class:has-items={heatmapData.HM.length > 0}>
              <span class="cell-count">{heatmapData.HM.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">HIGH EXPOSURE (HM)</span>
                {#each heatmapData.HM as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>
            <div class="matrix-cell HL" class:has-items={heatmapData.HL.length > 0}>
              <span class="cell-count">{heatmapData.HL.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">MEDIUM EXPOSURE (HL)</span>
                {#each heatmapData.HL as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>

            <div class="axis-label y-axis">EPSS 0.1–0.5</div>
            <div class="matrix-cell MH" class:has-items={heatmapData.MH.length > 0}>
              <span class="cell-count">{heatmapData.MH.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">HIGH EXPOSURE (MH)</span>
                {#each heatmapData.MH as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>
            <div class="matrix-cell MM" class:has-items={heatmapData.MM.length > 0}>
              <span class="cell-count">{heatmapData.MM.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">ELEVATED RISK (MM)</span>
                {#each heatmapData.MM as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>
            <div class="matrix-cell ML" class:has-items={heatmapData.ML.length > 0}>
              <span class="cell-count">{heatmapData.ML.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">LOW RISK (ML)</span>
                {#each heatmapData.ML as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>

            <div class="axis-label y-axis">EPSS &lt; 0.1</div>
            <div class="matrix-cell LH" class:has-items={heatmapData.LH.length > 0}>
              <span class="cell-count">{heatmapData.LH.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">MEDIUM EXPOSURE (LH)</span>
                {#each heatmapData.LH as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>
            <div class="matrix-cell LM" class:has-items={heatmapData.LM.length > 0}>
              <span class="cell-count">{heatmapData.LM.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">SECURE/COMPLIANT (LM)</span>
                {#each heatmapData.LM as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>
            <div class="matrix-cell LL" class:has-items={heatmapData.LL.length > 0}>
              <span class="cell-count">{heatmapData.LL.length}</span>
              <div class="cell-popover glass-popover">
                <span class="popover-title">SECURE/COMPLIANT (LL)</span>
                {#each heatmapData.LL as c}
                  <div class="pop-item" on:click={() => selectItem(c)} role="button" tabindex="0">📦 {c.name} (v{c.version})</div>
                {/each}
              </div>
            </div>

            <!-- X-Axis Labels -->
            <div></div>
            <div class="axis-label x-axis">BLAST &gt; 5</div>
            <div class="axis-label x-axis">BLAST 2–5</div>
            <div class="axis-label x-axis">BLAST &lt; 2</div>
          </div>
          <p class="matrix-hint">Hover cells to view exposing package names. Click packages to locate.</p>
        </div>
      </div>

      <!-- Threat Registry Matrix -->
      <div class="panel threats-panel glass-card">
        <div class="panel-header">
          <h4>IDENTIFIED VULNERABILITY TELEMETRY</h4>
        </div>
        <div class="panel-content">
          <table class="dense-table">
            <thead>
              <tr>
                <th>COMPONENT</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>BLAST RADIUS</th>
                <th>CASCADING RISK</th>
              </tr>
            </thead>
            <tbody>
              {#each [...components].sort((a,b) => b.cascadingScore - a.cascadingScore).slice(0, 7) as comp}
                {@const maxEpss = comp.cves && comp.cves.length > 0 ? Math.max(...comp.cves.map(v => v.epss_score || 0)) : 0}
                {@const maxCvss = comp.cves && comp.cves.length > 0 ? Math.max(...comp.cves.map(v => v.cvss_score || 0)) : 0}
                {@const hasKev = comp.cves?.some(v => v.is_cisa_kev)}
                <tr on:click={() => selectItem(comp)} class="interactive-row">
                  <td class="comp-name-td">
                    <div class="comp-cell-layout">
                      <span class="comp-title">{comp.name}</span>
                      <span class="comp-ver">v{comp.version}</span>
                      {#if hasKev}
                        <span class="cisa-kev-badge">CISA KEV</span>
                      {/if}
                      {#if comp.staleInfo?.stale}
                        <span class="stale-badge" class:ancient={comp.staleInfo.ancient}>STALE</span>
                      {/if}
                    </div>
                  </td>
                  <td>
                    <span class="badge cvss-badge" style="background: {maxCvss >= 9.0 ? 'rgba(255, 69, 58, 0.15)' : maxCvss >= 7.0 ? 'rgba(255, 159, 10, 0.15)' : 'rgba(255, 255, 255, 0.05)'}; color: {maxCvss >= 9.0 ? 'var(--color-critical)' : maxCvss >= 7.0 ? 'var(--color-warning)' : 'var(--text-secondary)'}">
                      {maxCvss ? maxCvss.toFixed(1) : '—'}
                    </span>
                  </td>
                  <td>{maxEpss ? `${(maxEpss * 100).toFixed(1)}%` : '—'}</td>
                  <td>
                    <div class="br-indicator-bar">
                      <div class="br-fill" style="width: {Math.min(100, (comp.blastRadius || 0) * 15)}%"></div>
                      <span>{comp.blastRadius} affected</span>
                    </div>
                  </td>
                  <td style="color: {comp.cascadingScore >= 6.0 ? 'var(--color-critical)' : comp.cascadingScore >= 3.0 ? 'var(--color-warning)' : 'var(--color-ok)'}" class="score-cell font-mono">
                    {comp.cascadingScore.toFixed(1)}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>

      <!-- SPDX Compliance Table -->
      <div class="panel compliance-panel glass-card">
        <div class="panel-header">
          <h4>SPDX LICENSE COMPLIANCE AUDIT</h4>
        </div>
        <div class="panel-content">
          <table class="dense-table">
            <thead>
              <tr>
                <th>LICENSE EXPRESSION</th>
                <th>COMPONENTS</th>
                <th>AUDIT STATUS</th>
              </tr>
            </thead>
            <tbody>
              {#each components.slice(0, 5) as comp}
                {@const lic = getLicenseName(comp)}
                {@const audit = auditLicense(lic)}
                <tr on:click={() => selectItem(comp)} class="interactive-row">
                  <td class="license-expr">{lic}</td>
                  <td>{comp.name}</td>
                  <td>
                    <span class="compliance-badge {getComplianceClass(audit.risk)}">
                      <span class="status-light"></span>
                      {audit.risk.toUpperCase()}
                    </span>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  {:else if activeSubTab === 'COMPLIANCE'}
    <div class="compliance-dashboard">
      <div class="compliance-header">
        <h3>⚖️ CORPORATE COMPLIANCE AUDIT CENTER</h3>
        <button class="cert-btn" on:click={downloadComplianceCertificate}>
          📥 DOWNLOAD ATTESTATION CERTIFICATE
        </button>
      </div>
      
      <div class="compliance-cards-grid">
        {#each Object.values(complianceChecks) as check}
          <div class="compliance-card glass-card" class:passed={check.status === 'PASS'}>
            <div class="card-head">
              <span class="ctrl-id">{check.id}</span>
              <span class="status-badge" class:passed={check.status === 'PASS'}>
                {check.status}
              </span>
            </div>
            <h4>{check.name}</h4>
            <p class="desc">{check.desc}</p>
            
            <div class="divider"></div>
            
            <div class="audit-metrics">
              <span class="label">CURRENT METRIC</span>
              <p class="metric-val">{check.metric}</p>
            </div>
            
            {#if check.status === 'FAIL'}
              <div class="audit-fix-banner">
                <span class="fix-title">⚠️ REMEDIATION STEPS REQUIRED</span>
                <p>{check.fix}</p>
              </div>
            {/if}
          </div>
        {/each}
      </div>
    </div>
  {:else if activeSubTab === 'COMPARISON' && diffReport}
    <div class="comparison-dashboard">
      <div class="comparison-header">
        <h3>⚡ SBOM DIFFERENTIAL REPORT</h3>
        <span class="comparison-delta-badge" class:warning={diffReport.scoreDelta > 0} class:success={diffReport.scoreDelta <= 0}>
          Risk Shift: {diffReport.scoreDelta > 0 ? '+' : ''}{diffReport.scoreDelta.toFixed(3)} Avg Score
        </span>
      </div>
      
      <div class="comparison-metrics-grid">
        <div class="stat-cell glass-card">
          <span class="label">BASELINE AVG RISK</span>
          <span class="value">{diffReport.baseAvgScore.toFixed(2)}</span>
        </div>
        <div class="stat-cell glass-card">
          <span class="label">TARGET AVG RISK</span>
          <span class="value">{diffReport.targetAvgScore.toFixed(2)}</span>
        </div>
        <div class="stat-cell glass-card">
          <span class="label">ADDED MODULES</span>
          <span class="value" style="color: var(--color-warning)">+{diffReport.added.length}</span>
        </div>
        <div class="stat-cell glass-card">
          <span class="label">REMOVED MODULES</span>
          <span class="value" style="color: var(--color-ok)">-{diffReport.removed.length}</span>
        </div>
      </div>
      
      <div class="comparison-grid-layout">
        <!-- Changes list -->
        <div class="panel glass-card">
          <div class="panel-header">
            <h4>PACKAGE MODIFICATIONS</h4>
          </div>
          <div class="panel-content scrollable-panel">
            {#if diffReport.added.length > 0 || diffReport.removed.length > 0 || diffReport.upgraded.length > 0}
              {#if diffReport.added.length > 0}
                <div class="diff-section">
                  <h5 class="diff-title added">+ ADDED MODULES ({diffReport.added.length})</h5>
                  {#each diffReport.added as comp}
                    <div class="diff-item">
                      <span class="name">{comp.name} (v{comp.version})</span>
                      <span class="score" style="color: {comp.cascadingScore >= 6.0 ? 'var(--color-critical)' : comp.cascadingScore >= 3.0 ? 'var(--color-warning)' : 'var(--color-ok)'}">
                        Risk: {comp.cascadingScore.toFixed(1)}
                      </span>
                    </div>
                  {/each}
                </div>
              {/if}
              
              {#if diffReport.upgraded.length > 0}
                <div class="diff-section">
                  <h5 class="diff-title upgraded">⚡ UPGRADED MODULES ({diffReport.upgraded.length})</h5>
                  {#each diffReport.upgraded as up}
                    <div class="diff-item">
                      <span class="name">{up.name} ({up.fromVersion} → {up.toVersion})</span>
                      <span class="score-diff">
                        Risk: {up.fromScore.toFixed(1)} → {up.toScore.toFixed(1)}
                        <span class="delta" class:neg={up.toScore - up.fromScore <= 0} class:pos={up.toScore - up.fromScore > 0}>
                          ({up.toScore - up.fromScore > 0 ? '+' : ''}{(up.toScore - up.fromScore).toFixed(1)})
                        </span>
                      </span>
                    </div>
                  {/each}
                </div>
              {/if}

              {#if diffReport.removed.length > 0}
                <div class="diff-section">
                  <h5 class="diff-title removed">- REMOVED MODULES ({diffReport.removed.length})</h5>
                  {#each diffReport.removed as comp}
                    <div class="diff-item">
                      <span class="name">{comp.name} (v{comp.version})</span>
                    </div>
                  {/each}
                </div>
              {/if}
            {:else}
              <p class="no-diff-data">No package modifications detected between SBOM datasets.</p>
            {/if}
          </div>
        </div>

        <!-- Vulnerability changes -->
        <div class="panel glass-card">
          <div class="panel-header">
            <h4>VULNERABILITY DELTAS</h4>
          </div>
          <div class="panel-content scrollable-panel">
            {#if diffReport.introducedCves.length > 0 || diffReport.resolvedCves.length > 0}
              {#if diffReport.introducedCves.length > 0}
                <div class="diff-section">
                  <h5 class="diff-title introduced">🚨 INTRODUCED VULNERABILITIES ({diffReport.introducedCves.length})</h5>
                  {#each diffReport.introducedCves as intro}
                    <div class="diff-item vuln">
                      <div class="cve-line">
                        <span class="cve-id">{intro.cve.id}</span>
                        <span class="cve-severity" style="color: {getScoreColor(intro.cve.cvss_score || 5)}">CVSS {intro.cve.cvss_score?.toFixed(1) || 'N/A'}</span>
                      </div>
                      <p class="cve-desc-small">Introduced by package <code class="monospace">{intro.component}</code></p>
                    </div>
                  {/each}
                </div>
              {/if}
              
              {#if diffReport.resolvedCves.length > 0}
                <div class="diff-section">
                  <h5 class="diff-title resolved">🛡️ RESOLVED VULNERABILITIES ({diffReport.resolvedCves.length})</h5>
                  {#each diffReport.resolvedCves as res}
                    <div class="diff-item vuln">
                      <div class="cve-line">
                        <span class="cve-id">{res.cve.id}</span>
                      </div>
                      <p class="cve-desc-small">Resolved by upgrading <code class="monospace">{res.component}</code></p>
                    </div>
                  {/each}
                </div>
              {/if}
            {:else}
              <p class="no-diff-data">No vulnerability signature changes detected between SBOM datasets.</p>
            {/if}
          </div>
        </div>
      </div>
    </div>
  {:else if activeSubTab === 'LICENSES'}
    <div class="licenses-dashboard">
      <div class="panel glass-card">
        <div class="panel-header">
          <h4>GLOBAL LICENSE INVENTORY</h4>
        </div>
        <div class="panel-content scrollable-panel">
          <table class="dense-table">
            <thead>
              <tr>
                <th>LICENSE EXPRESSION</th>
                <th>AUDIT STATUS</th>
                <th>USAGE FREQUENCY</th>
                <th>AFFECTED COMPONENTS</th>
              </tr>
            </thead>
            <tbody>
              {#each licenseGroups as group}
                <tr>
                  <td class="license-expr">{group.license}</td>
                  <td>
                    <span class="compliance-badge {getComplianceClass(group.audit.risk)}">
                      <span class="status-light"></span>
                      {group.audit.risk.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <span class="font-mono">{group.components.length} components</span>
                  </td>
                  <td class="component-list-td">
                    <div class="component-list">
                      {#each group.components.slice(0, 10) as comp}
                        <span class="comp-chip" on:click={() => selectItem(comp)} role="button" tabindex="0">{comp.name}</span>
                      {/each}
                      {#if group.components.length > 10}
                        <span class="comp-chip more">+{group.components.length - 10} more</span>
                      {/if}
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .dashboard {
    flex: 1;
    overflow-y: auto;
    padding: 24px 32px;
    background: transparent;
    font-family: var(--font-sans);
  }

  .glass-card {
    background: var(--bg-panel);
    border: 1px solid var(--border-subtle);
    border-radius: 16px;
    backdrop-filter: blur(var(--blur-intensity));
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
    transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  }

  .glass-card:hover {
    border-color: var(--border-hover);
    box-shadow: 0 8px 32px rgba(255, 255, 255, 0.02), var(--glass-shadow);
  }

  .dashboard-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 24px;
  }

  .panel {
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .heatmap-panel {
    grid-column: span 2;
  }

  .panel-header {
    padding: 16px 24px;
    border-bottom: 1px solid var(--border-subtle);
    background: rgba(0, 0, 0, 0.1);
  }

  .panel-header h4 {
    margin: 0;
    font-family: var(--font-display);
    font-size: 11px;
    font-weight: 700;
    color: var(--text-secondary);
    letter-spacing: 0.8px;
  }

  .panel-content {
    padding: 24px;
    flex: 1;
  }

  .matrix-grid {
    display: grid;
    grid-template-columns: 100px repeat(3, 1fr);
    gap: 8px;
    background: rgba(0, 0, 0, 0.2);
    padding: 12px;
    border-radius: 12px;
    border: 1px solid var(--border-subtle);
  }

  .matrix-cell {
    background: rgba(255, 255, 255, 0.01);
    height: 72px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    border: 1px solid var(--border-subtle);
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  }

  .matrix-cell.has-items { cursor: pointer; }
  .matrix-cell.has-items:hover { transform: scale(1.02); box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4); z-index: 5; }
  
  .matrix-cell.HH.has-items { background: rgba(255, 255, 255, 0.12); border-color: #ffffff; box-shadow: 0 0 10px rgba(255, 255, 255, 0.2); }
  .matrix-cell.HM.has-items { background: rgba(255, 255, 255, 0.09); border-color: rgba(255, 255, 255, 0.7); }
  .matrix-cell.HL.has-items { background: rgba(255, 255, 255, 0.06); border-color: rgba(255, 255, 255, 0.45); }
  .matrix-cell.MH.has-items { background: rgba(255, 255, 255, 0.09); border-color: rgba(255, 255, 255, 0.65); }
  .matrix-cell.MM.has-items { background: rgba(255, 255, 255, 0.07); border-color: rgba(255, 255, 255, 0.45); }
  .matrix-cell.ML.has-items { background: rgba(255, 255, 255, 0.04); border-color: rgba(255, 255, 255, 0.25); }
  .matrix-cell.LH.has-items { background: rgba(255, 255, 255, 0.04); border-color: rgba(255, 255, 255, 0.3); }
  .matrix-cell.LM.has-items { background: rgba(255, 255, 255, 0.02); border-color: rgba(255, 255, 255, 0.15); }
  .matrix-cell.LL.has-items { background: rgba(255, 255, 255, 0.01); border-color: rgba(255, 255, 255, 0.1); }

  .cell-count { font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); }

  .glass-popover {
    display: none;
    position: absolute;
    bottom: 110%;
    left: 50%;
    transform: translateX(-50%);
    background: rgba(18, 20, 26, 0.95);
    border: 1px solid var(--border-hover);
    border-radius: 12px;
    padding: 12px;
    z-index: 100;
    width: 220px;
    backdrop-filter: blur(20px);
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
  }

  .matrix-cell.has-items:hover .glass-popover { display: block; }

  .popover-title {
    font-family: var(--font-display);
    font-size: 9px;
    font-weight: 700;
    color: var(--text-secondary);
    letter-spacing: 0.5px;
    display: block;
    margin-bottom: 8px;
    border-bottom: 1px solid var(--border-subtle);
    padding-bottom: 4px;
  }

  .pop-item {
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-secondary);
    padding: 6px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    text-align: left;
    cursor: pointer;
  }

  .pop-item:hover { color: var(--text-primary); }

  .axis-label {
    font-family: var(--font-mono);
    font-size: 9px;
    color: var(--text-secondary);
    font-weight: 600;
    display: flex;
    align-items: center;
  }

  .axis-label.y-axis { justify-content: flex-end; padding-right: 14px; text-align: right; }
  .axis-label.x-axis { justify-content: center; padding-top: 8px; }
  .matrix-hint { font-size: 11px; color: var(--text-muted); margin-top: 14px; margin-bottom: 0; font-style: italic; }

  .dense-table { width: 100%; border-collapse: collapse; }
  .dense-table th, .dense-table td { padding: 12px 16px; text-align: left; font-size: 12px; border-bottom: 1px solid var(--border-subtle); }
  .dense-table th { font-family: var(--font-display); font-size: 10px; font-weight: 700; color: var(--text-secondary); letter-spacing: 0.8px; background: rgba(0, 0, 0, 0.15); }
  .dense-table td { color: var(--text-secondary); font-family: var(--font-mono); }
  .interactive-row { cursor: pointer; transition: background 0.2s cubic-bezier(0.16, 1, 0.3, 1); }
  .interactive-row:hover { background: rgba(255, 255, 255, 0.02); }

  .comp-cell-layout { display: flex; align-items: center; gap: 8px; }
  .comp-title { color: var(--text-primary); font-weight: 600; }
  .comp-ver { font-size: 10px; color: var(--text-secondary); }

  .cisa-kev-badge {
    background: rgba(255, 69, 58, 0.12);
    color: var(--color-critical);
    font-size: 9px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 6px;
    border: 1px solid rgba(255, 69, 58, 0.2);
    font-family: var(--font-display);
    animation: pulse 2s infinite;
  }

  .stale-badge {
    background: rgba(255, 159, 10, 0.12);
    color: var(--color-warning);
    font-size: 9px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 6px;
    border: 1px solid rgba(255, 159, 10, 0.2);
    font-family: var(--font-display);
  }

  .stale-badge.ancient {
    background: rgba(255, 69, 58, 0.08);
    color: #ff3b30;
    border-color: rgba(255, 69, 58, 0.15);
  }

  .badge.cvss-badge {
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 6px;
  }

  /* Blast radius fill bar */
  .br-indicator-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 120px;
  }

  .br-fill {
    height: 4px;
    background: var(--text-muted);
    border-radius: 2px;
  }

  /* Compliance status badges */
  .compliance-badge {
    font-size: 10px;
    font-weight: 700;
    padding: 4px 12px;
    border-radius: 9999px;
    font-family: var(--font-display);
    letter-spacing: 0.5px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .status-light {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
    display: inline-block;
  }

  .comp-compliant { background: rgba(52, 199, 89, 0.08); color: var(--color-ok); border: 1px solid rgba(52, 199, 89, 0.15); }
  .comp-restricted { background: rgba(255, 159, 10, 0.08); color: var(--color-warning); border: 1px solid rgba(255, 159, 10, 0.15); }
  .comp-blocked { background: rgba(255, 69, 58, 0.08); color: var(--color-critical); border: 1px solid rgba(255, 69, 58, 0.15); }
  .comp-unknown { background: var(--bg-active); color: var(--text-secondary); border: 1px solid var(--border-subtle); }

  .license-expr {
    max-width: 250px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text-primary);
  }
</style>
