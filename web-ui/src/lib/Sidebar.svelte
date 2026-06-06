<script>
  import { createEventDispatcher } from 'svelte'
  
  export let node
  export let rules
  
  const dispatch = createEventDispatcher()
  
  let activeTab = 'OVERVIEW' // OVERVIEW, DEPENDENCIES, REMEDIATION, RAW
  export let ignoredCveIds = new Set()
  
  function handleClose() {
    dispatch('close')
  }
  
  function toggleIgnoreCve(cveId) {
    dispatch('toggleIgnoreCve', { cveId })
  }
  
  function getScoreColor(val) {
    if (val >= 6.0) return '#D50000'
    if (val >= 3.0) return '#FFB300'
    return '#00E676'
  }
  
  function getScoreLabel(val) {
    if (val >= 6.0) return 'CRITICAL EXPOSURE'
    if (val >= 3.0) return 'WARNING RISK'
    return 'SECURE'
  }

  function getLicenseName(n) {
    if (n.license) return n.license
    if (n.licenses && n.licenses.length > 0) {
      return n.licenses[0].license.id || n.licenses[0].license.name || 'Unknown'
    }
    return 'Unknown'
  }

  // Get mock target remediation version
  $: targetUpgrade = (() => {
    if (node.cves && node.cves.length > 0) {
      const fixed = node.cves.find(c => c.fixed_version)?.fixed_version
      if (fixed) return fixed
    }
    // generic fallback
    const parts = node.version.split('.')
    if (parts.length === 3) {
      const patch = parseInt(parts[2])
      if (!isNaN(patch)) return `${parts[0]}.${parts[1]}.${patch + 1}`
    }
    return null
  })()

  function downloadRemediationScript() {
    const targetVer = targetUpgrade || 'latest'
    let scriptContent = `#!/bin/bash\n`
    scriptContent += `# ZertTree Actionable Remediation Patching Script\n`
    scriptContent += `# Target: Resolve vulnerabilities in ${node.name}\n\n`
    scriptContent += `echo "Remediating ${node.name} from v${node.version} to v${targetVer}..."\n`
    
    if (node.purl?.includes('pkg:npm/')) {
      const parts = node.purl.split('@')
      const name = parts[0].replace('pkg:npm/', '')
      scriptContent += `npm install ${name}@${targetVer}\n`
    } else if (node.purl?.includes('pkg:cargo/')) {
      const parts = node.purl.split('@')
      const name = parts[0].replace('pkg:cargo/', '')
      scriptContent += `cargo add ${name}@${targetVer}\n`
    } else if (node.purl?.includes('pkg:pypi/')) {
      const parts = node.purl.split('@')
      const name = parts[0].replace('pkg:pypi/', '')
      scriptContent += `pip install ${name}==${targetVer}\n`
    } else {
      scriptContent += `# Package type not recognized automatically. Manual update required:\n`
      scriptContent += `# Upgrade ${node.name} to ${targetVer}\n`
    }
    
    scriptContent += `echo "Remediation command executed. Re-run SBOM scan to verify."\n`
    
    const blob = new Blob([scriptContent], { type: 'text/x-shellscript' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `remediate-${node.name.replace(/\//g, '-')}.sh`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }
</script>

<aside class="sidebar">
  <div class="sidebar-header">
    <div class="status-marker" style="background: {getScoreColor(node.cascadingScore || node.score || 0)}"></div>
    <div class="title-section">
      <h2 class="package-name">{node.name}</h2>
      <span class="package-version">VERSION {node.version}</span>
    </div>
    <button class="close-btn" on:click={handleClose}>✕</button>
  </div>
  
  <!-- Tab navigation -->
  <div class="tab-bar">
    <button class="tab-btn" class:active={activeTab === 'OVERVIEW'} on:click={() => activeTab = 'OVERVIEW'}>OVERVIEW</button>
    <button class="tab-btn" class:active={activeTab === 'DEPENDENCIES'} on:click={() => activeTab = 'DEPENDENCIES'}>RELATIONS</button>
    <button class="tab-btn" class:active={activeTab === 'REMEDIATION'} on:click={() => activeTab = 'REMEDIATION'}>REMEDIATION</button>
    <button class="tab-btn" class:active={activeTab === 'RAW'} on:click={() => activeTab = 'RAW'}>TELEMETRY</button>
  </div>
  
  <div class="sidebar-content">
    {#if activeTab === 'OVERVIEW'}
      <div class="score-card">
        <span class="score-num" style="color: {getScoreColor(node.cascadingScore || node.score || 0)}">
          {(node.cascadingScore || node.score || 0).toFixed(1)}
        </span>
        <span class="score-label">CASCADING EXPOSURE RISK</span>
        <span class="status-badge" style="background: {getScoreColor(node.cascadingScore || node.score || 0)}10; color: {getScoreColor(node.cascadingScore || node.score || 0)}; border: 1px solid {getScoreColor(node.cascadingScore || node.score || 0)}30">
          {getScoreLabel(node.cascadingScore || node.score || 0)}
        </span>
      </div>

      {#if node.staleInfo}
        <div class="stale-card" class:ancient={node.staleInfo.ancient}>
          <span class="stale-icon">⏳</span>
          <div class="stale-details">
            <h4>{node.staleInfo.ancient ? 'ANCIENT RELEASE' : 'STALE RELEASE'}</h4>
            <p>Published on {node.staleInfo.releaseDate} ({node.staleInfo.ageYears.toFixed(1)} years ago). Maintenance risk is elevated.</p>
          </div>
        </div>
      {/if}
      
      <!-- Quick metrics grid -->
      <div class="metrics-grid">
        <div class="metric-box">
          <span class="val">{node.blastRadius || 0}</span>
          <span class="lbl">Blast Radius</span>
        </div>
        <div class="metric-box">
          <span class="val">{getLicenseName(node)}</span>
          <span class="lbl">License Expression</span>
        </div>
        <div class="metric-box">
          <span class="val">{node.cves?.length || 0}</span>
          <span class="lbl">CVE Detections</span>
        </div>
      </div>
      
      <!-- Vulnerabilities list -->
      <div class="section">
        <h3 class="sec-title">Vulnerability Telemetry</h3>
        {#if node.cves && node.cves.length > 0}
          <div class="cve-list">
            {#each node.cves as cve}
              {@const isIgnored = ignoredCveIds.has(cve.id)}
              <div class="cve-item" class:ignored={isIgnored}>
                <div class="cve-head">
                  <span class="cve-id">{cve.id}</span>
                  <span class="epss-badge">EPSS {(cve.epss_score * 100).toFixed(1)}%</span>
                  <span class="cve-cvss" style="color: {isIgnored ? 'var(--text-muted)' : getScoreColor(cve.cvss_score || 5)}">
                    CVSS {cve.cvss_score?.toFixed(1) || 'N/A'}
                  </span>
                </div>
                {#if cve.is_cisa_kev}
                  <div class="kev-alert-banner">
                    <span class="kev-alert-title">⚠️ CISA KNOWN EXPLOITED VULNERABILITY</span>
                    <p class="kev-alert-text">CISA confirms this vulnerability is actively exploited in the wild. Immediate remediation required.</p>
                  </div>
                {/if}
                <p class="cve-desc">{cve.description}</p>
                <div class="cve-footer">
                  <button class="mute-btn" on:click={() => toggleIgnoreCve(cve.id)}>
                    {isIgnored ? 'ACTIVATE' : 'MUTE EXPOSURE'}
                  </button>
                </div>
              </div>
            {/each}
          </div>
        {:else}
          <p class="no-data">No vulnerability signatures detected in OSV database.</p>
        {/if}
      </div>
      
    {:else if activeTab === 'DEPENDENCIES'}
      <div class="section">
        <h3 class="sec-title">UPSTREAM DEPENDENTS (BLAST RADIUS)</h3>
        <p class="section-desc">These components will be impacted if this package is compromised:</p>
        {#if node.blastRadius > 0}
          <div class="relations-list">
            <span class="relation-badge parent-badge">{node.blastRadius} parent packages impacted</span>
          </div>
        {:else}
          <p class="no-data">This component is a leaf node; no upstream dependents affected.</p>
        {/if}
      </div>

      <div class="section">
        <h3 class="sec-title">DOWNSTREAM DEPENDENCIES</h3>
        <p class="section-desc">Direct dependencies imported by this component:</p>
        {#if node.dependenciesCount > 0}
          <div class="relations-list">
            <span class="relation-badge child-badge">Relies on {node.dependenciesCount} downstream packages</span>
          </div>
        {:else}
          <p class="no-data">This component has no downstream dependencies.</p>
        {/if}
      </div>
      
    {:else if activeTab === 'REMEDIATION'}
      <div class="remediation-flow">
        <h3 class="sec-title">Remediation Upgrade Path</h3>
        
        {#if node.cves && node.cves.length > 0}
          <div class="remedy-card">
            <div class="remedy-step">
              <span class="step-num">CURRENT</span>
              <span class="step-desc monospace">{node.name}@{node.version}</span>
            </div>
            
            <div class="remedy-arrow">↓</div>
            
            <div class="remedy-step success">
              <span class="step-num target">RECOMMENDED</span>
              <span class="step-desc monospace">{node.name}@{targetUpgrade || 'Latest Patch'}</span>
            </div>
            
            <div class="remedy-audit">
              <span class="audit-status">UPGRADE RECOMMENDED</span>
              <p>Upgrading to version <code class="monospace">{targetUpgrade || 'Latest Patch'}</code> resolves all CVSS detections for this asset branch.</p>
              <button class="patch-btn" on:click={downloadRemediationScript}>
                📥 DOWNLOAD REMEDIATION SCRIPT
              </button>
            </div>
          </div>
        {:else}
          <div class="remedy-clean">
            <span class="shield-icon">🛡️</span>
            <h4>NO REMEDIATION REQUIRED</h4>
            <p>Asset matches all active security policy definitions.</p>
          </div>
        {/if}
      </div>
      
    {:else if activeTab === 'RAW'}
      <div class="telemetry-log">
        <h3 class="sec-title">RAW TELEMETRY inspect</h3>
        <pre class="json-code"><code>{JSON.stringify({
          name: node.name,
          version: node.version,
          purl: node.purl,
          score: node.score,
          cascadingScore: node.cascadingScore,
          blastRadius: node.blastRadius,
          dependenciesCount: node.dependenciesCount,
          license: getLicenseName(node),
          cves: node.cves
        }, null, 2)}</code></pre>
      </div>
    {/if}
  </div>
</aside>

<style>
  .sidebar {
    width: 390px;
    background: var(--bg-panel);
    border-left: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    z-index: 90;
    backdrop-filter: blur(var(--blur-intensity));
  }
  
  @keyframes slideIn {
    from { transform: translateX(100%); }
    to { transform: translateX(0); }
  }
  
  .sidebar-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 18px 24px;
    border-bottom: 1px solid var(--border-subtle);
    background: rgba(25, 28, 36, 0.3);
  }
  
  .status-marker {
    width: 4px;
    height: 36px;
    border-radius: 2px;
    flex-shrink: 0;
  }
  
  .title-section {
    flex: 1;
    min-width: 0;
  }
  
  .package-name {
    font-family: var(--font-display);
    font-size: 16px;
    font-weight: 700;
    color: var(--text-primary);
    margin: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    letter-spacing: -0.2px;
  }
  
  .package-version {
    font-size: 10px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-weight: 600;
  }
  
  .close-btn {
    width: 26px;
    height: 26px;
    border-radius: 50%;
    border: 1px solid var(--border-subtle);
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 10px;
    transition: all 0.2s;
  }
  
  .close-btn:hover {
    border-color: var(--border-hover);
    color: var(--text-primary);
    background: var(--bg-active);
  }
  
  /* Tab bar */
  .tab-bar {
    display: flex;
    background: rgba(0, 0, 0, 0.15);
    border-bottom: 1px solid var(--border-subtle);
    padding: 0 6px;
  }
  
  .tab-btn {
    flex: 1;
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 10px;
    font-family: var(--font-display);
    font-weight: 700;
    padding: 12px 0;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
    letter-spacing: 0.5px;
  }
  
  .tab-btn:hover {
    color: var(--text-primary);
  }
  
  .tab-btn.active {
    color: var(--text-primary);
    border-bottom-color: var(--text-primary);
  }
  
  .sidebar-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }
  
  /* Score card */
  .score-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 24px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    margin-bottom: 20px;
  }
  
  .score-num {
    font-family: var(--font-mono);
    font-size: 48px;
    font-weight: 700;
    line-height: 1;
  }
  
  .score-label {
    font-size: 9px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-weight: 700;
    margin-top: 8px;
    letter-spacing: 0.5px;
  }
  
  .status-badge {
    margin-top: 12px;
    font-size: 9px;
    font-weight: 700;
    padding: 4px 12px;
    border-radius: 999px;
    font-family: var(--font-display);
    letter-spacing: 0.5px;
  }
  
  /* Stale Package Card */
  .stale-card {
    display: flex;
    gap: 12px;
    background: rgba(255, 159, 10, 0.08);
    border: 1px solid rgba(255, 159, 10, 0.15);
    padding: 12px 16px;
    border-radius: 12px;
    margin-bottom: 20px;
    color: var(--color-warning);
  }

  .stale-card.ancient {
    background: rgba(255, 69, 58, 0.08);
    border-color: rgba(255, 69, 58, 0.15);
    color: var(--color-critical);
  }

  .stale-icon {
    font-size: 18px;
    margin-top: 2px;
  }

  .stale-details h4 {
    margin: 0 0 4px 0;
    font-family: var(--font-display);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
  }

  .stale-details p {
    margin: 0;
    font-size: 11px;
    line-height: 1.4;
    color: var(--text-secondary);
  }

  /* Metrics grid */
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin-bottom: 24px;
  }
  
  .metric-box {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 12px 6px;
    text-align: center;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 6px;
  }
  
  .metric-box .val {
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  
  .metric-box .lbl {
    font-size: 9px;
    color: var(--text-secondary);
    font-family: var(--font-display);
    font-weight: 700;
  }
  
  .section {
    margin-bottom: 24px;
  }
  
  .sec-title {
    font-family: var(--font-display);
    font-size: 11px;
    font-weight: 700;
    color: var(--text-secondary);
    letter-spacing: 0.8px;
    margin-top: 0;
    margin-bottom: 14px;
    border-bottom: 1px solid var(--border-subtle);
    padding-bottom: 6px;
    text-transform: uppercase;
  }

  .section-desc {
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 0;
    margin-bottom: 12px;
    line-height: 1.5;
  }
  
  .cve-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  
  .cve-item {
    background: rgba(0, 0, 0, 0.15);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    transition: border-color 0.2s;
  }

  .cve-item:hover {
    border-color: var(--border-hover);
  }

  .cve-item.ignored {
    opacity: 0.4;
  }
  
  .cve-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  
  .cve-id {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 600;
    color: var(--text-primary);
  }
  
  .epss-badge {
    font-family: var(--font-mono);
    font-size: 9px;
    color: var(--text-secondary);
    background: var(--bg-active);
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid var(--border-subtle);
  }
  
  .cve-cvss {
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 700;
  }

  /* KEV Banner inside CVE item */
  .kev-alert-banner {
    background: rgba(255, 69, 58, 0.08);
    border: 1px solid rgba(255, 69, 58, 0.2);
    border-radius: 8px;
    padding: 10px 12px;
    color: var(--color-critical);
  }

  .kev-alert-title {
    font-family: var(--font-display);
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.5px;
    display: block;
    margin-bottom: 4px;
  }

  .kev-alert-text {
    margin: 0;
    font-size: 10px;
    line-height: 1.4;
    color: var(--text-secondary);
  }
  
  .cve-desc {
    font-size: 12px;
    color: var(--text-secondary);
    line-height: 1.5;
    margin: 0;
  }

  .cve-footer {
    display: flex;
    justify-content: flex-end;
  }

  .mute-btn {
    background: transparent;
    border: 1px dashed var(--border-hover);
    color: var(--text-secondary);
    font-size: 9px;
    font-family: var(--font-mono);
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
  }

  .mute-btn:hover {
    border-color: var(--text-primary);
    color: var(--text-primary);
    background: var(--bg-active);
  }
  
  .no-data {
    font-size: 11px;
    color: var(--text-muted);
    font-style: italic;
  }

  /* Relations list */
  .relations-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .relation-badge {
    padding: 8px 16px;
    border-radius: 8px;
    font-family: var(--font-mono);
    font-size: 11px;
    text-align: center;
    border: 1px solid;
  }

  .parent-badge {
    background: rgba(255, 159, 10, 0.05);
    color: var(--color-warning);
    border-color: rgba(255, 159, 10, 0.15);
  }

  .child-badge {
    background: rgba(48, 176, 199, 0.05);
    color: #30b0c7;
    border-color: rgba(48, 176, 199, 0.15);
  }

  /* Remediation guide styles */
  .remediation-flow {
    display: flex;
    flex-direction: column;
  }

  .remedy-card {
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 20px;
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  .remedy-step {
    width: 100%;
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-subtle);
    padding: 12px 16px;
    border-radius: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .remedy-step.success {
    border-color: rgba(52, 199, 89, 0.2);
    background: rgba(52, 199, 89, 0.02);
  }

  .step-num {
    font-size: 9px;
    font-family: var(--font-display);
    font-weight: 700;
    color: var(--text-muted);
    letter-spacing: 0.5px;
  }

  .step-num.target {
    color: var(--color-ok);
  }

  .step-desc {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .remedy-arrow {
    font-size: 18px;
    color: var(--text-muted);
    margin: 8px 0;
  }

  .remedy-audit {
    width: 100%;
    margin-top: 18px;
    border-top: 1px solid var(--border-subtle);
    padding-top: 18px;
  }

  .audit-status {
    font-size: 9px;
    font-family: var(--font-display);
    font-weight: 700;
    color: var(--color-ok);
    letter-spacing: 0.5px;
    background: rgba(52, 199, 89, 0.1);
    padding: 3px 8px;
    border-radius: 4px;
  }

  .remedy-audit p {
    font-size: 11px;
    color: var(--text-secondary);
    margin: 10px 0 0 0;
    line-height: 1.5;
  }

  .remedy-audit p code {
    background: var(--bg-active);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 10px;
    color: var(--text-primary);
  }

  .remedy-clean {
    text-align: center;
    padding: 48px 24px;
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
  }

  .shield-icon {
    font-size: 32px;
    display: block;
    margin-bottom: 12px;
  }

  .remedy-clean h4 {
    font-family: var(--font-display);
    font-size: 13px;
    font-weight: 700;
    color: var(--color-ok);
    margin: 0 0 6px 0;
  }

  .remedy-clean p {
    font-size: 11px;
    color: var(--text-secondary);
    margin: 0;
  }

  /* Raw JSON Telemetry */
  .telemetry-log {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .json-code {
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid var(--border-subtle);
    border-radius: 12px;
    padding: 16px;
    overflow: auto;
    font-size: 10px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    max-height: 520px;
    margin: 0;
  }

  .patch-btn {
    width: 100%;
    margin-top: 14px;
    background: var(--bg-active);
    border: 1px solid var(--border-subtle);
    color: var(--text-primary);
    font-size: 10px;
    font-family: var(--font-mono);
    font-weight: 700;
    padding: 8px 12px;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    letter-spacing: 0.3px;
  }

  .patch-btn:hover {
    background: rgba(255, 255, 255, 0.1);
    border-color: var(--border-hover);
    box-shadow: 0 4px 12px rgba(255, 255, 255, 0.02);
  }
</style>
