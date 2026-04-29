<script>
  import { createEventDispatcher } from 'svelte'
  
  export let node
  
  const dispatch = createEventDispatcher()
  
  function handleClose() {
    dispatch('close')
  }
  
  function getRiskColor(score) {
    if (score >= 8) return '#FF2A6D'
    if (score >= 4) return '#F7E018'
    return '#05D9E8'
  }
  
  function getRiskLabel(score) {
    if (score >= 8) return 'CRITICAL'
    if (score >= 4) return 'WARNING'
    return 'OK'
  }
</script>

<aside class="sidebar">
  <div class="sidebar-header">
    <div class="risk-indicator" style="background: {getRiskColor(node.score || 0)}"></div>
    <div class="title-section">
      <h2 class="package-name">{node.name}</h2>
      <span class="package-version">v{node.version}</span>
    </div>
    <button class="close-btn" on:click={handleClose}>✕</button>
  </div>
  
  <div class="sidebar-content">
    <div class="score-section">
      <div class="score-circle" style="border-color: {getRiskColor(node.score || 0)}">
        <span class="score-value" style="color: {getRiskColor(node.score || 0)}">
          {(node.score || 0).toFixed(1)}
        </span>
        <span class="score-label">Risk Score</span>
      </div>
      
      <span class="risk-badge" style="background: {getRiskColor(node.score || 0)}20; color: {getRiskColor(node.score || 0)}; border-color: {getRiskColor(node.score || 0)}40">
        {getRiskLabel(node.score || 0)}
      </span>
    </div>
    
    {#if node.licenses && node.licenses.length > 0}
      <div class="section">
        <h3>📄 License</h3>
        <div class="license-badge">
          {node.licenses[0].license.id || node.licenses[0].license.name || 'Unknown'}
        </div>
      </div>
    {/if}
    
    {#if node.cves && node.cves.length > 0}
      <div class="section">
        <h3>🚨 CVEs ({node.cves.length})</h3>
        <div class="cve-list">
          {#each node.cves as cve}
            <div class="cve-item">
              <a href="https://nvd.nist.gov/vuln/detail/{cve.id}" target="_blank" class="cve-link">
                {cve.id}
              </a>
              <span class="cve-severity" style="color: {getRiskColor(cve.cvss_score || 5)}">
                {cve.severity || 'UNKNOWN'}
              </span>
              <span class="cve-score">{cve.cvss_score?.toFixed(1) || 'N/A'}</span>
            </div>
          {/each}
        </div>
      </div>
    {:else}
      <div class="section">
        <h3>🚨 CVEs</h3>
        <p class="no-data">No known CVEs</p>
      </div>
    {/if}
    
    {#if node.description}
      <div class="section">
        <h3>📝 Description</h3>
        <p class="description">{node.description}</p>
      </div>
    {/if}
    
    <div class="section">
      <h3>📊 Details</h3>
      <div class="detail-grid">
        <div class="detail-item">
          <span class="detail-label">Type</span>
          <span class="detail-value">{node.component_type || 'library'}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">PURL</span>
          <span class="detail-value purl">{node.purl || 'N/A'}</span>
        </div>
        {#if node.publisher}
          <div class="detail-item">
            <span class="detail-label">Publisher</span>
            <span class="detail-value">{node.publisher}</span>
          </div>
        {/if}
      </div>
    </div>
  </div>
</aside>

<style>
  .sidebar {
    width: 340px;
    background: #12121F;
    border-left: 1px solid #1A1A2E;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    animation: slideIn 0.3s ease;
  }
  
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  
  .sidebar-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 20px;
    border-bottom: 1px solid #1A1A2E;
  }
  
  .risk-indicator {
    width: 4px;
    height: 40px;
    border-radius: 2px;
    flex-shrink: 0;
  }
  
  .title-section {
    flex: 1;
    min-width: 0;
  }
  
  .package-name {
    font-family: 'JetBrains Mono', monospace;
    font-size: 16px;
    font-weight: 600;
    color: #E0E0E0;
    margin: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  
  .package-version {
    font-size: 12px;
    color: #8A8AA3;
    font-family: 'JetBrains Mono', monospace;
  }
  
  .close-btn {
    width: 28px;
    height: 28px;
    border-radius: 4px;
    border: 1px solid #1A1A2E;
    background: transparent;
    color: #8A8AA3;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.2s;
  }
  
  .close-btn:hover {
    border-color: #FF2A6D;
    color: #FF2A6D;
  }
  
  .sidebar-content {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
  }
  
  .score-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 20px;
    background: #0A0A0F;
    border-radius: 8px;
    margin-bottom: 20px;
  }
  
  .score-circle {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    border: 3px solid;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 2px;
  }
  
  .score-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 32px;
    font-weight: 700;
  }
  
  .score-label {
    font-size: 11px;
    color: #8A8AA3;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  
  .risk-badge {
    padding: 4px 16px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
    border: 1px solid;
  }
  
  .section {
    margin-bottom: 20px;
  }
  
  .section h3 {
    font-size: 12px;
    font-weight: 600;
    color: #8A8AA3;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 12px;
  }
  
  .license-badge {
    display: inline-block;
    padding: 6px 12px;
    background: #1A1A2E;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #05D9E8;
  }
  
  .cve-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  
  .cve-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    background: #0A0A0F;
    border-radius: 4px;
    border-left: 2px solid #FF2A6D;
  }
  
  .cve-link {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #05D9E8;
    text-decoration: none;
  }
  
  .cve-link:hover {
    text-decoration: underline;
  }
  
  .cve-severity {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
  }
  
  .cve-score {
    margin-left: auto;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #8A8AA3;
  }
  
  .no-data {
    font-size: 13px;
    color: #8A8AA3;
    font-style: italic;
  }
  
  .description {
    font-size: 13px;
    color: #8A8AA3;
    line-height: 1.6;
  }
  
  .detail-grid {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  
  .detail-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid #1A1A2E;
  }
  
  .detail-label {
    font-size: 12px;
    color: #8A8AA3;
  }
  
  .detail-value {
    font-size: 12px;
    color: #E0E0E0;
    font-family: 'JetBrains Mono', monospace;
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  
  .detail-value.purl {
    font-size: 10px;
  }
</style>
