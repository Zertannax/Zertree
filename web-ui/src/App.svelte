<script>
  import { onMount } from 'svelte'
  import Graph from './lib/Graph.svelte'
  import Sidebar from './lib/Sidebar.svelte'
  import Header from './lib/Header.svelte'
  import FilmMode from './lib/FilmMode.svelte'
  
  let sbomData = null
  let selectedNode = null
  let filmMode = false
  let showUpload = true
  
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
    // CycloneDX format (pass through)
    return data
  }

  function handleFileUpload(event) {
    const file = event.detail
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const raw = JSON.parse(e.target.result)
        sbomData = normalizeSbom(raw)
        showUpload = false
      } catch (err) {
        alert('Invalid SBOM JSON file')
      }
    }
    reader.readAsText(file)
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
    selectedNode = null
    showUpload = true
    filmMode = false
  }
</script>

{#if showUpload}
  <div class="landing">
    <div class="particles">
      {#each Array(30) as _, i}
        <div class="particle" style="
          left: {Math.random() * 100}%;
          top: {Math.random() * 100}%;
          animation-delay: {Math.random() * 5}s;
          animation-duration: {3 + Math.random() * 4}s;
        "></div>
      {/each}
    </div>
    
    <header class="landing-header">
      <div class="logo">
        <svg viewBox="0 0 40 40" width="40" height="40">
          <circle cx="20" cy="10" r="6" fill="#05D9E8" opacity="0.9"/>
          <circle cx="10" cy="28" r="5" fill="#FF2A6D" opacity="0.8"/>
          <circle cx="30" cy="28" r="5" fill="#F7E018" opacity="0.8"/>
          <line x1="20" y1="16" x2="10" y2="23" stroke="#1A1A2E" stroke-width="1.5"/>
          <line x1="20" y1="16" x2="30" y2="23" stroke="#1A1A2E" stroke-width="1.5"/>
          <line x1="10" y1="33" x2="30" y2="33" stroke="#1A1A2E" stroke-width="1.5"/>
        </svg>
        <span class="logo-text">ZertTree</span>
      </div>
      <a href="https://github.com/zertannax/zertree" target="_blank" class="github-link">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
        </svg>
        GitHub
      </a>
    </header>
    
    <main class="hero">
      <h1 class="title">See the forest<br/>through the trees</h1>
      <p class="subtitle">Transform your SBOM into an interactive risk map</p>
      
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
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#05D9E8" stroke-width="1.5">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
            <polyline points="17 8 12 3 7 8"/>
            <line x1="12" y1="3" x2="12" y2="15"/>
          </svg>
          <span class="upload-text">Drop your SBOM here</span>
          <span class="upload-hint">or click to browse (CycloneDX JSON)</span>
        </label>
      </div>
      
      <div class="stats">
        <div class="stat">
          <span class="stat-number">12,847</span>
          <span class="stat-label">SBOMs analyzed</span>
        </div>
        <div class="stat">
          <span class="stat-number">2.4M</span>
          <span class="stat-label">Components scanned</span>
        </div>
        <div class="stat">
          <span class="stat-number">89K</span>
          <span class="stat-label">CVEs detected</span>
        </div>
      </div>
    </main>
    
    <footer class="landing-footer">
      <span>v0.1.0</span>
      <span>•</span>
      <span>CycloneDX &amp; SPDX</span>
      <span>•</span>
      <span>Rust + Svelte</span>
    </footer>
  </div>
{:else}
  <div class="app">
    <Header 
      {sbomData}
      on:reset={handleReset}
      on:toggleFilm={toggleFilmMode}
      {filmMode}
    />
    
    <div class="main-content">
      <Graph 
        {sbomData}
        on:nodeSelect={handleNodeSelect}
        {filmMode}
      />
      
      {#if selectedNode}
        <Sidebar 
          node={selectedNode}
          on:close={handleCloseSidebar}
        />
      {/if}
    </div>
    
    {#if filmMode}
      <FilmMode />
    {/if}
  </div>
{/if}

<style>
  .landing {
    width: 100vw;
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: #0A0A0F;
    position: relative;
    overflow: hidden;
  }
  
  .particles {
    position: absolute;
    inset: 0;
    pointer-events: none;
    z-index: 0;
  }
  
  .particle {
    position: absolute;
    width: 2px;
    height: 2px;
    background: #05D9E8;
    border-radius: 50%;
    opacity: 0;
    animation: float linear infinite;
  }
  
  @keyframes float {
    0% { opacity: 0; transform: translateY(0) scale(0); }
    10% { opacity: 0.6; }
    90% { opacity: 0.6; }
    100% { opacity: 0; transform: translateY(-100vh) scale(1); }
  }
  
  .landing-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 24px 40px;
    z-index: 1;
  }
  
  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  
  .logo-text {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 24px;
    font-weight: 700;
    color: #05D9E8;
    letter-spacing: -0.5px;
  }
  
  .github-link {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #8A8AA3;
    text-decoration: none;
    font-size: 14px;
    transition: color 0.2s;
  }
  
  .github-link:hover {
    color: #05D9E8;
  }
  
  .hero {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 40px;
    z-index: 1;
    padding: 0 20px;
  }
  
  .title {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 56px;
    font-weight: 700;
    text-align: center;
    color: #E0E0E0;
    line-height: 1.1;
    letter-spacing: -1px;
  }
  
  .subtitle {
    font-size: 18px;
    color: #8A8AA3;
    text-align: center;
  }
  
  .upload-zone {
    width: 100%;
    max-width: 480px;
    height: 200px;
    border: 2px dashed #1A1A2E;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all 0.3s;
    background: #12121F;
  }
  
  .upload-zone:hover {
    border-color: #05D9E8;
    background: #1A1A2E;
    box-shadow: 0 0 30px rgba(5, 217, 232, 0.1);
  }
  
  .upload-label {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    cursor: pointer;
  }
  
  .upload-text {
    font-size: 16px;
    color: #E0E0E0;
    font-weight: 500;
  }
  
  .upload-hint {
    font-size: 13px;
    color: #8A8AA3;
  }
  
  .stats {
    display: flex;
    gap: 48px;
  }
  
  .stat {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }
  
  .stat-number {
    font-family: 'JetBrains Mono', monospace;
    font-size: 28px;
    font-weight: 600;
    color: #05D9E8;
  }
  
  .stat-label {
    font-size: 13px;
    color: #8A8AA3;
  }
  
  .landing-footer {
    display: flex;
    justify-content: center;
    gap: 16px;
    padding: 24px;
    font-size: 12px;
    color: #8A8AA3;
    z-index: 1;
  }
  
  .app {
    width: 100vw;
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: #0A0A0F;
  }
  
  .main-content {
    flex: 1;
    display: flex;
    overflow: hidden;
    position: relative;
  }
</style>
