<script>
  import { createEventDispatcher } from 'svelte'
  
  export let sbomData
  export let filmMode
  export let currentView
  export let baselineSbomData = null
  export let diffReport = null
  
  const dispatch = createEventDispatcher()
  
  $: totalComponents = sbomData?.components?.length || 0
  $: criticalCount = sbomData?.components?.filter(c => c.score >= 6.0 || c.cascadingScore >= 6.0).length || 0
  $: warningCount = sbomData?.components?.filter(c => (c.score >= 3.0 && c.score < 6.0) || (c.cascadingScore >= 3.0 && c.cascadingScore < 6.0)).length || 0
  $: okCount = totalComponents - criticalCount - warningCount
  
  function handleReset() {
    dispatch('reset')
  }
  
  function toggleFilm() {
    dispatch('toggleFilm')
  }

  function toggleRules() {
    dispatch('toggleRules')
  }

  function switchView(view) {
    dispatch('viewChange', view)
  }

  function exportReport() {
    dispatch('toggleRules')
  }

  function handleBaselineUpload(event) {
    const file = event.target.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const raw = JSON.parse(e.target.result)
        dispatch('baselineUpload', raw)
      } catch (err) {
        alert('Invalid SBOM JSON file')
      }
    }
    reader.readAsText(file)
  }

  function clearDiff() {
    dispatch('clearDiff')
  }
</script>

<header class="header">
  <div class="left">
    <div class="logo-small" on:click={handleReset} role="button" tabindex="0" on:keydown={(e) => e.key === 'Enter' && handleReset()}>
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.5" class="logo-icon">
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
      <span>ZertTree</span>
    </div>
    
    {#if totalComponents > 0}
      <div class="telemetry-bar">
        <span class="badge crit">CRIT {criticalCount}</span>
        <span class="badge warn">WARN {warningCount}</span>
        <span class="badge safe">OK {okCount}</span>
      </div>
    {/if}
  </div>

  {#if totalComponents > 0}
    <div class="center-nav">
      <button 
        class="nav-tab" 
        class:active={currentView === 'DASHBOARD'} 
        on:click={() => switchView('DASHBOARD')}
      >
        TELEMETRY DASHBOARD
      </button>
      <button 
        class="nav-tab" 
        class:active={currentView === 'GRAPH'} 
        on:click={() => switchView('GRAPH')}
      >
        EXPOSURE VECTOR GRAPH
      </button>
    </div>
  {/if}
  
  <div class="right">
    {#if totalComponents > 0}
      <input
        type="file"
        accept=".json"
        on:change={handleBaselineUpload}
        id="baseline-file-input"
        style="display: none;"
      />
      
      {#if baselineSbomData}
        <div class="diff-badge" title="Active baseline comparison mode">
          <span class="diff-badge-label">COMPARING</span>
          <button class="btn-clear-diff" on:click={clearDiff} title="Clear baseline comparison">✕</button>
        </div>
      {:else}
        <label for="baseline-file-input" class="btn-compare" role="button">
          COMPARE BASELINE
        </label>
      {/if}

      <button class="btn-rules" on:click={toggleRules} title="Scoring coefficients">
        ENG_RULES
      </button>
      
      {#if currentView === 'GRAPH'}
        <button class="btn-film" class:active={filmMode} on:click={toggleFilm} title="Cinematic flyover">
          FLYOVER
        </button>
      {/if}
    {/if}
    
    <button class="btn-reset" on:click={handleReset}>
      DISCONNECT SBOM
    </button>
  </div>
</header>

<style>
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 24px;
    background: var(--bg-panel);
    backdrop-filter: blur(var(--blur-intensity));
    border-bottom: 1px solid var(--border-subtle);
    box-shadow: 0 4px 30px rgba(0, 0, 0, 0.25);
    z-index: 100;
  }
  
  .left {
    display: flex;
    align-items: center;
    gap: 24px;
  }
  
  .logo-small {
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: var(--font-display);
    font-size: 16px;
    font-weight: 700;
    color: var(--text-primary);
    cursor: pointer;
    letter-spacing: -0.3px;
    outline: none;
    transition: opacity 0.2s;
  }

  .logo-small:hover {
    opacity: 0.85;
  }
  
  .telemetry-bar {
    display: flex;
    align-items: center;
    gap: 6px;
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid var(--border-subtle);
    padding: 3px 6px;
    border-radius: 8px;
  }
  
  .badge {
    font-size: 9px;
    font-family: var(--font-mono);
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 5px;
    letter-spacing: 0.2px;
  }
  
  .badge.crit { 
    background: rgba(255, 69, 58, 0.12); 
    color: var(--color-critical); 
    border: 1px solid rgba(255, 69, 58, 0.15);
  }
  .badge.warn { 
    background: rgba(255, 159, 10, 0.12); 
    color: var(--color-warning); 
    border: 1px solid rgba(255, 159, 10, 0.15);
  }
  .badge.safe { 
    background: rgba(52, 199, 89, 0.12); 
    color: var(--color-ok); 
    border: 1px solid rgba(52, 199, 89, 0.15);
  }

  .center-nav {
    display: flex;
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    padding: 3px;
  }

  .nav-tab {
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-secondary);
    font-size: 10px;
    padding: 6px 16px;
    border-radius: 7px;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    font-weight: 700;
    font-family: var(--font-display);
    letter-spacing: 0.5px;
  }

  .nav-tab:hover {
    color: var(--text-primary);
  }

  .nav-tab.active {
    background: var(--bg-active);
    border-color: var(--border-subtle);
    color: var(--text-primary);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
  }
  
  .right {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  
  button {
    padding: 6px 14px;
    border-radius: 8px;
    border: 1px solid var(--border-subtle);
    background: rgba(255, 255, 255, 0.03);
    color: var(--text-secondary);
    font-size: 10px;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    font-family: var(--font-mono);
    font-weight: 600;
  }
  
  button:hover {
    border-color: var(--border-hover);
    background: var(--bg-active);
    color: var(--text-primary);
  }
  
  .btn-film.active {
    background: var(--bg-active);
    color: var(--text-primary);
    border-color: var(--border-hover);
  }
  
  .btn-reset:hover {
    border-color: rgba(255, 69, 58, 0.3);
    color: var(--color-critical);
    background: rgba(255, 69, 58, 0.06);
  }

  .btn-compare {
    display: inline-flex;
    align-items: center;
    padding: 6px 14px;
    border-radius: 8px;
    border: 1px solid var(--border-subtle);
    background: rgba(255, 255, 255, 0.03);
    color: var(--text-secondary);
    font-size: 10px;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    font-family: var(--font-mono);
    font-weight: 600;
  }
  
  .btn-compare:hover {
    border-color: var(--border-hover);
    background: var(--bg-active);
    color: var(--text-primary);
  }
  
  .diff-badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 5px 10px 5px 12px;
    background: rgba(52, 199, 89, 0.1);
    border: 1px solid rgba(52, 199, 89, 0.25);
    border-radius: 8px;
    color: var(--color-ok);
    font-family: var(--font-mono);
    font-size: 10px;
    font-weight: 700;
  }
  
  .diff-badge-label {
    letter-spacing: 0.5px;
  }
  
  .btn-clear-diff {
    background: transparent;
    border: none;
    color: var(--color-ok);
    font-size: 10px;
    cursor: pointer;
    padding: 0;
    width: 14px;
    height: 14px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    transition: all 0.2s;
  }
  
  .btn-clear-diff:hover {
    background: rgba(52, 199, 89, 0.2);
    color: var(--text-primary);
  }
</style>
