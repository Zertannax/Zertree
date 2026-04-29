<script>
  import { createEventDispatcher } from 'svelte'
  
  export let sbomData
  export let filmMode
  
  const dispatch = createEventDispatcher()
  
  $: totalComponents = sbomData?.components?.length || 0
  $: criticalCount = sbomData?.components?.filter(c => c.riskScore >= 8).length || 0
  $: warningCount = sbomData?.components?.filter(c => c.riskScore >= 4 && c.riskScore < 8).length || 0
  $: okCount = totalComponents - criticalCount - warningCount
  
  function handleReset() {
    dispatch('reset')
  }
  
  function toggleFilm() {
    dispatch('toggleFilm')
  }
</script>

<header class="header">
  <div class="left">
    <div class="logo-small">
      <svg viewBox="0 0 24 24" width="24" height="24">
        <circle cx="12" cy="6" r="4" fill="#05D9E8"/>
        <circle cx="6" cy="17" r="3.5" fill="#FF2A6D"/>
        <circle cx="18" cy="17" r="3.5" fill="#F7E018"/>
        <line x1="12" y1="10" x2="6" y2="13.5" stroke="#1A1A2E" stroke-width="1"/>
        <line x1="12" y1="10" x2="18" y2="13.5" stroke="#1A1A2E" stroke-width="1"/>
      </svg>
      <span>ZertTree</span>
    </div>
    
    {#if totalComponents > 0}
      <div class="stats-bar">
        <span class="stat-badge critical">🔴 {criticalCount}</span>
        <span class="stat-badge warning">🟡 {warningCount}</span>
        <span class="stat-badge ok">🟢 {okCount}</span>
        <span class="stat-total">{totalComponents} components</span>
      </div>
    {/if}
  </div>
  
  <div class="right">
    {#if totalComponents > 0}
      <button class="btn-film" class:active={filmMode} on:click={toggleFilm}>
        🎬 {filmMode ? 'Stop' : 'Film'}
      </button>
      
      <button class="btn-export">💾 Export</button>
    {/if}
    
    <button class="btn-reset" on:click={handleReset}>
      ✕ Close
    </button>
  </div>
</header>

<style>
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 20px;
    background: #12121F;
    border-bottom: 1px solid #1A1A2E;
    z-index: 10;
  }
  
  .left {
    display: flex;
    align-items: center;
    gap: 24px;
  }
  
  .logo-small {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: 'Space Grotesk', sans-serif;
    font-size: 18px;
    font-weight: 600;
    color: #05D9E8;
  }
  
  .stats-bar {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  
  .stat-badge {
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
  }
  
  .stat-badge.critical {
    background: rgba(255, 42, 109, 0.15);
    color: #FF2A6D;
    border: 1px solid rgba(255, 42, 109, 0.3);
  }
  
  .stat-badge.warning {
    background: rgba(247, 224, 24, 0.15);
    color: #F7E018;
    border: 1px solid rgba(247, 224, 24, 0.3);
  }
  
  .stat-badge.ok {
    background: rgba(5, 217, 232, 0.15);
    color: #05D9E8;
    border: 1px solid rgba(5, 217, 232, 0.3);
  }
  
  .stat-total {
    font-size: 12px;
    color: #8A8AA3;
    font-family: 'JetBrains Mono', monospace;
  }
  
  .right {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  
  button {
    padding: 6px 14px;
    border-radius: 4px;
    border: 1px solid #1A1A2E;
    background: #12121F;
    color: #8A8AA3;
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s;
    font-family: 'Inter', sans-serif;
  }
  
  button:hover {
    border-color: #05D9E8;
    color: #E0E0E0;
  }
  
  .btn-film.active {
    background: rgba(5, 217, 232, 0.15);
    border-color: #05D9E8;
    color: #05D9E8;
  }
  
  .btn-reset:hover {
    border-color: #FF2A6D;
    color: #FF2A6D;
  }
</style>
