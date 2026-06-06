<script>
  import { onMount, onDestroy } from 'svelte'
  import { createEventDispatcher } from 'svelte'
  
  export let sbomData
  
  const dispatch = createEventDispatcher()
  let isOpen = false
  let query = ''
  let inputEl
  let selectedIndex = 0
  
  $: components = sbomData?.components || []
  
  // Filtered options: both packages and action items
  $: actions = [
    { type: 'action', id: 'view_dashboard', label: 'View: Switch to Security Dashboard', icon: '📊' },
    { type: 'action', id: 'view_graph', label: 'View: Switch to Dependency Graph', icon: '🧬' },
    { type: 'action', id: 'view_licenses', label: 'View: License Inventory Dashboard', icon: '⚖️' },
    { type: 'action', id: 'open_rules', label: 'Config: Open Scoring Engine Rules', icon: '⚙️' },
    { type: 'action', id: 'export_json', label: 'Export: Download Report (JSON)', icon: '💾' },
    { type: 'action', id: 'export_pdf', label: 'Export: Print PDF Report', icon: '🖨️' }
  ]
  
  $: filteredPackages = query.trim() === '' 
    ? [] 
    : components
        .filter(c => c.name.toLowerCase().includes(query.toLowerCase()))
        .map(c => ({ type: 'package', id: c.purl || c.name, label: `Locate: ${c.name} (v${c.version})`, node: c, icon: '📦' }))
        .slice(0, 8)
        
  $: filteredActions = query.trim() === ''
    ? actions
    : actions.filter(a => a.label.toLowerCase().includes(query.toLowerCase()))
    
  $: results = [...filteredActions, ...filteredPackages]
  
  $: if (results) {
    selectedIndex = Math.min(selectedIndex, Math.max(0, results.length - 1))
  }
  
  function handleKeyDown(event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
      event.preventDefault()
      isOpen = !isOpen
      if (isOpen) {
        query = ''
        selectedIndex = 0
        setTimeout(() => inputEl?.focus(), 50)
      }
    } else if (event.key === 'Escape' && isOpen) {
      isOpen = false
    }
  }
  
  onMount(() => {
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  })
  
  function executeSelection() {
    if (results.length === 0) return
    const selected = results[selectedIndex]
    
    if (selected.type === 'action') {
      if (selected.id === 'view_dashboard') dispatch('action', { type: 'view', value: 'DASHBOARD' })
      if (selected.id === 'view_graph') dispatch('action', { type: 'view', value: 'GRAPH' })
      if (selected.id === 'view_licenses') dispatch('action', { type: 'view', value: 'LICENSES' })
      if (selected.id === 'open_rules') dispatch('action', { type: 'rules' })
      if (selected.id === 'export_json') dispatch('action', { type: 'export' })
      if (selected.id === 'export_pdf') dispatch('action', { type: 'export_pdf' })
    } else if (selected.type === 'package') {
      dispatch('nodeSelect', selected.node)
    }
    
    isOpen = false
  }
  
  function handleInputKey(event) {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      selectedIndex = (selectedIndex + 1) % results.length
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      selectedIndex = (selectedIndex - 1 + results.length) % results.length
    } else if (event.key === 'Enter') {
      event.preventDefault()
      executeSelection()
    }
  }
</script>

{#if isOpen}
  <div class="overlay" on:click={() => isOpen = false} role="presentation">
    <div class="palette" on:click|stopPropagation role="dialog" aria-modal="true" aria-label="Command Palette">
      <div class="search-header">
        <span class="prompt-symbol">⌘</span>
        <input 
          type="text" 
          placeholder="Search packages, registry items, or actions..." 
          bind:value={query}
          bind:this={inputEl}
          on:keydown={handleInputKey}
        />
        <span class="esc-badge">ESC</span>
      </div>
      
      <div class="results-list">
        {#if results.length > 0}
          {#each results as item, index}
            <div 
              class="result-item" 
              class:selected={index === selectedIndex}
              on:mouseenter={() => selectedIndex = index}
              on:click={executeSelection}
              on:keydown={(e) => e.key === 'Enter' && executeSelection()}
              role="button"
              tabindex="0"
            >
              <span class="item-icon">{item.icon}</span>
              <span class="item-label">{item.label}</span>
              {#if index === selectedIndex}
                <span class="enter-badge">ENTER</span>
              {/if}
            </div>
          {/each}
        {:else}
          <div class="empty-state">No matching packages or commands found.</div>
        {/if}
      </div>
      
      <div class="palette-footer">
        <span>Use <kbd>↑</kbd> <kbd>↓</kbd> to navigate</span>
        <span><kbd>⏎ Enter</kbd> to execute</span>
        <span><kbd>⌘ K</kbd> to toggle</span>
      </div>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(5, 6, 8, 0.45);
    backdrop-filter: blur(25px);
    z-index: 1000;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding-top: 15vh;
  }
  
  .palette {
    width: 620px;
    background: var(--bg-panel);
    border: 1px solid var(--border-hover);
    border-radius: 16px;
    box-shadow: var(--glass-shadow), 0 0 0 1px rgba(255, 255, 255, 0.05);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    backdrop-filter: blur(var(--blur-intensity));
    animation: scaleIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  }
  
  @keyframes scaleIn {
    from { transform: scale(0.97); opacity: 0; }
    to { transform: scale(1); opacity: 1; }
  }
  
  .search-header {
    display: flex;
    align-items: center;
    padding: 18px 24px;
    border-bottom: 1px solid var(--border-subtle);
    background: rgba(0, 0, 0, 0.15);
  }
  
  .prompt-symbol {
    font-family: var(--font-sans);
    color: var(--text-secondary);
    font-size: 18px;
    margin-right: 14px;
    font-weight: 500;
  }
  
  input {
    flex: 1;
    background: transparent;
    border: none;
    outline: none;
    color: var(--text-primary);
    font-size: 15px;
    font-family: var(--font-sans);
    letter-spacing: -0.2px;
  }
  
  input::placeholder {
    color: var(--text-secondary);
    opacity: 0.7;
  }
  
  .esc-badge {
    font-size: 9px;
    font-family: var(--font-mono);
    background: var(--bg-active);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    padding: 3px 6px;
    border-radius: 5px;
    font-weight: 600;
  }
  
  .results-list {
    max-height: 340px;
    overflow-y: auto;
    padding: 10px;
    background: transparent;
  }
  
  .result-item {
    display: flex;
    align-items: center;
    padding: 10px 16px;
    border-radius: 10px;
    cursor: pointer;
    transition: all 0.15s cubic-bezier(0.16, 1, 0.3, 1);
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 4px;
    border: 1px solid transparent;
    outline: none;
  }
  
  .result-item.selected {
    background: var(--bg-active);
    border-color: var(--border-subtle);
    color: var(--text-primary);
  }
  
  .item-icon {
    font-size: 14px;
    margin-right: 14px;
    width: 20px;
    text-align: center;
  }
  
  .item-label {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 12px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    letter-spacing: -0.2px;
  }
  
  .enter-badge {
    font-size: 9px;
    font-family: var(--font-mono);
    color: var(--color-ok);
    background: rgba(52, 199, 89, 0.12);
    border: 1px solid rgba(52, 199, 89, 0.15);
    padding: 2px 6px;
    border-radius: 5px;
    font-weight: 700;
  }
  
  .empty-state {
    padding: 32px;
    text-align: center;
    color: var(--text-secondary);
    font-size: 13px;
    font-family: var(--font-sans);
  }
  
  .palette-footer {
    display: flex;
    justify-content: space-between;
    padding: 12px 24px;
    background: rgba(0, 0, 0, 0.25);
    border-top: 1px solid var(--border-subtle);
    font-size: 10px;
    color: var(--text-secondary);
  }
  
  kbd {
    background: var(--bg-active);
    border: 1px solid var(--border-subtle);
    border-radius: 5px;
    padding: 2px 6px;
    margin: 0 2px;
    font-family: var(--font-mono);
    color: var(--text-primary);
    font-size: 9px;
    font-weight: 600;
  }
</style>
