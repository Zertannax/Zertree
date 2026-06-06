<script>
  import { onMount, onDestroy } from 'svelte'
  import { createEventDispatcher } from 'svelte'
  import * as d3 from 'd3'
  
  export let sbomData
  export let filmMode
  export let rules
  
  const dispatch = createEventDispatcher()
  let svg
  let container
  let simulation
  let width = 800
  let height = 600
  let animationId
  let filmAngle = 0
  
  // State for search and filters
  let searchQuery = ''
  let riskFilter = 'ALL' // ALL, CRITICAL, WARNING, OK
  let layoutMode = 'FORCE' // FORCE, RADIAL, GRID
  let isSimulating = true
  let selectedNodeId = null
  let hoveredNodeId = null
  
  // Graph data structures for path highlighting
  let graphNodes = []
  let graphLinks = []
  
  // Traversal sets for highlighting
  let ancestorsSet = new Set() // Upstream (Amber)
  let descendantsSet = new Set() // Downstream (Red)
  let highlightedNodeIds = new Set()
  
  $: if (sbomData && svg) {
    initializeGraphData()
  }
  
  $: if (layoutMode || riskFilter || searchQuery) {
    applyFiltersAndLayout()
  }
  
  $: if (filmMode) {
    startFilmMode()
  } else {
    stopFilmMode()
  }
  
  onMount(() => {
    const resizeObserver = new ResizeObserver((entries) => {
      for (let entry of entries) {
        width = entry.contentRect.width
        height = entry.contentRect.height
        if (sbomData) applyFiltersAndLayout()
      }
    })
    resizeObserver.observe(container)
    
    return () => resizeObserver.disconnect()
  })
  
  onDestroy(() => {
    stopFilmMode()
    if (simulation) simulation.stop()
  })
  
  function getLicenseName(component) {
    if (component.license) return component.license;
    if (component.licenses && component.licenses.length > 0) {
      return component.licenses[0]?.license?.id || component.licenses[0]?.license?.name || ''
    }
    return ''
  }
  
  function getScoreColor(score) {
    if (score >= 6.0) return '#D50000' // Crimson
    if (score >= 3.0) return '#FFB300' // Amber
    return '#00E676' // Green
  }
  
  // Sizing circle nodes by Blast Radius (impact score) to highlight hubs
  function getNodeRadius(blastRadius) {
    const br = blastRadius || 0
    return 6 + Math.min(br * 3, 22)
  }
  
  function initializeGraphData() {
    if (!sbomData?.components) return
    
    // Process nodes
    graphNodes = sbomData.components.map((c, i) => ({
      id: i,
      name: c.name,
      version: c.version,
      score: c.cascadingScore || c.score || 0,
      blastRadius: c.blastRadius || 0,
      purl: c.purl,
      ...c
    }))
    
    // Process links
    graphLinks = []
    if (sbomData.dependencies) {
      sbomData.dependencies.forEach(dep => {
        const sourceIdx = graphNodes.findIndex(c => 
          dep.ref === c.purl || dep.ref.includes(c.name) || c.name.includes(dep.ref.split('/').pop())
        )
        if (sourceIdx >= 0 && dep.dependsOn) {
          dep.dependsOn.forEach(targetRef => {
            const targetIdx = graphNodes.findIndex(c => 
              targetRef === c.purl || targetRef.includes(c.name) || c.name.includes(targetRef.split('/').pop())
            )
            if (targetIdx >= 0 && sourceIdx !== targetIdx) {
              graphLinks.push({ source: sourceIdx, target: targetIdx })
            }
          })
        }
      })
    }
    
    // Fallback links
    if (graphLinks.length === 0 && graphNodes.length > 1) {
      graphNodes.forEach((c, i) => {
        if (i < graphNodes.length - 1) {
          graphLinks.push({ source: i, target: i + 1 })
        }
      })
    }
    
    applyFiltersAndLayout()
  }
  
  function applyFiltersAndLayout() {
    if (!graphNodes.length || !svg) return
    
    d3.select(svg).selectAll('*').remove()
    
    // Apply filters
    const filteredNodes = graphNodes.map(node => {
      let isVisible = true
      
      if (riskFilter === 'CRITICAL' && node.score < 6) isVisible = false
      else if (riskFilter === 'WARNING' && (node.score < 3 || node.score >= 6)) isVisible = false
      else if (riskFilter === 'OK' && node.score >= 3) isVisible = false
      
      if (searchQuery.trim() !== '') {
        const query = searchQuery.toLowerCase()
        if (!node.name.toLowerCase().includes(query) && !getLicenseName(node).toLowerCase().includes(query)) {
          isVisible = false
        }
      }
      
      return { ...node, isVisible }
    })
    
    const filteredLinks = graphLinks.filter(link => {
      const srcId = typeof link.source === 'object' ? link.source.id : link.source
      const tgtId = typeof link.target === 'object' ? link.target.id : link.target
      return filteredNodes[srcId]?.isVisible && filteredNodes[tgtId]?.isVisible
    }).map(l => ({
      source: typeof l.source === 'object' ? l.source.id : l.source,
      target: typeof l.target === 'object' ? l.target.id : l.target
    }))
    
    // Add marker defs for arrowheads
    const defs = d3.select(svg).append('defs')
    
    defs.append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 0 10 10')
      .attr('refX', 18)
      .attr('refY', 5)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto-start-reverse')
      .append('path')
      .attr('d', 'M 0 0 L 10 5 L 0 10 z')
      .attr('fill', 'rgba(255, 255, 255, 0.15)')
      
    defs.append('marker')
      .attr('id', 'arrow-downstream')
      .attr('viewBox', '0 0 10 10')
      .attr('refX', 18)
      .attr('refY', 5)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto-start-reverse')
      .append('path')
      .attr('d', 'M 0 0 L 10 5 L 0 10 z')
      .attr('fill', '#D50000') // Crimson (downstream dependencies)
      
    defs.append('marker')
      .attr('id', 'arrow-upstream')
      .attr('viewBox', '0 0 10 10')
      .attr('refX', 18)
      .attr('refY', 5)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto-start-reverse')
      .append('path')
      .attr('d', 'M 0 0 L 10 5 L 0 10 z')
      .attr('fill', '#FFB300') // Amber (upstream dependents)
    
    const mainGroup = d3.select(svg).append('g').attr('class', 'main-group')
    
    // Draw links
    const linkGroup = mainGroup.append('g').attr('class', 'links')
    const linkElements = linkGroup.selectAll('.link-line')
      .data(filteredLinks)
      .enter()
      .append('line')
      .attr('class', 'link-line')
      .attr('stroke', 'var(--border-subtle)')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.65)
      .attr('marker-end', 'url(#arrow)')
      
    // Draw nodes
    const nodeGroup = mainGroup.append('g').attr('class', 'nodes')
    const nodeElements = nodeGroup.selectAll('.node')
      .data(filteredNodes.filter(n => n.isVisible))
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended))
        
    // Glowing Concentric Ring for warning/critical risks (Palantir style)
    nodeElements.append('circle')
      .attr('class', d => d.score >= 6.0 ? 'pulse-ring critical' : d.score >= 3.0 ? 'pulse-ring warning' : '')
      .attr('r', d => getNodeRadius(d.blastRadius) + 8)
      .attr('fill', 'none')
      .attr('stroke', d => getScoreColor(d.score))
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', d => d.score >= 3.0 ? 0.35 : 0)
      
    // Core node circle
    nodeElements.append('circle')
      .attr('class', 'node-core')
      .attr('r', d => getNodeRadius(d.blastRadius))
      .attr('fill', '#020204')
      .attr('stroke', d => getScoreColor(d.score))
      .attr('stroke-width', 2.5)
      
    // Anchor indicator dot (Glowing white core highlight!)
    nodeElements.append('circle')
      .attr('r', 2.2)
      .attr('fill', '#ffffff')
      .attr('style', 'filter: drop-shadow(0 0 2px #ffffff);')
      
    // Label text
    nodeElements.append('text')
      .text(d => d.name)
      .attr('x', d => getNodeRadius(d.blastRadius) + 6)
      .attr('y', 3)
      .attr('font-size', '10px')
      .attr('fill', 'var(--text-secondary)')
      .attr('font-family', 'var(--font-mono)')
      .style('pointer-events', 'none')
      
    // Node events
    nodeElements.on('click', (event, d) => {
      selectedNodeId = d.id
      highlightPaths(d.id, filteredNodes, filteredLinks)
      dispatch('nodeSelect', d)
    })
    
    nodeElements.on('mouseover', function(event, d) {
      hoveredNodeId = d.id
      highlightPaths(d.id, filteredNodes, filteredLinks)
    })
    
    nodeElements.on('mouseout', function(event, d) {
      hoveredNodeId = null
      if (selectedNodeId !== null) {
        highlightPaths(selectedNodeId, filteredNodes, filteredLinks)
      } else {
        clearHighlights()
      }
    })
    
    // Zoom setup
    const zoom = d3.zoom()
      .scaleExtent([0.1, 5])
      .on('zoom', (event) => {
        mainGroup.attr('transform', event.transform)
      })
      
    d3.select(svg).call(zoom).on('dblclick.zoom', null)
    
    // Layouts
    if (layoutMode === 'FORCE') {
      if (simulation) simulation.stop()
      
      simulation = d3.forceSimulation(filteredNodes.filter(n => n.isVisible))
        .force('link', d3.forceLink(filteredLinks).id(d => d.id).distance(90))
        .force('charge', d3.forceManyBody().strength(-280))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(d => getNodeRadius(d.blastRadius) + 10))
        
      simulation.on('tick', () => {
        linkElements
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y)
          
        nodeElements.attr('transform', d => `translate(${d.x},${d.y})`)
      })
      
      if (isSimulating) {
        simulation.alpha(1).restart()
      } else {
        simulation.stop()
      }
    } else if (layoutMode === 'RADIAL') {
      if (simulation) simulation.stop()
      
      const visibleNodes = filteredNodes.filter(n => n.isVisible)
      const center = { x: width / 2, y: height / 2 }
      
      visibleNodes.sort((a, b) => b.score - a.score)
      
      visibleNodes.forEach((node, index) => {
        let radius = 90
        if (node.score < 3.0) radius = 210
        else if (node.score < 6.0) radius = 150
        
        const angle = (index / (visibleNodes.length || 1)) * 2 * Math.PI
        node.x = center.x + radius * Math.cos(angle)
        node.y = center.y + radius * Math.sin(angle)
      })
      
      linkElements
        .attr('x1', d => visibleNodes.find(n => n.id === d.source)?.x || 0)
        .attr('y1', d => visibleNodes.find(n => n.id === d.source)?.y || 0)
        .attr('x2', d => visibleNodes.find(n => n.id === d.target)?.x || 0)
        .attr('y2', d => visibleNodes.find(n => n.id === d.target)?.y || 0)
        
      nodeElements.transition().duration(600)
        .attr('transform', d => `translate(${d.x},${d.y})`)
        
    } else if (layoutMode === 'GRID') {
      if (simulation) simulation.stop()
      
      const visibleNodes = filteredNodes.filter(n => n.isVisible)
      visibleNodes.sort((a, b) => b.score - a.score)
      
      const cols = Math.ceil(Math.sqrt(visibleNodes.length))
      const spacing = 110
      const startX = (width - (cols - 1) * spacing) / 2
      const startY = (height - (Math.ceil(visibleNodes.length / cols) - 1) * spacing) / 2
      
      visibleNodes.forEach((node, index) => {
        const col = index % cols
        const row = Math.floor(index / cols)
        node.x = startX + col * spacing
        node.y = startY + row * spacing
      })
      
      linkElements
        .attr('x1', d => visibleNodes.find(n => n.id === d.source)?.x || 0)
        .attr('y1', d => visibleNodes.find(n => n.id === d.source)?.y || 0)
        .attr('x2', d => visibleNodes.find(n => n.id === d.target)?.x || 0)
        .attr('y2', d => visibleNodes.find(n => n.id === d.target)?.y || 0)
        
      nodeElements.transition().duration(600)
        .attr('transform', d => `translate(${d.x},${d.y})`)
    }
  }
  
  function highlightPaths(targetId, nodes, links) {
    ancestorsSet = new Set() // Upstream (Amber)
    descendantsSet = new Set() // Downstream (Red)
    highlightedNodeIds = new Set([targetId])
    
    // Downstream (Dependencies: paths targetId depends on)
    let queue = [targetId]
    while (queue.length > 0) {
      const current = queue.shift()
      links.forEach(l => {
        if (l.source === current) {
          const tgtId = typeof l.target === 'object' ? l.target.id : l.target
          if (!descendantsSet.has(tgtId)) {
            descendantsSet.add(tgtId)
            highlightedNodeIds.add(tgtId)
            queue.push(tgtId)
          }
        }
      })
    }
    
    // Upstream (Dependents: paths that depend on targetId)
    queue = [targetId]
    while (queue.length > 0) {
      const current = queue.shift()
      links.forEach(l => {
        if (l.target === current) {
          const srcId = typeof l.source === 'object' ? l.source.id : l.source
          if (!ancestorsSet.has(srcId)) {
            ancestorsSet.add(srcId)
            highlightedNodeIds.add(srcId)
            queue.push(srcId)
          }
        }
      })
    }
    
    // Style nodes: target fully highlighted, ancestors amber border, descendants red border
    d3.select(svg).selectAll('.node')
      .style('opacity', d => highlightedNodeIds.has(d.id) ? 1.0 : 0.15)
      
    d3.select(svg).selectAll('.node').select('.node-core')
      .attr('stroke', d => {
        if (d.id === targetId) return getScoreColor(d.score)
        if (ancestorsSet.has(d.id)) return 'var(--color-warning)' // Apple orange
        if (descendantsSet.has(d.id)) return 'var(--color-critical)' // Apple red
        return getScoreColor(d.score)
      })
      
    // Style links: trace direction and activate flowing particles
    d3.select(svg).selectAll('.link-line')
      .style('opacity', d => {
        const s = typeof d.source === 'object' ? d.source.id : d.source
        const t = typeof d.target === 'object' ? d.target.id : d.target
        
        const isDownstream = (s === targetId || descendantsSet.has(s)) && descendantsSet.has(t)
        const isUpstream = (t === targetId || ancestorsSet.has(t)) && ancestorsSet.has(s)
        
        return (isDownstream || isUpstream) ? 1.0 : 0.08
      })
      .attr('stroke', d => {
        const s = typeof d.source === 'object' ? d.source.id : d.source
        const t = typeof d.target === 'object' ? d.target.id : d.target
        if ((s === targetId || descendantsSet.has(s)) && descendantsSet.has(t)) return 'var(--color-critical)'
        if ((t === targetId || ancestorsSet.has(t)) && ancestorsSet.has(s)) return 'var(--color-warning)'
        return 'var(--border-subtle)'
      })
      .attr('class', d => {
        const s = typeof d.source === 'object' ? d.source.id : d.source
        const t = typeof d.target === 'object' ? d.target.id : d.target
        const active = (s === targetId || descendantsSet.has(s)) && descendantsSet.has(t) || (t === targetId || ancestorsSet.has(t)) && ancestorsSet.has(s);
        return active ? 'link-line flow-active' : 'link-line';
      })
      .attr('marker-end', d => {
        const s = typeof d.source === 'object' ? d.source.id : d.source
        const t = typeof d.target === 'object' ? d.target.id : d.target
        if ((s === targetId || descendantsSet.has(s)) && descendantsSet.has(t)) return 'url(#arrow-downstream)'
        if ((t === targetId || ancestorsSet.has(t)) && ancestorsSet.has(s)) return 'url(#arrow-upstream)'
        return 'url(#arrow)'
      })
  }
  
  function clearHighlights() {
    highlightedNodeIds.clear()
    ancestorsSet.clear()
    descendantsSet.clear()
    
    d3.select(svg).selectAll('.node')
      .style('opacity', 1.0)
      
    d3.select(svg).selectAll('.node').select('.node-core')
      .attr('stroke', d => getScoreColor(d.score))
      
    d3.select(svg).selectAll('.link-line')
      .style('opacity', 0.35)
      .attr('stroke', 'var(--border-subtle)')
      .attr('class', 'link-line')
      .attr('marker-end', 'url(#arrow)')
  }
  
  function dragstarted(event, d) {
    if (layoutMode !== 'FORCE') return
    if (!event.active && simulation) simulation.alphaTarget(0.3).restart()
    d.fx = d.x
    d.fy = d.y
  }
  
  function dragged(event, d) {
    if (layoutMode !== 'FORCE') return
    d.fx = event.x
    d.fy = event.y
  }
  
  function dragended(event, d) {
    if (layoutMode !== 'FORCE') return
    if (!event.active && simulation) simulation.alphaTarget(0)
    d.fx = null
    d.fy = null
  }
  
  // HUD Actions
  function zoomIn() {
    d3.select(svg).transition().duration(250).call(d3.zoom().scaleBy, 1.4)
  }
  
  function zoomOut() {
    d3.select(svg).transition().duration(250).call(d3.zoom().scaleBy, 0.7)
  }
  
  function fitToScreen() {
    const mainGroup = d3.select(svg).select('.main-group')
    if (mainGroup.empty() || graphNodes.length === 0) return
    
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
    
    graphNodes.filter(n => n.isVisible).forEach(n => {
      if (n.x === undefined) return
      const r = getNodeRadius(n.blastRadius)
      if (n.x - r < minX) minX = n.x - r
      if (n.x + r > maxX) maxX = n.x + r
      if (n.y - r < minY) minY = n.y - r
      if (n.y + r > maxY) maxY = n.y + r
    })
    
    if (minX === Infinity) return
    
    const dx = maxX - minX
    const dy = maxY - minY
    const cx = (minX + maxX) / 2
    const cy = (minY + maxY) / 2
    
    const scale = 0.85 / Math.max(dx / width, dy / height)
    const t = d3.zoomIdentity.translate(width / 2, height / 2).scale(scale).translate(-cx, -cy)
    
    d3.select(svg).transition().duration(500).call(d3.zoom().transform, t)
  }
  
  function toggleSimulation() {
    isSimulating = !isSimulating
    if (layoutMode === 'FORCE' && simulation) {
      if (isSimulating) {
        simulation.alpha(0.3).restart()
      } else {
        simulation.stop()
      }
    }
  }
  
  function startFilmMode() {
    if (animationId) cancelAnimationFrame(animationId)
    
    function animate() {
      filmAngle += 0.002
      const scale = 1 + Math.sin(filmAngle * 0.4) * 0.15
      const x = width / 2 + Math.cos(filmAngle) * 60
      const y = height / 2 + Math.sin(filmAngle * 0.6) * 30
      
      const t = d3.zoomIdentity.translate(width / 2, height / 2).scale(scale).translate(-x, -y)
      
      const mainGroup = d3.select(svg).select('.main-group')
      if (!mainGroup.empty()) {
        mainGroup.attr('transform', t)
      }
      
      animationId = requestAnimationFrame(animate)
    }
    
    animate()
  }
  
  function stopFilmMode() {
    if (animationId) {
      cancelAnimationFrame(animationId)
      animationId = null
      fitToScreen()
    }
  }
</script>

<div class="graph-container" bind:this={container}>
  <svg bind:this={svg}></svg>
  
  <!-- Foundry style floating HUD -->
  <div class="graph-hud">
    <div class="hud-search">
      <input 
        type="text" 
        placeholder="Filter SBOM node name..." 
        bind:value={searchQuery}
        class="search-input"
      />
      {#if searchQuery}
        <button class="clear-search" on:click={() => searchQuery = ''}>✕</button>
      {/if}
    </div>
    
    <div class="hud-row">
      <div class="hud-group">
        <span class="sec-label">SEVERITY FILTER</span>
        <div class="btn-group">
          <button class="hud-btn" class:active={riskFilter === 'ALL'} on:click={() => riskFilter = 'ALL'}>ALL</button>
          <button class="hud-btn crit" class:active={riskFilter === 'CRITICAL'} on:click={() => riskFilter = 'CRITICAL'}>CRIT</button>
          <button class="hud-btn warn" class:active={riskFilter === 'WARNING'} on:click={() => riskFilter = 'WARNING'}>WARN</button>
          <button class="hud-btn safe" class:active={riskFilter === 'OK'} on:click={() => riskFilter = 'OK'}>OK</button>
        </div>
      </div>
    </div>

    <div class="hud-row">
      <div class="hud-group">
        <span class="sec-label">LAYOUT SCHEMA</span>
        <div class="btn-group full-width">
          <button class="hud-btn" class:active={layoutMode === 'FORCE'} on:click={() => layoutMode = 'FORCE'}>FORCE</button>
          <button class="hud-btn" class:active={layoutMode === 'RADIAL'} on:click={() => layoutMode = 'RADIAL'}>RADIAL</button>
          <button class="hud-btn" class:active={layoutMode === 'GRID'} on:click={() => layoutMode = 'GRID'}>GRID</button>
        </div>
      </div>
    </div>
    
    <!-- Controls -->
    <div class="hud-controls">
      <button class="ctrl-btn" on:click={zoomIn}>+</button>
      <button class="ctrl-btn" on:click={zoomOut}>-</button>
      <button class="ctrl-btn" on:click={fitToScreen}>FIT</button>
      {#if layoutMode === 'FORCE'}
        <button class="ctrl-btn simulation-toggle" class:paused={!isSimulating} on:click={toggleSimulation}>
          {isSimulating ? 'HALT' : 'RUN'}
        </button>
      {/if}
    </div>
  </div>
  
  <!-- Legend HUD -->
  <div class="legend-hud">
    <div class="legend-item"><span class="legend-dot critical"></span> Critical Risk</div>
    <div class="legend-item"><span class="legend-dot warning"></span> Warning Risk</div>
    <div class="legend-item"><span class="legend-dot ok"></span> Ok / Compliant</div>
    <div class="divider"></div>
    <div class="trace-help">
      <div class="trace-row"><span class="line-indicator downstream"></span> Downstream Dependency</div>
      <div class="trace-row"><span class="line-indicator upstream"></span> Upstream Dependent</div>
    </div>
    <div class="divider"></div>
    <div class="legend-help">Nodes scaled by Blast Radius. Hover to trace paths.</div>
  </div>
</div>

<style>
  .graph-container {
    flex: 1;
    position: relative;
    overflow: hidden;
    background: var(--bg-main);
  }
  
  svg {
    width: 100%;
    height: 100%;
    display: block;
  }

  /* Flowing edge animation */
  @keyframes flow {
    to {
      stroke-dashoffset: -20;
    }
  }

  .link-line {
    stroke-dasharray: 4, 4;
    animation: flow 6s linear infinite;
    transition: stroke-opacity 0.3s, stroke 0.3s;
  }

  .link-line.flow-active {
    stroke-dasharray: 6, 4;
    animation: flow 1.2s linear infinite;
    stroke-width: 2px;
  }

  /* Node core and halo pulse animations */
  @keyframes pulse-halo {
    0% {
      stroke-width: 1px;
      stroke-opacity: 0.4;
      transform: scale(0.96);
    }
    50% {
      stroke-width: 3px;
      stroke-opacity: 0.8;
      transform: scale(1.04);
    }
    100% {
      stroke-width: 1px;
      stroke-opacity: 0.4;
      transform: scale(0.96);
    }
  }

  .pulse-ring {
    animation: pulse-halo 2.5s infinite ease-in-out;
    transform-origin: center;
    pointer-events: none;
  }

  .node-core {
    transition: fill 0.2s, stroke 0.2s, stroke-width 0.2s;
  }

  .node:hover .node-core {
    fill: rgba(255, 255, 255, 0.08);
    stroke-width: 3.5px;
  }
  
  /* Floating HUD Panel */
  .graph-hud {
    position: absolute;
    top: 24px;
    left: 24px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    background: var(--bg-panel);
    border: 1px solid var(--border-subtle);
    padding: 18px;
    border-radius: 16px;
    z-index: 10;
    width: 260px;
    box-shadow: var(--glass-shadow);
    backdrop-filter: blur(var(--blur-intensity));
  }
  
  .hud-search {
    position: relative;
    display: flex;
  }
  
  .search-input {
    width: 100%;
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 11px;
    padding: 8px 28px 8px 12px;
    font-family: var(--font-mono);
    outline: none;
    transition: border-color 0.2s;
  }
  
  .search-input:focus {
    border-color: var(--text-secondary);
  }
  
  .clear-search {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: transparent;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 11px;
  }
  
  .clear-search:hover {
    color: var(--text-primary);
  }

  .hud-row {
    display: flex;
    flex-direction: column;
  }

  .hud-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .sec-label {
    font-family: var(--font-display);
    font-size: 9px;
    font-weight: 700;
    color: var(--text-secondary);
    letter-spacing: 0.8px;
  }

  .btn-group {
    display: flex;
    gap: 2px;
    background: rgba(0, 0, 0, 0.2);
    padding: 3px;
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
  }

  .btn-group.full-width {
    justify-content: stretch;
  }

  .btn-group.full-width .hud-btn {
    flex: 1;
  }
  
  .hud-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 9px;
    font-family: var(--font-mono);
    padding: 6px 10px;
    border-radius: 6px;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.2s;
  }
  
  .hud-btn:hover {
    color: var(--text-primary);
  }
  
  .hud-btn.active {
    background: var(--bg-active);
    color: var(--text-primary);
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
  }

  .hud-btn.crit.active { color: var(--color-critical); background: rgba(255, 69, 58, 0.1); }
  .hud-btn.warn.active { color: var(--color-warning); background: rgba(255, 159, 10, 0.1); }
  .hud-btn.safe.active { color: var(--color-ok); background: rgba(52, 199, 89, 0.1); }
  
  .hud-controls {
    border-top: 1px solid var(--border-subtle);
    padding-top: 12px;
    display: flex;
    gap: 6px;
  }
  
  .ctrl-btn {
    flex: 1;
    font-size: 10px;
    font-weight: 700;
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid var(--border-subtle);
    color: var(--text-secondary);
    font-family: var(--font-mono);
    padding: 6px 0;
    cursor: pointer;
    border-radius: 8px;
    transition: all 0.2s;
  }

  .ctrl-btn:hover {
    border-color: var(--border-hover);
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.03);
  }
  
  .simulation-toggle.paused {
    color: var(--color-warning);
    border-color: rgba(255, 159, 10, 0.3);
  }
  
  /* Legend HUD */
  .legend-hud {
    position: absolute;
    bottom: 24px;
    right: 24px;
    background: var(--bg-panel);
    border: 1px solid var(--border-subtle);
    border-radius: 16px;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 10;
    box-shadow: var(--glass-shadow);
    backdrop-filter: blur(var(--blur-intensity));
  }
  
  .legend-item {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 11px;
    color: var(--text-secondary);
  }
  
  .legend-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }
  
  .legend-dot.critical { background: var(--color-critical); box-shadow: 0 0 8px var(--color-critical); }
  .legend-dot.warning { background: var(--color-warning); box-shadow: 0 0 8px var(--color-warning); }
  .legend-dot.ok { background: var(--color-ok); box-shadow: 0 0 8px var(--color-ok); }
  
  .divider {
    height: 1px;
    background: var(--border-subtle);
    margin: 6px 0;
  }
  
  .trace-help {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .trace-row {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 10px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
  }

  .line-indicator {
    width: 18px;
    height: 2px;
    border-radius: 1px;
  }

  .line-indicator.downstream { background: var(--color-critical); }
  .line-indicator.upstream { background: var(--color-warning); }

  .legend-help {
    font-size: 9px;
    color: var(--text-muted);
    font-style: italic;
  }
</style>
