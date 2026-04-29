<script>
  import { onMount, onDestroy } from 'svelte'
  import { createEventDispatcher } from 'svelte'
  import * as d3 from 'd3'
  
  export let sbomData
  export let filmMode
  
  const dispatch = createEventDispatcher()
  let svg
  let container
  let simulation
  let width = 800
  let height = 600
  let animationId
  let filmAngle = 0
  
  $: if (sbomData && svg) {
    renderGraph()
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
        if (sbomData) renderGraph()
      }
    })
    resizeObserver.observe(container)
    
    return () => resizeObserver.disconnect()
  })
  
  onDestroy(() => {
    stopFilmMode()
    if (simulation) simulation.stop()
  })
  
  function getRiskScore(component) {
    if (component.riskScore !== undefined) return component.riskScore
    if (component.licenses) {
      const license = component.licenses[0]?.license?.id || ''
      if (license.includes('GPL') || license.includes('AGPL')) return 8
      if (license.includes('MIT') || license.includes('Apache')) return 1
    }
    return Math.random() * 10
  }
  
  function getNodeColor(score) {
    if (score >= 8) return '#FF2A6D'
    if (score >= 4) return '#F7E018'
    return '#05D9E8'
  }
  
  function getNodeRadius(score) {
    return 6 + (score / 10) * 14
  }
  
  function renderGraph() {
    if (!sbomData?.components) return
    
    d3.select(svg).selectAll('*').remove()
    
    const components = sbomData.components.map((c, i) => ({
      id: i,
      name: c.name,
      version: c.version,
      score: getRiskScore(c),
      ...c
    }))
    
    const links = []
    if (sbomData.dependencies) {
      sbomData.dependencies.forEach(dep => {
        const sourceIdx = components.findIndex(c => 
          dep.ref.includes(c.name) || c.name.includes(dep.ref.split('/').pop())
        )
        if (sourceIdx >= 0 && dep.dependsOn) {
          dep.dependsOn.forEach(targetRef => {
            const targetIdx = components.findIndex(c => 
              targetRef.includes(c.name) || c.name.includes(targetRef.split('/').pop())
            )
            if (targetIdx >= 0) {
              links.push({ source: sourceIdx, target: targetIdx })
            }
          })
        }
      })
    }
    
    // Create nodes even without dependencies
    if (links.length === 0) {
      components.forEach((c, i) => {
        if (i < components.length - 1) {
          links.push({ source: i, target: i + 1 })
        }
      })
    }
    
    const g = d3.select(svg).append('g')
    
    simulation = d3.forceSimulation(components)
      .force('link', d3.forceLink(links).id(d => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => getNodeRadius(d.score) + 5))
    
    const linkElements = g.append('g')
      .selectAll('line')
      .data(links)
      .enter()
      .append('line')
      .attr('stroke', '#1A1A2E')
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.6)
    
    const nodeElements = g.append('g')
      .selectAll('g')
      .data(components)
      .enter()
      .append('g')
      .attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended))
    
    nodeElements.append('circle')
      .attr('r', d => getNodeRadius(d.score))
      .attr('fill', d => getNodeColor(d.score))
      .attr('stroke', d => getNodeColor(d.score))
      .attr('stroke-width', 2)
      .attr('stroke-opacity', 0.3)
      .style('filter', d => d.score >= 8 ? 'drop-shadow(0 0 8px rgba(255, 42, 109, 0.6))' : 'none')
      .style('animation', d => d.score >= 8 ? 'pulse 2s ease-in-out infinite' : 'none')
    
    nodeElements.append('text')
      .text(d => d.name)
      .attr('x', d => getNodeRadius(d.score) + 4)
      .attr('y', 4)
      .attr('font-size', '10px')
      .attr('fill', '#8A8AA3')
      .attr('font-family', 'JetBrains Mono, monospace')
      .style('pointer-events', 'none')
    
    nodeElements.on('click', (event, d) => {
      dispatch('nodeSelect', d)
    })
    
    nodeElements.on('mouseover', function(event, d) {
      d3.select(this).select('circle')
        .transition()
        .duration(200)
        .attr('r', getNodeRadius(d.score) * 1.3)
    })
    
    nodeElements.on('mouseout', function(event, d) {
      d3.select(this).select('circle')
        .transition()
        .duration(200)
        .attr('r', getNodeRadius(d.score))
    })
    
    simulation.on('tick', () => {
      linkElements
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y)
      
      nodeElements.attr('transform', d => `translate(${d.x},${d.y})`)
    })
    
    // Zoom
    const zoom = d3.zoom()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform)
      })
    
    d3.select(svg).call(zoom)
  }
  
  function dragstarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart()
    d.fx = d.x
    d.fy = d.y
  }
  
  function dragged(event, d) {
    d.fx = event.x
    d.fy = event.y
  }
  
  function dragended(event, d) {
    if (!event.active) simulation.alphaTarget(0)
    d.fx = null
    d.fy = null
  }
  
  function startFilmMode() {
    if (animationId) cancelAnimationFrame(animationId)
    
    function animate() {
      filmAngle += 0.003
      const scale = 1 + Math.sin(filmAngle * 0.5) * 0.3
      const x = width / 2 + Math.cos(filmAngle) * 100
      const y = height / 2 + Math.sin(filmAngle * 0.7) * 50
      
      const svgEl = d3.select(svg)
      svgEl.transition()
        .duration(50)
        .call(
          d3.zoom().transform,
          d3.zoomIdentity.translate(width / 2, height / 2).scale(scale).translate(-x, -y)
        )
      
      animationId = requestAnimationFrame(animate)
    }
    
    animate()
  }
  
  function stopFilmMode() {
    if (animationId) {
      cancelAnimationFrame(animationId)
      animationId = null
    }
  }
</script>

<div class="graph-container" bind:this={container}>
  <svg bind:this={svg} {width} {height}></svg>
  
  {#if !sbomData}
    <div class="placeholder">
      <span>Upload an SBOM to visualize</span>
    </div>
  {/if}
</div>

<style>
  .graph-container {
    flex: 1;
    position: relative;
    overflow: hidden;
    background: #0A0A0F;
  }
  
  svg {
    width: 100%;
    height: 100%;
    display: block;
  }
  
  .placeholder {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #8A8AA3;
    font-size: 16px;
  }
  
</style>
