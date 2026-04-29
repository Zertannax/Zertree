<script>
  import { onMount } from 'svelte'
  
  let visible = false
  
  onMount(() => {
    visible = true
  })
</script>

{#if visible}
  <div class="film-overlay">
    <div class="film-hud">
      <div class="recording-dot"></div>
      <span class="recording-text">REC</span>
      <span class="film-time">{new Date().toLocaleTimeString()}</span>
    </div>
    
    <div class="scanlines"></div>
    <div class="vignette"></div>
  </div>
{/if}

<style>
  .film-overlay {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 100;
  }
  
  .film-hud {
    position: absolute;
    top: 60px;
    left: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    background: rgba(255, 42, 109, 0.1);
    border: 1px solid rgba(255, 42, 109, 0.3);
    border-radius: 4px;
    animation: fadeIn 0.5s ease;
  }
  
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  
  .recording-dot {
    width: 8px;
    height: 8px;
    background: #FF2A6D;
    border-radius: 50%;
    animation: blink 1s ease-in-out infinite;
  }
  
  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }
  
  .recording-text {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    font-weight: 600;
    color: #FF2A6D;
    letter-spacing: 2px;
  }
  
  .film-time {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #8A8AA3;
    margin-left: 8px;
  }
  
  .scanlines {
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0, 0, 0, 0.03) 2px,
      rgba(0, 0, 0, 0.03) 4px
    );
    pointer-events: none;
  }
  
  .vignette {
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse at center, transparent 60%, rgba(0, 0, 0, 0.4) 100%);
    pointer-events: none;
  }
</style>
