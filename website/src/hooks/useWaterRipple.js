import { useEffect, useRef } from 'react'

// Attaches a canvas-based water-ripple trail to the given container ref.
// Returns a canvasRef to be rendered as an absolutely-positioned canvas
// inside that container.
export function useWaterRipple(containerRef) {
  const canvasRef = useRef(null)

  useEffect(() => {
    const container = containerRef.current
    const canvas = canvasRef.current
    if (!container || !canvas) return

    const ctx = canvas.getContext('2d')
    let ripples = []
    let raf
    let lastSpawn = 0
    let dpr = window.devicePixelRatio || 1

    const resize = () => {
      dpr = window.devicePixelRatio || 1
      canvas.width = container.clientWidth * dpr
      canvas.height = container.clientHeight * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    window.addEventListener('resize', resize)

    const onMove = (e) => {
      const now = performance.now()
      if (now - lastSpawn < 30) return
      lastSpawn = now
      const rect = container.getBoundingClientRect()
      ripples.push({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
        radius: 2,
        maxRadius: 70 + Math.random() * 40,
        alpha: 0.55,
      })
      if (ripples.length > 30) ripples.shift()
    }
    container.addEventListener('mousemove', onMove)

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width / dpr, canvas.height / dpr)
      ripples.forEach((r) => {
        const progress = r.radius / r.maxRadius
        const alpha = r.alpha * (1 - progress)

        ctx.beginPath()
        ctx.arc(r.x, r.y, r.radius, 0, Math.PI * 2)
        ctx.strokeStyle = `rgba(232, 196, 154, ${alpha})`
        ctx.lineWidth = 1.5
        ctx.stroke()

        if (r.radius > 14) {
          ctx.beginPath()
          ctx.arc(r.x, r.y, r.radius * 0.62, 0, Math.PI * 2)
          ctx.strokeStyle = `rgba(248, 247, 244, ${alpha * 0.5})`
          ctx.lineWidth = 1
          ctx.stroke()
        }

        r.radius += 1.6
      })
      ripples = ripples.filter((r) => r.radius < r.maxRadius)
      raf = requestAnimationFrame(draw)
    }
    draw()

    return () => {
      container.removeEventListener('mousemove', onMove)
      window.removeEventListener('resize', resize)
      cancelAnimationFrame(raf)
    }
  }, [containerRef])

  return canvasRef
}
