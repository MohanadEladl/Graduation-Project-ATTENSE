import { useEffect, useRef } from 'react'
import { GLOBE_DESTS } from '../data/index.js'

// ─────────────────────────────────────────────────────
//  useGlobe — D3 orthographic globe with city cycling
//  Usage: useGlobe(containerRef)
// ─────────────────────────────────────────────────────

const CONTINENTS = [
  { label: 'NORTH AMERICA', center: [-100, 48] },
  { label: 'SOUTH AMERICA', center: [-58,  -15] },
  { label: 'EUROPE',        center: [ 15,   54] },
  { label: 'AFRICA',        center: [ 20,    4] },
  { label: 'ASIA',          center: [ 90,   45] },
  { label: 'OCEANIA',       center: [134,  -25] },
]

function hexRgb(h) {
  h = h.replace('#', '')
  if (h.length === 3) h = h.split('').map(c => c + c).join('')
  return { r: parseInt(h.slice(0,2),16), g: parseInt(h.slice(2,4),16), b: parseInt(h.slice(4,6),16) }
}
function lerp(a, b, t) { return a + (b - a) * t }
function lerpCol(a, b, t) {
  return { r: Math.round(lerp(a.r,b.r,t)), g: Math.round(lerp(a.g,b.g,t)), b: Math.round(lerp(a.b,b.b,t)) }
}
function rgba(c, a) { return `rgba(${c.r},${c.g},${c.b},${a ?? 1})` }
function mix(base, col, amt) {
  return { r: Math.round(base.r*(1-amt)+col.r*amt), g: Math.round(base.g*(1-amt)+col.g*amt), b: Math.round(base.b*(1-amt)+col.b*amt) }
}

export function useGlobe(containerRef) {
  const stateRef = useRef({
    canvas: null, ctx: null, w: 0, h: 0, r: 0,
    rot: [10, -25, 0], trot: [10, -25, 0],
    land: null, borders: null,
    t: 0, arcOff: 0, activeIdx: 0,
    mC: { r: 14, g: 44, b: 125 }, aC: { r: 26, g: 58, b: 153 },
    zoomT: 0, zoomDur: 2.6, zoomAmt: 0.10, prevTs: 0,
    rafId: null, loopRaf: null,
    curIdx: 0, nxtIdx: 1, cycStart: null, transStart: null,
  })

  useEffect(() => {
    if (!containerRef.current) return
    const gv = stateRef.current

    let d3mod, topojsonmod
    let mounted = true

    async function init() {
      try {
        [d3mod, topojsonmod] = await Promise.all([
          import('d3'),
          import('topojson-client'),
        ])
      } catch (e) { return }
      if (!mounted) return

      const wrap = containerRef.current
      wrap.innerHTML = ''
      const canv = document.createElement('canvas')
      canv.className = 'hero-globe-canvas'
      wrap.appendChild(canv)
      gv.canvas = canv

      function rsz() {
        const dpr = window.devicePixelRatio || 1
        gv.w = canv.offsetWidth || 400
        gv.h = canv.offsetHeight || 400
        canv.width  = gv.w * dpr
        canv.height = gv.h * dpr
        gv.ctx = canv.getContext('2d')
        gv.ctx.scale(dpr, dpr)
        gv.r = Math.min(gv.w, gv.h) * 0.44
      }
      rsz()
      window.addEventListener('resize', rsz)

      fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
        .then(r => r.json())
        .then(w => {
          if (!mounted) return
          gv.land    = topojsonmod.feature(w, w.objects.land)
          gv.borders = topojsonmod.mesh(w, w.objects.countries, (a, b) => a !== b)
        })
        .catch(() => {})

      function goNext() {
        gv.curIdx = gv.nxtIdx
        gv.nxtIdx = (gv.curIdx + 1) % GLOBE_DESTS.length
        gv.cycStart = performance.now()
        gv.transStart = null
        const d = GLOBE_DESTS[gv.curIdx]
        gv.trot = [-d.center[0]+3, -d.center[1]+8, 0]
        gv.activeIdx = gv.curIdx
        gv.zoomT = 0.001
      }

      function drawGlobe() {
        if (!gv.canvas || !gv.ctx) return
        const { ctx, w, h } = gv
        const cx = w / 2, cy = h / 2
        const zf = gv.zoomT > 0 ? 1 + gv.zoomAmt * Math.sin(Math.PI * gv.zoomT) : 1
        const r = gv.r * zf
        const { mC, aC } = gv
        const dark  = { r:5, g:6, b:16 }
        const sDark = mix(dark, mC, 0.18)
        const sMid  = mix(dark, mC, 0.07)
        const land  = mix(dark, mC, 0.30)
        const lEdge = mix(dark, mC, 0.55)
        const bdr   = mix(dark, mC, 0.40)
        const arcC  = lerpCol(mC, {r:80,g:180,b:255}, 0.45)

        ctx.clearRect(0, 0, w, h)
        const proj = d3mod.geoOrthographic().scale(r).translate([cx,cy]).rotate(gv.rot).clipAngle(90)
        const path = d3mod.geoPath().projection(proj).context(ctx)

        ctx.beginPath(); path({type:'Sphere'})
        const sg = ctx.createRadialGradient(cx-r*.28, cy-r*.3, r*.05, cx+r*.05, cy+r*.05, r)
        sg.addColorStop(0, rgba(sDark,1)); sg.addColorStop(.5, rgba(sMid,1)); sg.addColorStop(1,'rgba(2,3,8,1)')
        ctx.fillStyle = sg; ctx.fill()

        ctx.beginPath(); path(d3mod.geoGraticule()())
        ctx.strokeStyle = rgba(mC,.06); ctx.lineWidth = .5; ctx.stroke()

        if (gv.land)    { ctx.beginPath(); path(gv.land);    ctx.fillStyle=rgba(land,.88); ctx.fill(); ctx.strokeStyle=rgba(lEdge,.42); ctx.lineWidth=.6; ctx.stroke() }
        if (gv.borders) { ctx.beginPath(); path(gv.borders); ctx.strokeStyle=rgba(bdr,.22); ctx.lineWidth=.4; ctx.stroke() }

        ctx.beginPath(); path({type:'Sphere'}); ctx.strokeStyle=rgba(mC,.32); ctx.lineWidth=2; ctx.stroke()

        // Arcs
        const act = GLOBE_DESTS[gv.activeIdx]
        ctx.save(); ctx.setLineDash([5,7]); ctx.lineDashOffset = gv.arcOff
        GLOBE_DESTS.forEach((d, i) => {
          if (i === gv.activeIdx) return
          ctx.beginPath(); path({type:'LineString',coordinates:[act.center,d.center]})
          ctx.strokeStyle=rgba(arcC,.50); ctx.lineWidth=1.2; ctx.stroke()
        })
        ctx.restore()

        const vc = [-gv.rot[0], -gv.rot[1]]
        ctx.textAlign = 'center'
        CONTINENTS.forEach(c => {
          if (d3mod.geoDistance(vc, c.center) > Math.PI*.43) return
          const pt = proj(c.center); if (!pt) return
          ctx.font='bold 8px sans-serif'; ctx.fillStyle=rgba(lEdge,.35)
          ctx.fillText(c.label, pt[0], pt[1])
        })
        GLOBE_DESTS.forEach((d, i) => {
          if (d3mod.geoDistance(vc, d.center) > Math.PI*.5) return
          const pt = proj(d.center); if (!pt) return
          const [px, py] = pt
          const isAct = (i === gv.activeIdx)
          const fade = Math.max(0, 1 - d3mod.geoDistance(vc,d.center)/(Math.PI*.5))
          if (!isAct) {
            ctx.beginPath(); ctx.arc(px,py,3.5,0,Math.PI*2)
            ctx.fillStyle=rgba(lerpCol(mC,{r:255,g:255,b:255},.55),.85*fade); ctx.fill()
            ctx.strokeStyle=`rgba(255,255,255,${.4*fade})`; ctx.lineWidth=1; ctx.stroke()
          }
          if (isAct) {
            const pulse = .5+.5*Math.sin(gv.t*2.8)
            ctx.beginPath(); ctx.arc(px,py,11+pulse*4,0,Math.PI*2)
            ctx.strokeStyle=rgba(mC,.18+.12*pulse); ctx.lineWidth=1.2; ctx.stroke()
            ctx.beginPath(); ctx.arc(px,py,5.5,0,Math.PI*2)
            ctx.fillStyle=rgba(mC,1); ctx.fill()
            ctx.strokeStyle='rgba(255,255,255,.8)'; ctx.lineWidth=1.5; ctx.stroke()
          }
          ctx.textAlign='left'; ctx.font=(isAct?'bold 11':'9')+'px sans-serif'
          ctx.fillStyle=isAct?rgba(lerpCol(mC,{r:255,g:255,b:255},.7),fade):rgba(lerpCol(mC,{r:255,g:255,b:255},.7),.60*fade)
          ctx.fillText(d.name, px+9, py+4)
        })
      }

      function globeFrame(ts) {
        if (!mounted) return
        const dt = gv.prevTs > 0 ? (ts - gv.prevTs) / 1000 : 0.016
        gv.prevTs = ts; gv.t = ts/1000; gv.arcOff = -(gv.t*14)
        gv.rot[0] += (gv.trot[0] - gv.rot[0]) * .014
        gv.rot[1] += (gv.trot[1] - gv.rot[1]) * .007
        gv.rot[0] -= .05; gv.trot[0] -= .05
        if (gv.zoomT > 0) { gv.zoomT += dt/gv.zoomDur; if (gv.zoomT >= 1) gv.zoomT = 0 }
        drawGlobe()
        gv.rafId = requestAnimationFrame(globeFrame)
      }

      const CYCLE_MS = 7000, TRANSIT_MS = 3500
      let lStart = null
      function colorLoop(ts) {
        if (!mounted) return
        if (!lStart) { lStart = ts; gv.cycStart = ts }
        const elapsed = ts - gv.cycStart
        let blend = 0
        if (elapsed >= CYCLE_MS) {
          if (!gv.transStart) gv.transStart = ts
          blend = Math.min((ts - gv.transStart) / TRANSIT_MS, 1)
          if (blend >= 1) goNext()
        }
        gv.mC = lerpCol(hexRgb(GLOBE_DESTS[gv.curIdx].main), hexRgb(GLOBE_DESTS[gv.nxtIdx].main), blend)
        gv.aC = lerpCol(hexRgb(GLOBE_DESTS[gv.curIdx].alt),  hexRgb(GLOBE_DESTS[gv.nxtIdx].alt),  blend)
        gv.loopRaf = requestAnimationFrame(colorLoop)
      }

      gv.trot = [-GLOBE_DESTS[0].center[0]+3, -GLOBE_DESTS[0].center[1]+8, 0]
      gv.rot  = [...gv.trot]
      gv.rafId    = requestAnimationFrame(globeFrame)
      gv.loopRaf  = requestAnimationFrame(colorLoop)
    }

    init()

    return () => {
      mounted = false
      const gv = stateRef.current
      if (gv.rafId)   cancelAnimationFrame(gv.rafId)
      if (gv.loopRaf) cancelAnimationFrame(gv.loopRaf)
    }
  }, [containerRef])
}
