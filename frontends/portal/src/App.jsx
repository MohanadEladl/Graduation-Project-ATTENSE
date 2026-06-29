import { useEffect } from 'react'
import { useLenis } from './hooks/useLenis.js'
import Nav from './components/Nav.jsx'
import Hero from './components/Hero.jsx'
import LogoCarousel from './components/LogoCarousel.jsx'
import CasesSection from './components/CasesSection.jsx'
import WhatWeDo from './components/WhatWeDo.jsx'
import Footer from './components/Footer.jsx'

export default function App() {
  useLenis()

  useEffect(() => {
    function loadScript(src, isModule = false) {
      return new Promise((resolve, reject) => {
        if (document.querySelector(`script[src="${src}"]`)) { resolve(); return }
        const s = document.createElement('script')
        s.src = src
        if (isModule) s.type = 'module'
        s.onload = resolve
        s.onerror = reject
        document.body.appendChild(s)
      })
    }

    async function initScripts() {
      try {
        await loadScript('/assets/gsap.min.js')
        await loadScript('/assets/ScrollTrigger.min.js')
        await loadScript('/assets/CustomEase.min.js')
        await loadScript('https://files.clevermellow.co/gsap/minified/ScrambleTextPlugin.min.js')
        await loadScript('https://files.clevermellow.co/gsap/minified/DrawSVGPlugin.min.js')
        await loadScript('https://files.clevermellow.co/gsap/minified/splittext.min.js')
        await loadScript('/assets/flickity.pkgd.min.js')
        await loadScript('/assets/p5.js')
        await loadScript('/assets/7804.js', true)
      } catch (e) {
        console.warn('Script load error (non-fatal):', e.message)
      }
    }

    initScripts()
  }, [])

  useEffect(() => {
    function killBars() {
      ;['case_progress_track', 'case_progress', 'case-progress'].forEach(id => {
        const el = document.getElementById(id) || document.querySelector('.' + id)
        if (el) el.style.cssText = 'display:none!important;height:0!important;opacity:0!important;'
      })
      const sec = document.querySelector('.section_home_header')
      if (sec) sec.style.background = '#000000'
    }
    const t1 = setTimeout(killBars, 0)
    const t2 = setTimeout(killBars, 500)
    const t3 = setTimeout(killBars, 1500)
    return () => { clearTimeout(t1); clearTimeout(t2); clearTimeout(t3) }
  }, [])

  useEffect(() => {
    function fixAttenseCard() {
      const wrappers = document.querySelectorAll('.is-home-case:first-child .video_preview_wrapper')
      for (let i = 1; i < wrappers.length; i++) wrappers[i].remove()
      const v = document.querySelector('.is-home-case:first-child .video_preview_wrapper video')
      if (v && !v.src.includes('attense-demo')) {
        v.src = '/assets/attense-demo.mp4'
        v.load()
        v.play().catch(() => {})
      }
    }

    function fixHeadline() {
      const h1 = document.querySelector('h1.u-text-h1')
      if (h1 && (h1.textContent.includes('Every story') || h1.textContent.includes('digital stage'))) {
        h1.innerHTML = h1.innerHTML
          .replace(/Every story/g, 'Every attack')
          .replace(/digital stage\./g, 'response.')
      }
    }

    const intervals = [100, 500, 1500].map(ms => setTimeout(() => { fixAttenseCard(); fixHeadline() }, ms))
    return () => intervals.forEach(clearTimeout)
  }, [])

  return (
    <div className="page-wrap" data-wf-page="attense-home">
      <div className="page_loader_wrap">
        <div className="noise_overlay"></div>
        {[...Array(7)].map((_, i) => <div key={i} className="page_loader_column"></div>)}
        <div className="page_loader_content"></div>
      </div>

      <Nav />

      <main>
        <Hero />
        <LogoCarousel />
        <CasesSection />
        <WhatWeDo />
      </main>

      <Footer />
    </div>
  )
}
