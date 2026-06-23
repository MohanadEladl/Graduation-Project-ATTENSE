import { useEffect, useRef } from 'react'

// Arrow SVG shared across nav + buttons
export function ArrowIcon({ dir = 'diag' }) {
  return dir === 'diag' ? (
    <svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%" viewBox="0 0 10 10" fill="none" preserveAspectRatio="xMidYMid meet" aria-hidden="true" role="img">
      <path d="M1 9L9 1M9 1H1M9 1V9" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ) : (
    <svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%" viewBox="0 0 10 10" fill="none" preserveAspectRatio="xMidYMid meet" aria-hidden="true" role="img">
      <path d="M1 5H9" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M5 1L9 5L5 9" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

// Builds the ATTENSE logo canvas (strips white background from PNG)
function useAttenseLogo(brandRef) {
  useEffect(() => {
    const SIZE = 38
    const img = new Image()
    img.src = '/assets/ATTENSELOGO.png'
    img.onload = () => {
      const off = document.createElement('canvas')
      off.width = SIZE; off.height = SIZE
      const ctx = off.getContext('2d')
      ctx.drawImage(img, 0, 0, SIZE, SIZE)
      const d = ctx.getImageData(0, 0, SIZE, SIZE)
      for (let i = 0; i < d.data.length; i += 4) {
        const r = d.data[i], g = d.data[i+1], b = d.data[i+2]
        if (r > 210 && g > 210 && b > 210) {
          d.data[i+3] = 0
        } else if (r > 180 && g > 180 && b > 180) {
          d.data[i+3] = Math.round((255 - r) * 2.5)
        }
      }
      ctx.putImageData(d, 0, 0)

      if (!brandRef.current) return
      const canvas = brandRef.current.querySelector('.attense-logo-canvas')
      if (canvas) canvas.getContext('2d').drawImage(off, 0, 0)
    }
  }, [brandRef])
}

export default function Nav() {
  const brandRef = useRef(null)
  useAttenseLogo(brandRef)

  return (
    <nav>
      <div className="u-container">
        <div className="nav_wrap">
          {/* Logo */}
          <a href="/index.html" ref={brandRef} className="nav_brand w-nav-brand w--current" aria-label="ATTENSE">
            <div className="attense-logo-wrap">
              <canvas className="attense-logo-canvas" width="38" height="38" />
            </div>
            <span className="attense-logo-text">ATTENSE</span>
          </a>

          {/* Primary links */}
          <div className="nav_links u-text-small">
            <ul role="list" className="nav_list">
              <li><a href="/cases.html" className="nav_link w-inline-block"><div className="u-font-secondary">STAGES</div></a></li>
              <li><a href="/cases.html" className="nav_link w-inline-block"><div className="u-font-secondary">PLATFORM</div></a></li>
              <li><a href="/manifesto.html" className="nav_link w-inline-block"><div className="u-font-secondary">MANIFESTO</div></a></li>
              <li><a href="/manifesto.html" className="nav_link w-inline-block"><div className="u-font-secondary">MANIFESTO</div></a></li>
            </ul>
          </div>

          {/* CTA */}
          <div id="nav-contact" className="nav_links u-text-small">
            <a href="mailto:hello@attense.io" className="nav_link w-inline-block">
              <div className="u-font-secondary">LET'S TALK</div>
            </a>
          </div>

          {/* Mobile toggle */}
          <button className="nav_toggle" aria-label="Menu">
            <div className="text_label">ENTER RANGE</div>
          </button>
        </div>
      </div>
    </nav>
  )
}
