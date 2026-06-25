import { useRef } from 'react'
import { useGlobe } from '../hooks/useGlobe.js'
import { ArrowIcon } from './Nav.jsx'
import { HEADER_VIDEOS } from '../data/index.js'

// ── Hero section ──────────────────────────────────────
// Contains: globe/fortress + video carousel + headline + CTA
export default function Hero() {
  const globeWrapRef = useRef(null)
  useGlobe(globeWrapRef)

  return (
    <section className="section_home_header">
      <div className="u-container">
        <div className="header_grid u-grid-desktop">

          {/* Globe / Fortress */}
          <div className="header_cases u-column-6">
            {/* Globe canvas injected by useGlobe hook */}
            <div ref={globeWrapRef} className="hero-globe-wrap">
              {/* Fortress iframe overlays globe */}
              <iframe
                className="fortress-frame"
                src="/fortress-viewer.html"
                title="ATTENSE AI Fortress"
                allowTransparency="true"
              />
            </div>

            {/* Video carousel (hidden below globe — driven by original Webflow JS) */}
            <div className="header_case_video_wrap w-dyn-list" style={{ display: 'none' }}>
              <div role="list" className="header_case_video_list w-dyn-items">
                {HEADER_VIDEOS.map(v => (
                  <div key={v.id} data-case={v.id} role="listitem" className="header_case_video_item w-dyn-item">
                    <a data-label="View all stages" href="/cases.html" className="header_case_link w-inline-block">
                      <div className="video_preview w-embed">
                        <video src={v.src} muted autoPlay loop playsInline style={{ height: '100%' }} />
                      </div>
                      <div className="w-embed">
                        <input type="hidden" name="color-main" value={v.colorMain} />
                        <input type="hidden" name="color-alt"  value={v.colorAlt}  />
                      </div>
                      <div data-theme="invert" className="btn_arrow_square">
                        <div className="btn_arrow_icon w-embed"><ArrowIcon dir="diag" /></div>
                      </div>
                    </a>
                  </div>
                ))}
              </div>
            </div>

            {/* Progress bar (hidden via CSS) */}
            <div className="case_progress_track">
              <div id="case-progress" className="case_progress"></div>
            </div>
          </div>

          {/* Headline */}
          <div id="w-node-a8b04439-929b-185d-2d32-4efd948fd273" className="home_header_heading u-column-6">
            <h1 className="u-text-h1 is-bigger">
              Every attack
              <span className="u-text-muted u-blend-overlay">deserves a</span>
              response.
            </h1>
          </div>

          {/* CTA */}
          <div className="header_cta_wrap u-column-6">
            <a href="#intro" className="btn_arrow u-text-small u-tw-nowrap w-inline-block">
              <div className="btn_arrow_text">Discover more</div>
              <div data-theme="" className="btn_arrow_icon_wrap">
                <div className="btn_arrow_icon_move">
                  <div className="btn_arrow_icon is-hor w-embed"><ArrowIcon dir="hor" /></div>
                  <div className="btn_arrow_icon is-hor is-2nd w-embed"><ArrowIcon dir="hor" /></div>
                </div>
              </div>
            </a>
          </div>

        </div>
      </div>
    </section>
  )
}
