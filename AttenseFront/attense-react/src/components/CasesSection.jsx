import { useEffect, useRef } from 'react'
import { CASES } from '../data/index.js'
import CaseCard from './CaseCard.jsx'

// ── Cases section — 4 featured case cards ────────────
export default function CasesSection() {
  const sectionRef = useRef(null)

  // Match ATTENSE card video size to the second card after layout
  useEffect(() => {
    function matchSizes() {
      const first  = document.querySelector('.is-home-case:first-child .video_preview_wrapper')
      const second = document.querySelector('.is-home-case:nth-child(2) .video_preview_wrapper')
      if (first && second) {
        first.style.setProperty('width',  second.offsetWidth  + 'px', 'important')
        first.style.setProperty('height', second.offsetHeight + 'px', 'important')
      }
    }
    const t1 = setTimeout(matchSizes, 600)
    const t2 = setTimeout(matchSizes, 1500)
    window.addEventListener('resize', matchSizes)
    return () => { clearTimeout(t1); clearTimeout(t2); window.removeEventListener('resize', matchSizes) }
  }, [])

  return (
    <section ref={sectionRef} id="cases" data-theme="inherit" className="section_home_cases">
      <div data-padding-bottom="large" className="u-container">

        {/* Lightbars decorative element */}
        <div id="bars-cases" className="cases_lightbars">
          {[...Array(3)].map((_, row) => (
            <div key={row} className="lightbar_row">
              {[...Array(12)].map((_, col) => {
                const hasBar = (row === 0 && col === 9) ||
                               (row === 1 && (col === 8 || col === 9 || col === 10)) ||
                               (row === 2 && (col === 8 || col === 9))
                return hasBar ? (
                  <div key={col} className="lightbar_block">
                    <div className="lightbar_bar"></div>
                    <div className="lightbar_bar"></div>
                    {col !== 10 && <div className="lightbar_bar"></div>}
                  </div>
                ) : (
                  <div key={col} className="lightbar_block_empty"></div>
                )
              })}
            </div>
          ))}
        </div>

        {/* Header row */}
        <div className="cases_header u-grid-desktop">
          <div className="content_block_col u-column-2">
            <div className="text_label"><span>&gt;&gt;</span>Our stages</div>
          </div>
          <div className="content_block_col u-column-6 is-title">
            <h2 className="u-text-h2">A selection of our recent work</h2>
          </div>
          <div className="content_block_col u-column-4 u-hflex-right-center">
            <a href="/cases.html" className="btn_arrow u-text-small w-inline-block">
              <div className="btn_arrow_text">View all stages</div>
            </a>
          </div>
        </div>

        {/* Grid of 4 cards */}
        <div id="case-grid" className="home_cases_grid u-grid-desktop w-dyn-list">
          <div role="list" className="home_cases_list w-dyn-items">
            {CASES.map((c, i) => (
              <CaseCard key={c.id} caseData={c} isFirst={i === 0} />
            ))}
          </div>
        </div>

      </div>
    </section>
  )
}
