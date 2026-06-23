import { useRef } from 'react'
import { useCaseTilt } from '../hooks/useCaseTilt.js'
import { ArrowIcon } from './Nav.jsx'

// ── Single case card ──────────────────────────────────
// Handles: background image, video preview, 3D tilt,
// tags, arrow button, cover link.
export default function CaseCard({ caseData, isFirst }) {
  const cardRef = useRef(null)
  useCaseTilt(cardRef)

  const { client, subtitle, image, video, link, tags } = caseData

  return (
    <div role="listitem" className={`u-column-5 is-home-case w-dyn-item${isFirst ? ' is-first' : ''}`}>
      <div ref={cardRef} className="home_case-item" data-animate-arrow="" data-scramble="">
        {/* Background image (or gradient for ATTENSE) */}
        {image && (
          <img
            src={image}
            loading="lazy"
            alt={client}
            data-parralax=""
            className="home_case-img u-cover-absolute"
          />
        )}

        {/* Gradient overlay */}
        <div className="home_case-gradient"></div>

        {/* Video preview */}
        <div className="video_preview_wrapper">
          <div className="video_preview w-embed">
            <video
              src={video}
              muted
              autoPlay
              loop
              playsInline
            />
          </div>
        </div>

        {/* Arrow button */}
        <div data-theme="invert" className="btn_arrow_square">
          <div className="btn_arrow_icon w-embed">
            <ArrowIcon dir="diag" />
          </div>
        </div>

        {/* Info */}
        <div className="home_case-info">
          <div className="text_label">{client}</div>
          <div className="text_label u-text-muted">{subtitle}</div>
        </div>

        {/* Tags */}
        <div className="home_case-tags w-dyn-list">
          <div role="list" className="home_case_tag-list w-dyn-items">
            {tags.map(tag => (
              <div key={tag} role="listitem" className="w-dyn-item">
                <div className="tag_item">
                  <div className="text_label">{tag}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Invisible cover link */}
        <a
          data-label="View this case"
          aria-label={`View ${client}`}
          href={link}
          className="case_link u-cover-absolute w-inline-block"
        />
      </div>
    </div>
  )
}
