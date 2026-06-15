import { SKILLS } from '../data/index.js'
import { ArrowIcon } from './Nav.jsx'

// ── What We Do section ────────────────────────────────
export default function WhatWeDo() {
  return (
    <section id="intro" data-theme="inherit" data-padding-bottom="large" className="section_home_what-we-do">
      <div className="u-container">
        <div className="u-grid-tablet">

          {/* Label */}
          <div className="content_block_col u-column-2">
            <div className="text_label"><span>&gt;&gt;</span>What we do</div>
          </div>

          {/* Title */}
          <div className="content_block_col u-column-6 is-title">
            <h2 className="u-text-h2">How we create a digital stage</h2>
          </div>

          {/* Description */}
          <div className="content_block_col u-column-4">
            <p>
              A stage for an event is built around the visitor's experience.
              It is not about the separate elements, like lighting, sound and technology.
              It is about the whole coming together to form the show.
            </p>
          </div>

          {/* Skills list */}
          <div className="col u-column-10">
            <div className="skills_wrap w-dyn-list">
              <div role="list" className="skills_list w-dyn-items">
                {SKILLS.map(skill => (
                  <div
                    key={skill.id}
                    data-video={skill.video || ''}
                    role="listitem"
                    className="skills_item u-grid-desktop u-column-10 w-dyn-item"
                  >
                    <h3 className="u-text-h2 u-column-6">{skill.title}</h3>
                    <ul className="skills_item-list u-column-4">
                      {skill.items.map(item => (
                        <li key={item}><div className="text_label">{item}</div></li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* CTA */}
          <div className="content_block_col u-column-10">
            <a href="/cases.html" className="btn_arrow u-text-small w-inline-block">
              <div className="btn_arrow_text">View all our work</div>
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
