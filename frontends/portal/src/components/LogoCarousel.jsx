import { LOGOS } from '../data/index.js'

// ── Logo carousel ─────────────────────────────────────
// Pure CSS marquee — duplicates list for seamless loop.
// Flickity is NOT used here; the original Webflow code
// only uses Flickity on the team slider.
export default function LogoCarousel() {
  return (
    <section className="section_home_logos">
      <div className="logo_carousel">
        <div className="logo_carousel_wrap w-dyn-list">
          <div role="list" className="logo_carousel_content w-dyn-items">
            {LOGOS.map(logo => (
              <div key={logo.name} role="listitem" className="logo_carousel_item w-dyn-item">
                <img
                  src={logo.src}
                  loading="lazy"
                  alt={logo.name}
                  className="logo_carousel_img"
                />
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
