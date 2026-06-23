import { ArrowIcon } from './Nav.jsx'

// Full Clevermellow/ATTENSE wordmark SVG paths
function WordmarkSVG() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="100%" height="100%" viewBox="0 0 818 102" fill="none" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
      <path d="M733.364 100.121L714.941 33.3735V32.0386H725.754L741.24 91.3102H744.043L756.859 32.0386H775.948L788.764 91.3102H791.567L807.453 32.0386H817.999V33.3735L799.444 100.121H780.621L767.939 40.8492H765.135L752.186 100.121H733.364Z" fill="currentColor"/>
      <path d="M673.513 101.856C652.955 101.856 638.137 87.172 638.137 66.0798C638.137 45.1211 652.955 30.3032 673.513 30.3032C694.071 30.3032 708.889 45.1211 708.889 66.0798C708.889 87.172 694.071 101.856 673.513 101.856ZM648.95 66.0798C648.95 81.8322 659.229 92.3783 673.513 92.3783C687.797 92.3783 698.076 81.8322 698.076 66.0798C698.076 50.8614 687.797 39.7813 673.513 39.7813C659.229 39.7813 648.95 50.8614 648.95 66.0798Z" fill="currentColor"/>
      <path d="M615.609 100.121V0H626.155V100.121H615.609Z" fill="currentColor"/>
      <path d="M589.078 100.121V0H599.624V100.121H589.078Z" fill="currentColor"/>
      <path d="M545.512 101.856C524.821 101.856 511.738 86.5045 511.738 65.4123C511.738 43.5192 527.224 30.3032 545.112 30.3032C565.937 30.3032 578.085 45.9221 577.017 64.7449L576.75 69.4172H522.151C523.486 83.0336 531.362 92.3783 545.512 92.3783C554.724 92.3783 561.932 88.6404 566.738 80.7642L574.614 85.837C569.408 95.4486 558.862 101.856 545.512 101.856ZM522.418 60.0725H566.738C566.738 48.4585 557.66 39.5144 545.112 39.5144C531.896 39.5144 524.153 48.4585 522.418 60.0725Z" fill="currentColor"/>
      <path d="M437.175 100.121L409.942 15.4855H407.405V100.121H396.859V6.6748H417.952L445.051 91.3105H447.721L475.488 6.6748H496.446V100.121H485.9V15.4855H483.23L455.998 100.121H437.175Z" fill="currentColor"/>
      <path d="M346.816 100.121V32.0386H357.229V46.3225H360.032C361.768 41.2497 367.775 30.7036 382.726 30.7036V42.0507H381.525C364.705 42.0507 357.362 54.0652 357.362 67.1477V100.121H346.816Z" fill="currentColor"/>
      <path d="M301.915 101.856C281.223 101.856 268.141 86.5045 268.141 65.4123C268.141 43.5192 283.626 30.3032 301.514 30.3032C322.339 30.3032 334.488 45.9221 333.42 64.7449L333.153 69.4172H278.553C279.888 83.0336 287.764 92.3783 301.915 92.3783C311.126 92.3783 318.335 88.6404 323.14 80.7642L331.017 85.837C325.81 95.4486 315.264 101.856 301.915 101.856ZM278.82 60.0725H323.14C323.14 48.4585 314.063 39.5144 301.514 39.5144C288.298 39.5144 280.556 48.4585 278.82 60.0725Z" fill="currentColor"/>
      <path d="M220.902 100.121L195.805 33.3735V32.0386H206.751L228.377 91.3102H231.181L252.273 32.0386H263.486V33.3735L238.389 100.121H220.902Z" fill="currentColor"/>
      <path d="M159.552 101.856C138.86 101.856 125.777 86.5045 125.777 65.4123C125.777 43.5192 141.263 30.3032 159.151 30.3032C179.976 30.3032 192.124 45.9221 191.056 64.7449L190.789 69.4172H136.19C137.525 83.0336 145.401 92.3783 159.552 92.3783C168.763 92.3783 175.971 88.6404 180.777 80.7642L188.653 85.837C183.447 95.4486 172.901 101.856 159.552 101.856ZM136.457 60.0725H180.777C180.777 48.4585 171.7 39.5144 159.151 39.5144C145.935 39.5144 138.192 48.4585 136.457 60.0725Z" fill="currentColor"/>
      <path d="M103.25 100.121V0H113.796V100.121H103.25Z" fill="currentColor"/>
      <path d="M47.1237 101.857C19.2233 101.857 0 81.1649 0 53.398C0 25.8981 19.3567 4.93945 47.2571 4.93945C67.4148 4.93945 81.8323 16.153 88.24 30.8374L79.0289 35.7767C74.757 24.5632 63.2765 14.9516 47.2571 14.9516C25.898 14.9516 10.9466 31.2379 10.9466 53.398C10.9466 75.8251 25.898 91.8445 47.2571 91.8445C62.2086 91.8445 75.9585 82.7669 80.2303 67.2815L89.842 72.0873C83.9682 89.4416 67.6818 101.857 47.1237 101.857Z" fill="currentColor"/>
    </svg>
  )
}

export default function Footer() {
  return (
    <footer>
      <div className="u-container">

        {/* Top row: CTA */}
        <div className="footer_cta_wrap">
          <div className="footer_row-top u-grid-tablet">
            <div className="content_block_col u-column-6 is-title">
              <h2 className="u-text-h2">Ready to respond?</h2>
            </div>
            <div className="content_block_col u-column-4 u-hflex-right-center">
              <a href="mailto:hello@attense.io" className="btn_arrow u-text-small w-inline-block">
                <div className="btn_arrow_text">LET'S TALK</div>
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

        {/* Bottom rows */}
        <div className="footer_row-bottom u-grid-tablet">

          {/* Wordmark */}
          <div className="footer_logo-wrap u-column-6">
            <div className="footer_logo-svg w-embed">
              <WordmarkSVG />
            </div>
          </div>

          {/* Social */}
          <div className="nav_links u-text-small u-column-1 is-linkedin">
            <ul role="list" className="nav_list is-footer is-mobile-h">
              <li>
                <a href="https://www.linkedin.com/company/clevermellowcollective/" target="_blank" rel="noreferrer" className="nav_link w-inline-block">
                  <div className="u-font-secondary">Linkedin</div>
                </a>
              </li>
              <li>
                <a href="https://www.instagram.com/clevermellow/" target="_blank" rel="noreferrer" className="nav_link w-inline-block">
                  <div className="u-font-secondary">Instagram</div>
                </a>
              </li>
            </ul>
          </div>

          {/* Terms */}
          <div id="terms-group" className="nav_links u-text-small u-column-2 u-hflex-right-center">
            <a href="/assets/terms.pdf" target="_blank" rel="noreferrer" className="nav_link u-hflex-right-center w-inline-block">
              <div className="u-font-secondary">Terms and conditions</div>
            </a>
            <div className="text_label">©2025</div>
          </div>

        </div>

        {/* Nav links row */}
        <div className="footer_nav u-grid-tablet">
          <div className="nav_links u-text-small u-column-5">
            <ul role="list" className="nav_list is-footer">
              <li><a href="/cases.html"     className="nav_link w-inline-block"><div className="u-font-secondary">Platform</div></a></li>
              <li><a href="/manifesto.html" className="nav_link w-inline-block"><div className="u-font-secondary">Manifesto</div></a></li>
            </ul>
          </div>
        </div>

      </div>
    </footer>
  )
}
