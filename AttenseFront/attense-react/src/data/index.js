// ─────────────────────────────────────────────
//  Single source of truth for all static data
// ─────────────────────────────────────────────

export const COLORS = {
  navy:   '#0E2C7D',
  purple: '#5B3A8E',
  red:    '#8B1A2E',
  beige:  '#F0ECE3',
  dark:   '#050914',
}

// ── Navigation ────────────────────────────────
export const NAV_LINKS = [
  { label: 'STAGES',    href: '/cases.html' },
  { label: 'PLATFORM',  href: '/cases.html' },
  { label: 'MANIFESTO', href: '/manifesto.html' },
  { label: 'MANIFESTO', href: '/manifesto.html' },
]

// ── Case cards (4 main cards on homepage) ────
export const CASES = [
  {
    id: 'attense',
    client: 'ATTENSE',
    subtitle: 'Enterprise cybersecurity',
    image: null, // uses gradient background
    video: '/assets/attense-demo.mp4',
    link: '/attense-enterprise.html',
    tags: ['Enterprise', 'Incident Response'],
    colorMain: '#0E2C7D',
    colorAlt: '#5B3A8E',
    isAttense: true,
  },
  {
    id: 'koersmakers',
    client: 'Koersmakers',
    subtitle: 'Strengthens skilled professionals',
    image: '/assets/68666c2e33371009c75ad20b_tsn-koersmakers.avif',
    video: 'https://clevermellow.b-cdn.net/homepage/Koersmakers%20-%20Websitevideo%20(final).mp4',
    link: 'https://www.koersmakers.com/',
    tags: ['Design', 'Development'],
    colorMain: '#29225C',
    colorAlt: '#A31352',
  },
  {
    id: 'byont',
    client: 'Byont',
    subtitle: 'Is an innovation partner in biogas',
    image: '/assets/68666c8ec3d37e98208b423e_byont.avif',
    video: 'https://clevermellow.b-cdn.net/homepage/Byont-websitevideo%20(final).mp4',
    link: 'https://go-byont.com',
    tags: ['Design', 'Development'],
    colorMain: '#6DDCFE',
    colorAlt: '#BBD1F3',
  },
  {
    id: 'stedelijk',
    client: 'Het Stedelijk',
    subtitle: 'Where students discover',
    image: '/assets/68679d5d5d0d6a455e9056af_stedelijk-website.jpg',
    video: 'https://clevermellow.b-cdn.net/homepage/Het-stedelijk-website%20(final).mp4',
    link: 'https://www.hetstedelijk.nl/',
    tags: ['Design', 'Development'],
    colorMain: '#3927D4',
    colorAlt: '#9B55F4',
  },
]

// ── Header video carousel (hero section) ─────
export const HEADER_VIDEOS = [
  { id: 'koersmakers', src: 'https://clevermellow.b-cdn.net/homepage/Koersmakers%20-%20Websitevideo%20(final).mp4', colorMain: '#29225C', colorAlt: '#A31352' },
  { id: 'byont',       src: 'https://clevermellow.b-cdn.net/homepage/Byont-websitevideo%20(final).mp4',              colorMain: '#6DDCFE', colorAlt: '#BBD1F3' },
  { id: 'stedelijk',   src: 'https://clevermellow.b-cdn.net/homepage/Het-stedelijk-website%20(final).mp4',           colorMain: '#3927D4', colorAlt: '#9B55F4' },
  { id: 'joris',       src: 'https://clevermellow.b-cdn.net/homepage/Joris%20-%20Websitevideo%20(final).mp4',         colorMain: '#F4ED6C', colorAlt: '#FFFFFF' },
  { id: 'transferendi',src: 'https://clevermellow.b-cdn.net/homepage/Transferendi-website%20(final).mp4',            colorMain: '#261BAD', colorAlt: '#F4F4F6' },
  { id: 'polyned',     src: 'https://clevermellow.b-cdn.net/homepage/Polyned%20-%20Websitevideo%20(final).mp4',       colorMain: '#FF5B05', colorAlt: '#F6F8F8' },
  { id: 'asito',       src: 'https://files.clevermellow.co/clevermellow/asito-website.mp4',                          colorMain: '#D03B1D', colorAlt: '#F39237' },
  { id: 'playside',    src: 'https://files.clevermellow.co/clevermellow/playside-website.mp4',                       colorMain: '#114CFC', colorAlt: '#5BC3FF' },
  { id: 'hpse',        src: 'https://files.clevermellow.co/clevermellow/hpse-website.mp4',                           colorMain: '#8B5938', colorAlt: '#FFEDC4' },
]

// ── Logo carousel ─────────────────────────────
export const LOGOS = [
  { name: 'Polyned',                     src: '/assets/666b1e3a7048532a08edec64_polyned.svg' },
  { name: 'Asito',                        src: '/assets/666b1eb4017f2c4f03894b1d_asito.svg' },
  { name: 'Campus Offices',              src: '/assets/666b1e787aaab65035ac38df_co.svg' },
  { name: 'Het Stedelijk',               src: '/assets/666b1eaa490ceaf500b9e4de_stedelijk.svg' },
  { name: 'FC Urban',                    src: '/assets/666b1e828559258da51732d7_fcurban.svg' },
  { name: 'INC',                         src: '/assets/666b1e2df8dfb200a8592748_inc.svg' },
  { name: 'Grid To Great',               src: '/assets/666b1e249d3cee18df0968b9_gtg.svg' },
  { name: 'Het Personal Shop Event',     src: '/assets/666b1e459504aa63e6e1f331_hpse.svg' },
  { name: 'JORIS',                        src: '/assets/666b1e63cc22c4135eb6c8ce_joris.svg' },
  { name: 'MORE',                         src: '/assets/666b1e8bd2401543332cfd96_more.svg' },
  { name: 'Playside',                    src: '/assets/666b1ddc8b135642abcd198d_playside.svg' },
  { name: 'LG TBG',                      src: '/assets/6736544c7faf6be84d105b08_LG TBG liggend wit.svg' },
  { name: 'Aqqo',                         src: '/assets/673746018968a70fa29652ea_aqqo.svg' },
  { name: 'Transferendi',                src: '/assets/6753182e209d52f8acabcfb8_Transferendi_merk_on_paperwhite.svg' },
  { name: 'ADG',                          src: '/assets/6842f0eac75016427cbf4a01_adg-logo.svg' },
  { name: 'Koersmakers',                 src: '/assets/6842fd30d1d016857b5f1fc8_koersmakers.svg' },
  { name: 'Byont',                        src: '/assets/6842fd42b1deb78e946aa04c_byont.svg' },
]

// ── Globe destinations ────────────────────────
export const GLOBE_DESTS = [
  { name: 'Amsterdam',  center: [  4.9041,  52.3676], main: '#0E2C7D', alt: '#1a3a99' },
  { name: 'Tokyo',      center: [139.6917,  35.6895], main: '#8B1A2E', alt: '#c0273d' },
  { name: 'New York',   center: [ -74.006,  40.7128], main: '#5B3A8E', alt: '#7B4EC0' },
  { name: 'Sydney',     center: [151.2093, -33.8688], main: '#0E2C7D', alt: '#2454C7' },
  { name: 'Dubai',      center: [  55.2708, 25.2048], main: '#8B1A2E', alt: '#6B0F22' },
  { name: 'São Paulo',  center: [ -46.6333,-23.5505], main: '#5B3A8E', alt: '#3D2060' },
  { name: 'Cape Town',  center: [  18.4241,-33.9249], main: '#0E2C7D', alt: '#8B1A2E' },
  { name: 'London',     center: [  -0.1278, 51.5074], main: '#667eea', alt: '#764ba2' },
  { name: 'Singapore',  center: [ 103.8198,  1.3521], main: '#00cdac', alt: '#02aab0' },
  { name: 'Reykjavik',  center: [ -21.9426, 64.1265], main: '#96fbc4', alt: '#f9f586' },
]

// ── Skills / What-we-do ───────────────────────
export const SKILLS = [
  {
    id: 'discover',
    title: 'Discover',
    items: ['Strategy', 'Research', 'Analysis', 'Roadmap'],
  },
  {
    id: 'design',
    title: 'Design',
    video: 'https://files.clevermellow.co/clevermellow/showreel-design.mp4',
    items: ['UX/UI', 'Branding', 'Motion', 'Prototyping'],
  },
  {
    id: 'develop',
    title: 'Develop',
    video: 'https://files.clevermellow.co/clevermellow/showreel-dev.mp4',
    items: ['Webflow', 'React', 'Next.js', 'Headless CMS'],
  },
  {
    id: 'grow',
    title: 'Grow',
    video: 'https://files.clevermellow.co/clevermellow/showreel-grow.mp4',
    items: ['SEO', 'Analytics', 'Content', 'Campaigns'],
  },
]

// ── Team members ──────────────────────────────
export const TEAM = [
  { name: 'Ali Iz',       role: 'Creative Director', img: '/assets/6736499090416b7b4e12daec_AliIz_Portret.avif' },
  { name: 'Niels',        role: 'Developer',          img: '/assets/6867813f1b3a13d43c2c4410_niels-bakhuis.avif' },
  { name: 'Jordi',        role: 'Designer',           img: '/assets/68678101c047367187ddb961_Jordi.avif' },
  { name: 'Aron',         role: 'Designer',           img: '/assets/6867815053db30634bec32ba_aronzomer-groen.avif' },
  { name: 'Marysa',       role: 'Strategy',           img: '/assets/6904ba6dd4490eb73ece6c0e_marysa.jpeg' },
]
