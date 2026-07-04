# ATTENSE — React + Vite

## Prerequisites
- Node.js 18+
- npm 9+

## Setup

```bash
# 1. Install dependencies
npm install

# 2. Copy assets from the original clevermellow project
cp -r ../clevermellow/assets ./public/assets
cp ../clevermellow/fortress-viewer.html ./public/
cp ../clevermellow/attense-enterprise.html ./public/
cp ../clevermellow/cases.html ./public/
cp ../clevermellow/manifesto.html ./public/

# 3. Start development server
npm run dev

# 4. Build for production
npm run build
```

## Project Structure

```
src/
├── main.jsx            — React entry point
├── App.jsx             — Root component, Lenis + GSAP setup
├── data/
│   └── index.js        — ALL static data (cases, logos, nav, globe) — single source of truth
├── hooks/
│   ├── useGlobe.js     — D3 globe animation hook
│   ├── useCaseTilt.js  — 3D card tilt on mouse move
│   └── useLenis.js     — Lenis smooth scroll
└── components/
    ├── Nav.jsx
    ├── Hero.jsx
    ├── LogoCarousel.jsx
    ├── CasesSection.jsx
    ├── CaseCard.jsx
    ├── WhatWeDo.jsx
    └── Footer.jsx
```

## Colors
- Navy:   #0E2C7D
- Purple: #5B3A8E
- Red:    #8B1A2E
- Beige:  #F0ECE3
