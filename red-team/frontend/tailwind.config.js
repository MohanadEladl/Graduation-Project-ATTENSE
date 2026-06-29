/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono:    ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
        sans:    ['"Inter"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['"Rajdhani"', '"Inter"', 'ui-sans-serif', 'sans-serif'],
      },
      colors: {
        attense: {
          bg:       '#07090f',
          panel:    '#0c0f16',
          panel2:   '#10141d',
          border:   '#1a2030',
          text:     '#e6e8ee',
          muted:    '#7a8699',
          dim:      '#4a5363',
          red:      '#ff1535',
          redSoft:  '#cc0020',
          redGlow:  'rgba(255,21,53,0.35)',
          amber:    '#ffa724',
          mint:     '#2ee39a',
          violet:   '#8b2fff',
          cyan:     '#00c8ff',
        },
      },
      boxShadow: {
        'glow-red':    '0 0 0 1px rgba(255,21,53,0.35), 0 0 24px rgba(255,21,53,0.22)',
        'glow-mint':   '0 0 0 1px rgba(46,227,154,0.3),  0 0 20px rgba(46,227,154,0.16)',
        'glow-violet': '0 0 0 1px rgba(139,47,255,0.3),  0 0 20px rgba(139,47,255,0.16)',
        'glow-cyan':   '0 0 0 1px rgba(0,200,255,0.3),   0 0 20px rgba(0,200,255,0.14)',
        'inset-hair':  'inset 0 1px 0 rgba(255,255,255,0.04)',
      },
      animation: {
        'fade-up':     'fade-up 0.3s ease forwards',
        'slide-in':    'slide-in 0.25s ease forwards',
        'pulse-slow':  'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'blink':       'blink 1.2s step-start infinite',
        'shimmer':     'shimmer 2s linear infinite',
      },
      keyframes: {
        'fade-up':  { '0%': { opacity: 0, transform: 'translateY(10px)' }, '100%': { opacity: 1, transform: 'translateY(0)' } },
        'slide-in': { '0%': { opacity: 0, transform: 'translateX(8px)'  }, '100%': { opacity: 1, transform: 'translateX(0)' } },
        'blink':    { '0%,49%': { opacity: 1 }, '50%,100%': { opacity: 0 } },
        'shimmer':  { 'from': { backgroundPosition: '0 0' }, 'to': { backgroundPosition: '-200% 0' } },
      },
      backgroundImage: {
        'grid': "linear-gradient(rgba(255,21,53,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,21,53,0.04) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
}
