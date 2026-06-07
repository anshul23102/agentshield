/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        bg:      '#080808',
        surface: '#0f0f0f',
        card:    '#111111',
        'card-h':'#171717',
        'b1':    'rgba(255,255,255,0.06)',
        'b2':    'rgba(255,255,255,0.12)',
        'b3':    'rgba(255,255,255,0.20)',
        t1:      '#f0f0f0',
        t2:      '#888888',
        t3:      '#444444',
        accent:  '#0A84FF',
        danger:  '#FF3B30',
        safe:    '#30D158',
        warn:    '#FF9F0A',
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'sans-serif'],
        body:    ['Inter', 'sans-serif'],
        mono:    ['"IBM Plex Mono"', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', '14px'],
      },
      animation: {
        'fade-up':    'fadeUp 0.5s ease forwards',
        'fade-in':    'fadeIn 0.4s ease forwards',
        'pulse-dot':  'pulseDot 2s ease-in-out infinite',
        'spin-slow':  'spin 8s linear infinite',
        'count':      'countUp 0.8s ease-out forwards',
      },
      keyframes: {
        fadeUp:   { from: { opacity: 0, transform: 'translateY(12px)' }, to: { opacity: 1, transform: 'translateY(0)' } },
        fadeIn:   { from: { opacity: 0 }, to: { opacity: 1 } },
        pulseDot: { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.3 } },
      },
    },
  },
  plugins: [],
}
