import type { Config } from 'tailwindcss';
import animate from 'tailwindcss-animate';
import forms from '@tailwindcss/forms';

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        'threat-critical': '#ef4444',
        'threat-high': '#f97316',
        'threat-medium': '#eab308',
        'threat-low': '#3b82f6',
        'surface-base': '#020617',
        'surface-elevated': '#0f172a',
        'surface-border': '#1e293b',
        'accent-cyan': '#06b6d4',
        'accent-glow': 'rgba(6, 182, 212, 0.15)',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      keyframes: {
        scan: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
        'fade-in': {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        scan: 'scan 1.6s linear infinite',
        'fade-in': 'fade-in 200ms ease-out',
      },
    },
  },
  plugins: [forms, animate],
};

export default config;

