/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ['class'],
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // ── Legacy shade scales (kept for pages/CSS not yet migrated to
        //    the semantic tokens below — safe to remove once every page
        //    uses the semantic names instead). ──────────────────────────
        danger: {
          50: '#fef2f2', 100: '#fee2e2', 200: '#fecaca', 300: '#fca5a5', 400: '#f87171',
          500: '#ef4444', 600: '#dc2626', 700: '#b91c1c', 800: '#991b1b', 900: '#7f1d1d',
        },

        // ── Semantic design tokens (shadcn/ui convention) — sourced from
        //    CSS custom properties defined in src/index.css, so the whole
        //    theme lives in one place instead of scattered !important
        //    overrides. RGB-triple format enables opacity modifiers
        //    (e.g. bg-primary/10). ────────────────────────────────────
        background: 'rgb(var(--background) / <alpha-value>)',
        foreground: 'rgb(var(--foreground) / <alpha-value>)',
        card: {
          DEFAULT: 'rgb(var(--card) / <alpha-value>)',
          foreground: 'rgb(var(--card-foreground) / <alpha-value>)',
        },
        popover: {
          DEFAULT: 'rgb(var(--popover) / <alpha-value>)',
          foreground: 'rgb(var(--popover-foreground) / <alpha-value>)',
        },
        primary: {
          // Legacy blue-500-ish shade scale kept for any lingering
          // bg-primary-600 references from before the redesign.
          50: '#eff6ff', 100: '#dbeafe', 200: '#bfdbfe', 300: '#93c5fd', 400: '#60a5fa',
          500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8', 800: '#1e40af', 900: '#1e3a8a',
          DEFAULT: 'rgb(var(--primary) / <alpha-value>)',
          foreground: 'rgb(var(--primary-foreground) / <alpha-value>)',
        },
        secondary: {
          DEFAULT: 'rgb(var(--secondary) / <alpha-value>)',
          foreground: 'rgb(var(--secondary-foreground) / <alpha-value>)',
        },
        muted: {
          DEFAULT: 'rgb(var(--muted) / <alpha-value>)',
          foreground: 'rgb(var(--muted-foreground) / <alpha-value>)',
        },
        accent: {
          DEFAULT: 'rgb(var(--accent) / <alpha-value>)',
          foreground: 'rgb(var(--accent-foreground) / <alpha-value>)',
        },
        destructive: {
          DEFAULT: 'rgb(var(--destructive) / <alpha-value>)',
          foreground: 'rgb(var(--destructive-foreground) / <alpha-value>)',
        },
        border: 'rgb(var(--border) / <alpha-value>)',
        input: 'rgb(var(--input) / <alpha-value>)',
        ring: 'rgb(var(--ring) / <alpha-value>)',

        // ── DLP severity palette — distinct from shadcn's generic
        //    destructive/warning so badges can carry real security
        //    meaning (critical/high/medium/low/info) independent of
        //    "destructive action" button semantics. Soft tinted-bg +
        //    saturated-text pattern, not solid fills. ──────────────────
        success: {
          50: '#f0fdf4', 100: '#dcfce7', 200: '#bbf7d0', 300: '#86efac', 400: '#4ade80',
          500: '#22c55e', 600: '#16a34a', 700: '#15803d', 800: '#166534', 900: '#14532d',
          DEFAULT: 'rgb(var(--success) / <alpha-value>)',
          bg: 'rgb(var(--success-bg) / <alpha-value>)',
        },
        warning: {
          50: '#fffbeb', 100: '#fef3c7', 200: '#fde68a', 300: '#fcd34d', 400: '#fbbf24',
          500: '#f59e0b', 600: '#d97706', 700: '#b45309', 800: '#92400e', 900: '#78350f',
          DEFAULT: 'rgb(var(--warning) / <alpha-value>)',
          bg: 'rgb(var(--warning-bg) / <alpha-value>)',
        },
        critical: {
          DEFAULT: 'rgb(var(--critical) / <alpha-value>)',
          bg: 'rgb(var(--critical-bg) / <alpha-value>)',
        },
        info: {
          DEFAULT: 'rgb(var(--info) / <alpha-value>)',
          bg: 'rgb(var(--info-bg) / <alpha-value>)',
        },

        // ── "cs-*" compatibility layer — see the comment on --cs-panel in
        //    src/index.css. Aliases the CyberSentinel-ported pages' token
        //    names onto this app's obsidian palette. ─────────────────────
        cs: {
          ink: 'rgb(var(--foreground) / <alpha-value>)',
          'ink-2': 'rgb(var(--foreground) / 0.78)',
          muted: 'rgb(var(--muted-foreground) / <alpha-value>)',
          'muted-2': 'rgb(var(--muted-foreground) / 0.65)',
          hair: 'rgb(var(--border) / <alpha-value>)',
          'hair-2': 'rgb(var(--border) / <alpha-value>)',
          indigo: 'rgb(var(--primary) / <alpha-value>)',
          'indigo-faint': 'rgb(var(--primary) / 0.12)',
          crit: 'rgb(var(--critical) / <alpha-value>)',
          med: 'rgb(var(--warning) / <alpha-value>)',
          panel: 'rgb(var(--card) / <alpha-value>)',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
        xl: 'calc(var(--radius) + 4px)',
        'cs-sm': 'calc(var(--radius) - 4px)',
        'cs-pill': '9999px',
      },
      fontFamily: {
        sans: [
          'Inter var', 'Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI',
          'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif',
        ],
        mono: [
          'JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace',
        ],
      },
      boxShadow: {
        'glow-primary': '0 0 0 1px rgb(var(--primary) / 0.4), 0 0 24px -4px rgb(var(--primary) / 0.35)',
        'glow-critical': '0 0 0 1px rgb(var(--critical) / 0.4), 0 0 24px -4px rgb(var(--critical) / 0.35)',
      },
      keyframes: {
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' },
        },
        'in': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up': 'accordion-up 0.2s ease-out',
        in: 'in 0.15s ease-out',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
}
