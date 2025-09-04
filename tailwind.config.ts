import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  safelist: [
    // Tooltip classes for ThreatTypePieChart
    'text-white',
    'text-gray-200',
    'text-gray-300',
    'text-gray-400',
    'bg-slate-900',
    'border-slate-600',
    'border-slate-400',
    'border-slate-500',
    'bg-slate-600',
    'bg-slate-700',
    'shadow-2xl',
    'rounded-md',
    'backdrop-blur-sm',
    // Animation classes
    'transition-colors',
    'transition-all',
    'duration-300',
    'ease-in-out',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}

export default config
