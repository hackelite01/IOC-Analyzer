import { nextEslintConfig } from '@next/eslint-config-next';

/** @type {import('eslint').Linter.Config} */
const config = {
  extends: ['next/core-web-vitals', 'next/typescript'],
  rules: {
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/no-explicit-any': 'warn',
  },
};

export default config;
