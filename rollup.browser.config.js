import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from 'rollup-plugin-typescript2';
import pkg from './package.json';

// UMD build (for browsers)
export default {
  input: 'src/index.ts',
  output: {
    name: pkg.displayName,
    file: pkg.browser,
    format: 'umd',
    globals: {
      'asn1js': 'asn1js',
      '@ne1410s/text': 'ne_text',
    }
  },
  plugins: [
    resolve(), // find external modules
    commonjs(), // convert external modules to ES modules
    typescript()
  ]
};