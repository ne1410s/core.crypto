import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import { terser } from 'rollup-plugin-terser';
import typescript from 'rollup-plugin-typescript2';
import pkg from './package.json';

// UMD build (for browsers)
export default {
  input: 'src/index.ts',
  output: {
    name: 'ne_crypto',
    file: pkg.browser,
    format: 'umd',
    globals: {
      'asn1js': 'asn1js',
      'node-webcrypto-ossl': 'WebCrypto',
      '@ne1410s/text': 'ne_text',
    }
  },
  plugins: [
    resolve(), // find external modules  // TODO
    commonjs(), // convert external modules to ES modules
    typescript(),
    terser({
      include: '*.umd.min.js'
    }),
  ]
};