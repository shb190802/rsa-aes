import babel from 'rollup-plugin-babel'

module.exports = {
  input: 'src/index.js',
  output: [{
    file: 'dist/main-esm.js',
    format: 'esm'
  },{
    file: 'dist/main-umd.js',
    format: 'umd',
    name: 'RsaAes'
  }],
  plugins: [babel({
    exclude: '**/node_modules/**'
  })]
}