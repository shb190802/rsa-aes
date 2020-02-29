import babel from 'rollup-plugin-babel'

module.exports = {
  input: 'src/index-node.js',
  output: [{
    file: 'dist/main-cjs.js',
    format: 'cjs'
  }],
  plugins: [babel({
    exclude: '**/node_modules/**'
  })]
}