const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  mode: 'development',
  entry: './src/background.js',
  devtool: 'inline-source-map',
  plugins: [
    new HtmlWebpackPlugin({
      title: 'Development',
    }),
  ],
  module: {
    rules: [
      {
        test: /\.json/,
        type: 'asset/resource',
        generator: {
          filename: '[name][ext]'
        },
      },
      {
        test: /\.der/,
        type: 'asset/resource',
          generator: {
          filename: '[name][ext]'
        },
      }, 
      {
        test: /\.svg/,
        type: 'asset/resource',
          generator: {
          filename: '[name][ext]'
        },
      },

    ]
  },
  
  output: {
    filename: 'background.js',
    path: path.resolve(__dirname, 'dist'),
  },
};