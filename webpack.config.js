const path = require('path')
const CopyWebpackPlugin = require('copy-webpack-plugin')

module.exports = {
	entry: {
		math: './src/index'
	},
	// mode: "development || "production",
	output: {
		path: path.resolve(__dirname, 'dist'),
		webassemblyModuleFilename: "[modulehash].wasm",
		publicPath: "js/"
	},
	module: {
		rules: [
			{
				test: /\.wasm$/,
				type: "webassembly/experimental"
			}
		]
	},
	optimization: {
		occurrenceOrder: true // To keep filename consistent between different modes (for example building only)
	},
	plugins: [
		new CopyWebpackPlugin([ {from: './src/*.d.ts', flatten: true } ])
	]
};
