/* eslint-disable unicorn/prefer-module */
module.exports = {
	root: true,
	parser: "@typescript-eslint/parser",
	plugins: ["@typescript-eslint", "unicorn"],
	extends: [
		"plugin:unicorn/recommended",
		"plugin:@typescript-eslint/recommended",
		"prettier",
	],
	rules: {
		"prefer-const": "off",
		"@typescript-eslint/explicit-module-boundary-types": "off",
		"@typescript-eslint/no-non-null-assertion": "off",
		"no-unused-vars": "off",
		"no-var": "off",
		"unicorn/no-null": "off",
		"unicorn/prefer-node-protocol": "off",
		"unicorn/filename-case": "off",
		"unicorn/prevent-abbreviations": "off",
	},
};
