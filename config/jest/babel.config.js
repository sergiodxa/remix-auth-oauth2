/* eslint-disable unicorn/no-empty-file */
/* eslint-disable unicorn/prefer-module */
/**
 * This Babel configuration is not being used by Remix to compile our app.
 * The reason to configure Babel in our project is because Jest needs this
 * file to support JSX and TypeScript. This is also the reason why the
 * preset-env targets is only the current version of Node.js
 */
module.exports = {
  presets: [
    [
      "@babel/preset-env",
      {
        targets: { node: "current" },
      },
    ],
    [
      "@babel/preset-react",
      {
        runtime: "automatic",
      },
    ],
    "@babel/preset-typescript",
  ],
};
