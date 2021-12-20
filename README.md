# Remix Auth - Strategy Template

> A template for creating a new Remix Auth strategy.

If you want to create a new strategy for Remix Auth, you could use this as a template for your repository.

The repo installs the latest version of Remix Auth and do the setup for you to have tests, linting and typechecking.

## How to use it

1. In the `package.json` change `name` to your strategy name, also add a description and ideally an author, repository and homepage keys.
2. In `src/index.ts` change the `MyStrategy` for the strategy name you want to use.
3. Implement the strategy flow inside the `authenticate` method. Use `this.success` and `this.failure` to correctly send finish the flow.
4. In `tests/index.test.ts` change the tests to use your strategy and test it. Inside the tests you have access to `jest-fetch-mock` to mock any fetch you may need to do.
5. Once you are ready, set the secrets on Github
   - `NPM_TOKEN`: The token for the npm registry
   - `GIT_USER_NAME`: The you want the bump workflow to use in the commit.
   - `GIT_USER_EMAIL`: The email you want the bump workflow to use in the commit.

## Scripts

- `build`: Build the project for production using the TypeScript compiler (strips the types).
- `typecheck`: Check the project for type errors, this also happens in build but it's useful to do in development.
- `lint`: Runs ESLint againt the source codebase to ensure it pass the linting rules.
- `test`: Runs all the test using Jest.
