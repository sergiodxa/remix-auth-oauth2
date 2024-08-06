import type { KnipConfig } from "knip";

// biome-ignore lint/style/noDefaultExport: Required by tool
export default {
	entry: ["./src/index.ts", "./scripts/exports.ts", "./src/index.test.ts"],
	typescript: true,
	ignoreDependencies: ["@arethetypeswrong/cli"],
} satisfies KnipConfig;
