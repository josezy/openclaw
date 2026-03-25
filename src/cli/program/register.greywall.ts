import type { Command } from "commander";

export function registerGreywallCommands(program: Command) {
  const greywall = program.command("greywall").description("Greywall sandbox policy management");

  greywall
    .command("generate-policy")
    .description("Generate a Greywall sandbox policy from active skills and plugins")
    .option("-o, --output <path>", "Write policy to file instead of stdout")
    .option("--save", "Write policy to default greywall.json location")
    .option("--audit", "Show what each skill/plugin contributes to the policy")
    .option("--include-undeclared", "Include skills/plugins without access manifests")
    .option("--apply-rules", "Ingest domain allow rules into GreyProxy")
    .option("--agent <id>", "Generate policy for a specific agent")
    .action(async (opts) => {
      const { greywallGeneratePolicy } = await import("../../commands/greywall-policy.js");
      await greywallGeneratePolicy(opts);
    });

  greywall
    .command("start")
    .description("Seed GreyProxy rules and start the gateway inside the greywall sandbox")
    .option("--profile <name>", "Greywall profile name", "openclaw")
    .allowUnknownOption(true)
    .allowExcessArguments(true)
    .action(async (opts, cmd) => {
      const { greywallStart } = await import("../../commands/greywall-policy.js");
      await greywallStart({
        profile: opts.profile,
        gatewayArgs: cmd.args,
      });
    });
}
