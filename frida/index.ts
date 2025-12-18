import frida from "frida";
import { execSync } from "child_process";

function findPythonPid(): number | null {
  // Get PID from command line argument or find python process
  const pidArg = process.argv[2];
  if (pidArg) {
    const pid = parseInt(pidArg, 10);
    if (!isNaN(pid)) return pid;
  }
  
  try {
    const result = execSync(
      `powershell.exe -Command "(Get-Process -Name 'python' -ErrorAction SilentlyContinue | Select-Object -First 1).Id"`,
      { encoding: "utf-8" }
    );
    const pid = parseInt(result.trim(), 10);
    return isNaN(pid) ? null : pid;
  } catch {
    return null;
  }
}

async function main() {
  console.log("Neewer DLL Deep Trace - Frida Hook");
  console.log("=".repeat(60));

  const pid = findPythonPid();
  if (!pid) {
    console.log("[-] No Python process found!");
    console.log("    Usage: bun run index.ts <PID>");
    console.log("    Or start trigger_send.py first.");
    process.exit(1);
  }

  console.log(`[+] Attaching to PID: ${pid}`);

  // Build the agent TypeScript to JavaScript
  const build = await Bun.build({
    entrypoints: ["./agent.ts"],
    target: "browser",
    minify: false,
  });

  if (!build.success) {
    console.log("[-] Failed to build agent:");
    build.logs.forEach((log) => console.log(log));
    process.exit(1);
  }

  const agentCode = await build.outputs[0].text();

  try {
    const session = await frida.attach(pid);
    console.log("[+] Attached to process");

    const script = await session.createScript(agentCode);

    script.message.connect((message) => {
      if (message.type === "send") {
        console.log((message as frida.SendMessage).payload);
      } else if (message.type === "error") {
        console.log(`[ERROR] ${(message as frida.ErrorMessage).stack}`);
      }
    });

    await script.load();

    console.log();
    console.log("=".repeat(60));
    console.log("Hooks active! Click ON/OFF button in Neewer Control Center!");
    console.log("Press Ctrl+C to stop.");
    console.log("=".repeat(60));
    console.log();

    // Keep running until Ctrl+C
    process.on("SIGINT", async () => {
      console.log("\nDetaching...");
      await session.detach();
      console.log("Done.");
      process.exit(0);
    });

    // Keep the process alive
    await new Promise(() => {});
  } catch (e) {
    console.log(`[-] Error: ${e}`);
    process.exit(1);
  }
}

main();
