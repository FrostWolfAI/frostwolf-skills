import { startService } from "./daemon.js";

/**
 * Entry point of the local service, started by the first hook that finds none
 * running. Takes the socket and log paths as arguments.
 */
async function main(): Promise<void> {
  const [socket, log, dataDir] = process.argv.slice(2);
  if (socket === undefined) {
    process.exitCode = 1;
    return;
  }

  const service = await startService({
    socket,
    ...(log === undefined ? {} : { log }),
    ...(dataDir === undefined ? {} : { dataDir }),
    onIdle: () => process.exit(0),
  });

  // Another service won the race to start. It serves every hook, so this one
  // has nothing to do.
  if (service === null) {
    return;
  }

  const stop = (): void => {
    void service.close().then(() => process.exit(0));
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

main().catch(() => {
  process.exit(1);
});
