<p align="center">
  <img src="docs/banner.svg" alt="Log Howl — Dispersal Wolves" width="100%">
</p>

# Log Howl

**Turn meaningful log lines into restrained alerts.**

Watches rotating local logs, applies regular-expression rules, suppresses repeats, and emits JSON, console, or webhook events.

## Start

```console
python src/log_howl.py watch --config examples/rules.json
```

For a global `log-howl` command, run `python -m pip install .`.

Run the command with `--help` for every option. The tool works locally, collects no telemetry, and supports machine-readable output where applicable.

## Principles

- **Local first.** Host data stays on the host unless you explicitly configure a webhook.
- **Safe by default.** Inspection is read-only and mutation requires a deliberate command.
- **Small contract.** The tool solves one defensive job and reports its limits plainly.
- **Scriptable.** Stable exit codes and structured output make automation practical.

## Platform

The initial release targets Linux. Portable behavior is also tested on Windows where the underlying operating-system facilities allow it. See [the threat model](docs/threat-model.md) for trust boundaries and non-goals.

## Development

This repository uses **Python** and the standard library only. Copy `examples/rules.json`, point it at local logs, and add a webhook only when events should leave the host.

```console
python -m compileall -q src
python -m unittest discover -s tests -v
```

## License

[MIT](LICENSE) © Dispersal Wolves.
