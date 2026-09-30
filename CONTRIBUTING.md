# Contributing

Start with the offline demo and the selected smoke suite in [Setup](docs/setup.md).

Useful first contributions:

- Replace remaining installation-specific defaults with explicit configuration.
- Improve clean-install documentation and dependency separation.
- Add a synthetic, guided memory-review example.
- Improve the workbench's accessibility and English/Chinese labels.

For bugs, include the command, Python/OS version, expected behavior and a minimal
synthetic reproduction. Remove credentials, private prompts, account identifiers
and runtime archives before attaching logs.

Keep pull requests focused. Explain the user-visible change and the checks run.
Tests should use temporary roots and mocked providers, with no personal data or
live model calls. Never weaken owner-verification or replay-protection behavior
to make a test pass.
