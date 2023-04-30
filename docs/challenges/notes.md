# Notes on the hands-on challenges

- `sbom_workshop/` already has a scaffold for building CycloneDX SBOM
- A challenge is implementing a function incomplete
- An implementation of a challenge is testable by `pytest`
- You will be able to create SBOM by the CLI tool (`sbom-workshop-cli`) after finishing the challenges
- The CLI tools is built on [Typer](https://typer.tiangolo.com/)

```bash
$ sbom-workshop-cli python --help

 Usage: sbom-workshop-cli python [OPTIONS] COMMAND [ARGS]...

╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                       │
╰───────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────╮
│ requirements    Parse requirements.txt and build CycloneDX SBOM                                   │
│ site-packages   Build CycloneDX SBOM based on site packages used by running Python processes      │
╰───────────────────────────────────────────────────────────────────────────────────────────────────╯

$ sbom-workshop-cli java --help

 Usage: sbom-workshop-cli java [OPTIONS] COMMAND [ARGS]...

╭─ Options ─────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                       │
╰───────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────────────╮
│ gradle        Parse gradle.lockfile and build CycloneDX SBOM                                      │
│ jar           Parse JAR file and build CycloneDX SBOM                                             │
╰───────────────────────────────────────────────────────────────────────────────────────────────────╯
```
