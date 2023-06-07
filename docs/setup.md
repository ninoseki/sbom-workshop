# Introduction of the lab env

- [Introduction of the lab env](#introduction-of-the-lab-env)
- [How to setup the lab env](#how-to-setup-the-lab-env)
- [How to confirm whether you are ready or not](#how-to-confirm-whether-you-are-ready-or-not)
- [Directory structure](#directory-structure)

## The lab env

Please install Docker Desktop and VS Code (with Remode Development extension pack) first.

- Docker Desktop 2.0+ (Linux: Docker CE/EE 18+ and Docker Compose 1.2+)
- VS Code + [Remote Development extension pack](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack)
  - Dev Container: `python:3.11` (Debian 11)
  - Installed packages:
    - Dev/utility:
      - [Poetry](https://python-poetry.org/)
      - tree
      - git
      - vim
      - curl
      - wget
      - [HTTPie](https://httpie.io/)
      - jq
      - yq
      - pigz
    - SBOM/OSV:
      - [microsoft/sbom-tool](https://github.com/microsoft/sbom-tool)
      - [anchore/syft](https://github.com/anchore/syft)
      - [google/osv-scanner](https://github.com/google/osv-scanner)

## How to setup the lab env

Please make sure to install the [Remote Development extension pack](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack) before proceeding further.

```bash
git clone https://github.com/ninoseki/sbom-workshop
code sbom-workshop
```

> **Note**
>
> Please follow [this instruction](https://code.visualstudio.com/docs/setup/mac#_launching-from-the-command-line) if you are unable to run `code` command

Click the bottom left corner button (Open a Remote Window) of VS Code.

![img](https://imgur.com/qoMiIpW.png)

And select "Reopen in Container".

![img](https://imgur.com/O4w0EYe.png)

It will start a dev container automatically.

See [VS Code: Quick start: Open an existing folder in a container](https://code.visualstudio.com/docs/devcontainers/containers#_quick-start-open-an-existing-folder-in-a-container) for more details.

## How to confirm whether you are ready or not

```bash
# in the host machine
$ docker ps | grep vsc-sbom-workshop
91a0b686f07c   vsc-sbom-workshop-44d779f9d1a0af24f7d968b3bdfe4417   "/bin/sh -c 'echo Co…"   54 seconds ago   Up 53 seconds             compassionate_knuth
```

```bash
# in the dev container

# check poetry is installed
$ poetry --version
Poetry (version 1.4.2)

# check pytest
$ pytest --version
pytest 7.2.2

# check Python app is running
$ curl localhost:8000
{"message":"hello, world!"}

# check Java app is running
$ curl localhost:8080
{"timestamp":"2022-11-12T07:10:56.045+00:00","status":400,"error":"Bad Request","path":"/"}
```

If you fail to check Python/Java app's running status by curl, please execute the following command.

```bash
# the script kicks off the apps
/app/postStartCommand.sh

# then it will work
curl localhost:8000
curl localhost:8080
```

If you still have the issue, please rebuild the container.

> **Note**
>
> Python requirements for the hands-on challenges are installed in the virtual environment via Poetry. It is activated by default.

```bash
$ python ...
$ pytest ...
# or
$ deactivate
$ poetry run python ...
$ poetry run pytest
```

## Directory structure

| Path                              | Desc.                               |
| --------------------------------- | ----------------------------------- |
| `/workspaces/sbom-workshop`       | A VS Code workspace                 |
| `/workspaces/sbom-workshop/.venv` | A virtualenv path for the workspace |

| Path           | Desc.                |
| -------------- | -------------------- |
| `/app/java/`   | Java app directory   |
| `/app/python/` | Python app directory |
| `/app/rust/`   | Rust app directory   |
| `/app/go/`     | Go app directory     |
