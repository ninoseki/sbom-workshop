# How to create SBOM

- [Mark it yourself]()
  - [CycloneDX/cyclonedx-python-lib](#cyclonedxcyclonedx-python-lib)
- [Tools](#tools)
  - [microsoft/sbom-tool](#microsoftsbom-tool)
  - [anchore/syft](#anchoresyft)
  - [advanced-security/gh-sbom](#advanced-securitygh-sbom)

## Code it yourself

### CycloneDX/cyclonedx-python-lib

> This CycloneDX module for Python can generate valid CycloneDX bill-of-material document containing an aggregate of all project dependencies.
>
> --- [CycloneDX/cyclonedx-python-lib](https://github.com/CycloneDX/cyclonedx-python-lib) ([Docs](https://cyclonedx-python-library.readthedocs.io/en/latest/))

```python
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.output import get_instance
from cyclonedx.schema import OutputFormat
from packageurl import PackageURL

component_name = "requests"
component_version = "2.18.1"

component = Component(
    name=component_name,
    version=component_version,
    purl=PackageURL(type="pypi", name=component_name, version=component_version),
)

bom = Bom(components=[component])

output_instance = get_instance(bom, output_format=OutputFormat.JSON)
print(output_instance.output_as_string())
```

## Tools

### microsoft/sbom-tool

> The SBOM tool is a highly scalable and enterprise ready tool to create SPDX 2.2 compatible SBOMs for any variety of artifacts.
>
> --- https://github.com/microsoft/sbom-tool

> **Warning**
>
> `sbom-tool` does not work in the dev container with ARM based Mac (and also Windows?).
> Please see the workaround section if you are using ARM Mac.

**Usage**

```bash
sbom-tool generate -b <drop path> -bc <build components path> -pn <package name> -pv <package version> -ps <package supplier> -nsb <namespace uri base>
```

```bash
# create SPDX SBOM from requirements.txt
sbom-tool generate -b ./ -bc /app/python/ -nsb http://example.com -pn foo -pv 0.1 -ps foo
cat _manifest/spdx_2.2/manifest.spdx.json | jq ".packages[] | .externalRefs[]? | .referenceLocator"

rm -rf _manifest/

# create SPDX SBOM from gradle.lockfile
sbom-tool generate -b ./ -bc /app/java/ -nsb http://example.com -pn foo -pv 0.1 -ps foo
cat _manifest/spdx_2.2/manifest.spdx.json | jq ".packages[] | .externalRefs[]? | .referenceLocator"
```

#### ARM Mac workaround

Please try the tool in the host machine instead.

- https://github.com/microsoft/sbom-tool/releases/tag/v1.0.2

```bash
# For ARM Mac
wget https://github.com/microsoft/sbom-tool/releases/download/v1.0.2/sbom-tool-osx-x64
chmod +x sbom-tool-osx-x64

./sbom-tool-osx-x64 generate -b ./ -bc ./.devcontainer/python/ -nsb http://example.com -pn foo -pv 0.1 -ps foo
./sbom-tool-osx-x64 generate -b ./ -bc ./.devcontainer/java/ -nsb http://example.com -pn foo -pv 0.1 -ps foo
```

#### How it works

`sbom-tool` scans the filesystem along with [microsoft/component-detection](https://github.com/microsoft/component-detection).

`component-detection` supports the following ecosystems.

| Ecosystem | Detection mechanisms                                                                                                       |
| --------- | -------------------------------------------------------------------------------------------------------------------------- |
| Cargo     | `Cargo.lock` or `Cargo.toml`                                                                                               |
| CocoaPods | `Podfile.lock`                                                                                                             |
| Go        | `go list -m -json all`, `go mod graph`, `go.mod`, `go.sum`                                                                 |
| Gradle    | `.lockfile`                                                                                                                |
| Maven     | `pom.xml` or `mvn dependency:tree -f {pom.xml}`                                                                            |
| NPM       | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `lerna.json`,`yarn.lock` (Yarn), `pnpm-lock.yaml` (Pnpm), etc. |
| NuGet     | `project.assets.json`, `.nupkg`, `.nuspec`, `nuget.config`                                                                 |
| PyPI      | `setup.py`, `requirements.txt`, `poetry.lock` (Poetry), etc.                                                               |
| RubyGems  | `Gemfile.lock`                                                                                                             |

(Based on `sbom-tool` v1.0.2 / `component-detection` v3.3.5)

See https://github.com/microsoft/component-detection/blob/main/docs/feature-overview.md for more details.

### anchore/syft

> A CLI tool and Go library for generating a Software Bill of Materials (SBOM) from container images and filesystems. Exceptional for vulnerability detection when used with a scanner like Grype.
>
> --- https://github.com/anchore/syft

**Usage**

```bash
syft <image_or_path> -o <format>
```

```bash
syft /app/python/ -o cyclonedx-json | jq ".components[] | .purl"
syft /app/java/ -o cyclonedx-json | jq ".components[] | .purl"
```

#### How it works

`syft` scans the filesystem with supporting the following ecosystems and others.

| Ecosystem            | Detection mechanisms                                                                  |
| -------------------- | ------------------------------------------------------------------------------------- |
| .NET                 | `.deps.json`                                                                          |
| Cargo                | Inspecting Rust executable (`cargo-audit` is required), `Cargo.lock`                  |
| CocoaPods            | `Podfile.lock`                                                                        |
| Conan (C/C++)        | `conanfile.txt`, `conanfile.lock`                                                     |
| Go                   | Inspecting Go executable, `go.mod`                                                    |
| Stack (Haskell)      | `stack.yaml`, `stack.yaml.lock`                                                       |
| Maven                | `MANIFEST.MF`, `pom.properties`, `pom.xml`                                            |
| NPM                  | `package.json`, `package-lock.json`, `yarn.lock` (Yarn), `pnpm-lock.yaml` (Pnpm)      |
| Packagist (Composer) | `composer.lock`, `installed.json`                                                     |
| Pub (Dart)           | `pubspec.lock`                                                                        |
| PyPI                 | `setup.py`, `requirements.txt`, `pipfile.lock` (Pipenv), `poetry.lock` (Poetry), etc. |
| RubyGems             | `Gemfile.lock`, `.gemspec`                                                            |
| Hex                  | `mix.lock`                                                                            |
| Rebar3               | `rebar.lock`                                                                          |

(Based on `syft` v0.79.0)

See https://github.com/anchore/syft/tree/main/syft/pkg/cataloger for more details.

### advanced-security/gh-sbom

> This is a gh CLI extension that outputs JSON SBOMs (in SPDX or CycloneDX format) for your GitHub repository using information from Dependency graph.
>
> --- https://github.com/advanced-security/gh-sbom

> **Warning**
>
> `gh` is not installed in the dev container.

**Usage**

```bash
$ gh sbom --help
Usage of gh-sbom:
  -c, --cyclonedx           Use CycloneDX SBOM format. Default is to use SPDX.
  -l, --license             Include license information from clearlydefined.io in SBOM.
  -r, --repository string   Repository to query. Current directory used by default.
pflag: help requested

# SPDX
$ gh sbom | jq
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "github.com/...",
  "documentNamespace": "https://spdx.org/spdxdocs/github.com/...",
  "creationInfo": {
    "creators": [
      "Organization: GitHub, Inc",
      "Tool: gh-sbom-0.0.8"
    ],
    "created": "2023-04-09T09:51:22Z"
  },
  "packages": [...]
}

# CycloneDX
$ gh sbom -c | jq
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2023-04-09T09:49:51Z",
    "tools": [
      {
        "vendor": "advanced-security",
        "name": "gh-sbom",
        "version": "0.0.8"
      }
    ],
    "licenses": [
      {
        "expression": "CC0-1.0"
      }
    ]
  },
  "components": [...]
}
```

## How it works

> The recommended formats explicitly define which versions are used for all direct and all indirect dependencies. If you use these formats, your dependency graph is more accurate. It also reflects the current build set up and enables the dependency graph to report vulnerabilities in both direct and indirect dependencies. Indirect dependencies that are inferred from a manifest file (or equivalent) are excluded from the checks for insecure dependencies.
>
> --- https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph#supported-package-ecosystems

| Ecosystem            | Detection mechanisms                                                      |
| -------------------- | ------------------------------------------------------------------------- |
| .NET                 | `.csproj`, `.vbproj`, `.nuspec`, `.vcxproj`, `.fsproj`, `packages.config` |
| Cargo                | `Cargo.lock`, `Cargo.toml`                                                |
| Go                   | `go.mod`                                                                  |
| Maven                | `pom.xml`                                                                 |
| NPM                  | `package.json`, `package-lock.json`, `yarn.lock` (Yarn)                   |
| Packagist (Composer) | `composer.lock`, `composer.json`                                          |
| Pub (Dart)           | `pubspec.lock`, `pubsec.yaml`                                             |
| PyPI                 | `requirements.txt`, `pipfile.lock` (Pipenv), `poetry.lock` (Poetry), etc. |
| RubyGems             | `Gemfile.lock`, `.gemspec` , `Gemfile`                                    |

The graph is probably based on Dependantbot.

- https://github.com/dependabot/dependabot-core
- https://github.com/dependabot/dependabot-script
