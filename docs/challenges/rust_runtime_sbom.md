# Rust Runtime SBOM

> Know the exact crate versions used to build your Rust executable. Audit binaries for known bugs or security vulnerabilities in production, at scale, with zero bookkeeping.
>
> This works by embedding data about the dependency tree in JSON format into a dedicated linker section of the compiled executable.
>
> Linux, Windows and Mac OS are officially supported. All other ELF targets should work, but are not tested on CI. WASM is currently not supported, but patches are welcome.
>
> --- https://github.com/rust-secure-code/cargo-auditable

**JSON schema**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://rustsec.org/schemas/cargo-auditable.json",
  "title": "cargo-auditable schema",
  "description": "Describes the `VersionInfo` JSON data structure that cargo-auditable embeds into Rust binaries.",
  "type": "object",
  "required": ["packages"],
  "properties": {
    "packages": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/Package"
      }
    }
  },
  "definitions": {
    "DependencyKind": {
      "type": "string",
      "enum": ["build", "runtime"]
    },
    "Package": {
      "description": "A single package in the dependency tree",
      "type": "object",
      "required": ["name", "source", "version"],
      "properties": {
        "dependencies": {
          "description": "Packages are stored in an ordered array both in the `VersionInfo` struct and in JSON. Here we refer to each package by its index in the array. May be omitted if the list is empty.",
          "type": "array",
          "items": {
            "type": "integer",
            "format": "uint",
            "minimum": 0.0
          }
        },
        "kind": {
          "description": "\"build\" or \"runtime\". May be omitted if set to \"runtime\". If it's both a build and a runtime dependency, \"runtime\" is recorded.",
          "allOf": [
            {
              "$ref": "#/definitions/DependencyKind"
            }
          ]
        },
        "name": {
          "description": "Crate name specified in the `name` field in Cargo.toml file. Examples: \"libc\", \"rand\"",
          "type": "string"
        },
        "root": {
          "description": "Whether this is the root package in the dependency tree. There should only be one root package. May be omitted if set to `false`.",
          "type": "boolean"
        },
        "source": {
          "description": "Currently \"git\", \"local\", \"crates.io\" or \"registry\". Designed to be extensible with other revision control systems, etc.",
          "allOf": [
            {
              "$ref": "#/definitions/Source"
            }
          ]
        },
        "version": {
          "description": "The package's version in the [semantic version](https://semver.org) format.",
          "type": "string"
        }
      }
    },
    "Source": {
      "description": "Serializes to \"git\", \"local\", \"crates.io\" or \"registry\". Designed to be extensible with other revision control systems, etc.",
      "oneOf": [
        {
          "type": "string",
          "enum": ["CratesIo", "Git", "Local", "Registry"]
        },
        {
          "type": "object",
          "required": ["Other"],
          "properties": {
            "Other": {
              "type": "string"
            }
          },
          "additionalProperties": false
        }
      ]
    }
  }
}
```

(https://github.com/rust-secure-code/cargo-auditable/blob/master/cargo-auditable.schema.json)

## How to inspect a Rust executable

`dep-v0` section has the metadata.

![](https://i.imgur.com/eflM0ET.png)

### By `rust-audit-info`

https://crates.io/crates/rust-audit-info

```bash
cargo install rust-audit-info
rust-audit-info /path/to/file
```

> **Note**
> This commands do not work in the dev container.

### By `objcopy`

```bash
objcopy --dump-section .dep-v0=/dev/stdout /path/to/file | pigz -zd - | jq .

objcopy --dump-section .dep-v0=/dev/stdout /app/rust/hello_world | pigz -zd - | jq .
```

## By Python

```python
import lief, zlib, json

binary = lief.parse("/path/to/file")
audit_data_section = next(
    filter(lambda section: section.name == ".dep-v0", binary.sections)
)
json_string = zlib.decompress(audit_data_section.content)
print(json_string.decode())
```

```bash
$ sbom-workshop-cli rust audit-data /app/rust/target/release/hello_world | jq ".components"
[
  {
    "type": "library",
    "bom-ref": "96998d72-6fa3-4ac5-9ea3-ee5ea64a3d89",
    "name": "autocfg",
    "version": "1.1.0",
    "purl": "pkg:cargo/autocfg@1.1.0"
  },
  {
    "type": "library",
    "bom-ref": "f576ca8b-19a9-405a-b2f0-68e34a6921a0",
    "name": "chrono",
    "version": "0.4.24",
    "purl": "pkg:cargo/chrono@0.4.24"
  },
  {
    "type": "library",
    "bom-ref": "15fea585-940a-4490-a4e6-55eeeb487611",
    "name": "core-foundation-sys",
    "version": "0.8.3",
    "purl": "pkg:cargo/core-foundation-sys@0.8.3"
  },
  {
    "type": "library",
    "bom-ref": "a8ccc576-ab35-4167-8046-9e16e23d96b3",
    "name": "iana-time-zone",
    "version": "0.1.54",
    "purl": "pkg:cargo/iana-time-zone@0.1.54"
  },
  {
    "type": "library",
    "bom-ref": "39b46306-d61c-49fe-8240-418dd176c5a5",
    "name": "libc",
    "version": "0.2.140",
    "purl": "pkg:cargo/libc@0.2.140"
  },
  {
    "type": "library",
    "bom-ref": "c1f50662-0ac0-4e7d-80d5-8b7625fff05f",
    "name": "num-integer",
    "version": "0.1.45",
    "purl": "pkg:cargo/num-integer@0.1.45"
  },
  {
    "type": "library",
    "bom-ref": "044bb9e2-104e-4876-94b2-917ad2b76da3",
    "name": "num-traits",
    "version": "0.2.15",
    "purl": "pkg:cargo/num-traits@0.2.15"
  },
  {
    "type": "library",
    "bom-ref": "1d41450a-d87d-4f00-85a8-ae54e87c08a7",
    "name": "rust",
    "version": "0.1.0",
    "purl": "pkg:cargo/rust@0.1.0"
  },
  {
    "type": "library",
    "bom-ref": "71f11558-e73f-4540-8d08-9383dc22b36c",
    "name": "time",
    "version": "0.1.45",
    "purl": "pkg:cargo/time@0.1.45"
  }
]
```

(Dependencies of fishnet v2.6.8)
