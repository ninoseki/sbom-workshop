# Go runtime SBOM

Go 1.18+ has `debug/buildinfo` for inspectng dependencies in a Go executable.

> The go command now embeds version control information in binaries. It includes the currently checked-out revision, commit time, and a flag indicating whether edited or untracked files are present. Version control information is embedded if the go command is invoked in a directory within a Git, Mercurial, Fossil, or Bazaar repository, and the main package and its containing main module are in the same repository. This information may be omitted using the flag -buildvcs=false.
>
> Additionally, the go command embeds information about the build, including build and tool tags (set with -tags), compiler, assembler, and linker flags (like -gcflags), whether cgo was enabled, and if it was, the values of the cgo environment variables (like CGO_CFLAGS). Both VCS and build information may be read together with module information using go version -m file or runtime/debug.ReadBuildInfo (for the currently running binary) or the new debug/buildinfo package.
>
> The underlying data format of the embedded build information can change with new go releases, so an older version of go may not handle the build information produced with a newer version of go. To read the version information from a binary built with go 1.18, use the go version command and the debug/buildinfo package from go 1.18+.
>
> --- https://tip.golang.org/doc/go1.18

**Buildinfo type**

```go
type BuildInfo struct {
	// GoVersion is the version of the Go toolchain that built the binary
	// (for example, "go1.19.2").
	GoVersion string

	// Path is the package path of the main package for the binary
	// (for example, "golang.org/x/tools/cmd/stringer").
	Path string

	// Main describes the module that contains the main package for the binary.
	Main Module

	// Deps describes all the dependency modules, both direct and indirect,
	// that contributed packages to the build of this binary.
	Deps []*Module

	// Settings describes the build settings used to build the binary.
	Settings []BuildSetting
}
```

See https://pkg.go.dev/runtime/debug#BuildInfo for more details.

## How to inspect a Go executable

`__go_buildinfo` section has the metadata.

![img](https://imgur.com/FIldtkc.png)

### By `go version`

```bash
 go help version                                                                                                                                                  15:22:47
usage: go version [-m] [-v] [file ...]

Version prints the build information for Go binary files.

Go version reports the Go version used to build each of the named files.

If no files are named on the command line, go version prints its own
version information.

If a directory is named, go version walks that directory, recursively,
looking for recognized Go binaries and reporting their versions.
By default, go version does not report unrecognized files found
during a directory scan. The -v flag causes it to report unrecognized files.

The -m flag causes go version to print each file's embedded
module version information, when available. In the output, the module
information consists of multiple lines following the version line, each
indented by a leading tab character.

See also: go doc runtime/debug.BuildInfo.
```

```bash
go version -m /path/to/file
```

### By Python

```py
from elftools.elf.elffile import ELFFile

with open("/path/to/file", "rb") as f:
    elf = ELFFile(f)

    build_info_section = next(
        (
            section
            for section in elf.iter_sections()
            if section.name == "__go_buildinfo" or section.name == ".go.buildinfo"
        ),
        None,
    )
    if build_info_section is not None:
        text = build_info_section.data().decode(errors="ignore")
        # very dirty way to get deps :D
        for line in text.splitlines():
            if line.startswith("dep\t"):
                print(line)
```

### By syft

```bash
$ syft /usr/local/bin/syft
 ✔ Indexed /usr/local/bin/syft
 ✔ Cataloged packages      [126 packages]
NAME                                              VERSION                                   TYPE
github.com/CycloneDX/cyclonedx-go                 v0.7.1-0.20221222100750-41a1ac565cce      go-module
github.com/Masterminds/goutils                    v1.1.1                                    go-module
github.com/Masterminds/semver/v3                  v3.2.0                                    go-module
github.com/Masterminds/sprig/v3                   v3.2.3                                    go-module
github.com/ProtonMail/go-crypto                   v0.0.0-20230217124315-7d5c6f04bbb8        go-module
...
```

(Dependencies of syft v0.79.0)
