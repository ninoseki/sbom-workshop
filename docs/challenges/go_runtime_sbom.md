# Go runtime SBOM

Go 1.18+ has `debug/buildinfo` to inspect dependencies in a Go executable.

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

(https://pkg.go.dev/runtime/debug#BuildInfo)

## How to inspect a Go executable

`__go_buildinfo` section has the metadata.

![](https://imgur.com/FIldtkc.png)

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
import lief, zlib, json

binary = lief.parse("/path/to/file")
build_info_section = next(
    filter(lambda section: section.name == "__go_buildinfo", binary.sections)
)

text = bytes(build_info_section.content).decode(errors="ignore")
# very dirty way to get deps :D
for line in text.splitlines():
    if line.startswith("dep\t"):
        print(line)
```

```
dep     github.com/CycloneDX/cyclonedx-go       v0.7.1-0.20221222100750-41a1ac565cce    h1:o5r3msApzvtE5LhcMkxWaKernD/PK0HpMccu7ywBj5Q=
dep     github.com/DataDog/zstd v1.4.5  h1:EndNeuB0l9syBZhut0wns3gV1hL8zX8LIu6ZiVHWLIQ=
dep     github.com/Masterminds/goutils  v1.1.1  h1:5nUrii3FMTL5diU80unEVvNevw1nH4+ZV4DSLVJLSYI=
dep     github.com/Masterminds/semver/v3        v3.2.0  h1:3MEsd0SM6jqZojhjLWWeBY+Kcjy9i6MQAeY7YgDP83g=
dep     github.com/Masterminds/sprig/v3 v3.2.3  h1:eL2fZNezLomi0uOLqjQoN6BfsDD+fyLtgbJMAj9n6YA=
dep     github.com/acobaugh/osrelease   v0.1.0  h1:Yb59HQDGGNhCj4suHaFQQfBps5wyoKLSSX/J/+UifRE=
dep     github.com/adrg/xdg     v0.4.0  h1:RzRqFcjH4nE5C6oTAxhBtoE2IRyjBSa62SCbyPidvls=
dep     github.com/anchore/go-logger    v0.0.0-20220728155337-03b66a5207d8      h1:imgMA0gN0TZx7PSa/pdWqXadBvrz8WsN6zySzCe4XX0=
dep     github.com/anchore/go-macholibre        v0.0.0-20220308212642-53e6d0aaf6fb      h1:iDMnx6LIjtjZ46C0akqveX83WFzhpTD3eqOthawb5vU=
dep     github.com/anchore/go-struct-converter  v0.0.0-20221118182256-c68fdcfa2092      h1:aM1rlcoLz8y5B2r4tTLMiVTrMtpfY0O8EScKJxaSaEc=
dep     github.com/anchore/go-version   v1.2.2-0.20200701162849-18adb9c92b9b    h1:e1bmaoJfZVsCYMrIZBpFxwV26CbsuoEh5muXD5I1Ods=
dep     github.com/anchore/packageurl-go        v0.1.1-0.20230104203445-02e0a6721501    h1:AV7qjwMcM4r8wFhJq3jLRztew3ywIyPTRapl2T1s9o8=
dep     github.com/anchore/stereoscope  v0.0.0-20230301191755-abfb374a1122      h1:Oe2PE8zNbJH4nGZoCIC/VZBgpr62BInLnUqIMZICUOk=
dep     github.com/andybalholm/brotli   v1.0.4  h1:V7DdXeJtZscaqfNuAdSRuRFzuiKlHSC/Zh3zl9qY3JY=
...
```

(Dependencies of syft v0.75.0)
