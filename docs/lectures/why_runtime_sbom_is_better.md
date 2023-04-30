# What is runtime SBOM

- [SBOM types](#sbom-types)
- [Why runtime SBOM is better](#why-runtime-sbom-is-better)

## SBOM types

![](https://imgur.com/pMPxC8D.png)

(Source: [Types of Software Bill of Materials (SBOM) - CISA](https://www.cisa.gov/resources-tools/resources/types-software-bill-materials-sbom))

In this workshop, we will use the following binary classification:

- Static SBOM:
  - Types: `Prospective` to `Analyzed`
  - Def.: SBOM based on a lockfile
- Runtime SBOM:
  - Types: `Runtime`
  - Def.: SBOM based on a running process
  - Notes: `Deployed` can be said as a near-runtime SBOM

## Why runtime SBOM is better

Static SBOM is unreliable narrator since it only knows known. It's very easy to come off the rail. If you do `pip install requests`, it is untraceable.

Also, it can do nothing if there is no lockfile.

```bash
# Remove the lockfile from the directory
mv /app/java/gradle.lockfile /tmp
# Then sbom-tool can detect nothing
sbom-tool generate -b ./ -bc /app/java/ -nsb http://example.com -pn foo -pv 0.1 -ps foo
cat _manifest/spdx_2.2/manifest.spdx.json | jq ".packages[] | .externalRefs[]? | .referenceLocator"
```

> you may be getting false results from other approaches. Scanning file systems, code repos, or containers could easily fail to detect libraries accurately.
>
> library could be buried in a fat jar, war, or ear
> library could be shaded in another jar
> library could be included in the appserver, not the code repo
> library could be part of dynamically loaded code or plugin
> library could be many different versions with different classloaders in a single app
> library could be masked by use of slf4j or other layers
> library could be renamed, recompiled, or otherwise changed
>
> --- https://github.com/eclipse/jbom

## How to generate runtime SBOM

- Metadata based SBOM generation (Rust, Go)
- Interacting with a processing system (Python, Java)
  - Python: can get modules which can be used
  - Java: can get loaded classes on JVM
