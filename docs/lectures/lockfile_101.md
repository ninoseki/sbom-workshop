# Lock file 101

## What is a lock file?

> A lock file contains important information about installed packages and it should always be committed into your Package Manager source repositories. Not committing the lock file to your source control results in installing two different modules from the same dependency definition.
>
> A lock file:
>
> - Is generated automatically for any operation
> - Describes the dependency tree and its changes, so the coworkers are guaranteed to install exactly the same dependencies
>   -Lets you "travel back in time" and check any former dependency tree
> - Allows your Package Manager to skip repeated metadata resolutions for previously-installed packages and, therefore, makes the installation much faster
>
> --- https://developerexperience.io/articles/lockfile

### Examples

- Maven (Java): `pom.xml`
  - Ref. https://maven.apache.org/guides/introduction/introduction-to-the-pom
  - E.g. https://github.com/apache/spark/blob/master/pom.xml
- Gradle (Java): `gradle.lockfile`
  - Ref. https://docs.gradle.org/current/userguide/dependency_locking.html
  - E.g. https://github.com/microsoft/ApplicationInsights-Java/blob/main/etw/java/gradle.lockfile
- NPM (Node.js): `package-lock.json`
  - Ref. https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json
  - E.g. https://github.com/twbs/bootstrap/blob/main/package-lock.json
- RubyGems (Ruby): `Gemfile.lock`
  - Ref. https://bundler.io/guides/rationale.html
  - E.g. https://github.com/rails/rails/blob/main/Gemfile.lock
- Composer (PHP): `composer.lock`
  - Ref. https://getcomposer.org/doc/01-basic-usage.md
  - E.g. https://github.com/Automattic/jetpack/blob/trunk/composer.lock
- PyPI (Python): `requirements.txt`, `poetry.lock` (Poetry), etc.
  - Ref. https://pip.pypa.io/en/stable/reference/requirements-file-format/#requirements-file-format
  - E.g. https://github.com/home-assistant/core/blob/dev/requirements.txt
- Go: `go.mod` and `go.sum`
  - Ref. https://go.dev/ref/mod
  - E.g. https://github.com/anchore/syft/blob/main/go.mod

## Unpacking a lockfile

![img](https://live.staticflickr.com/65535/51246137208_3538982c44_5k.jpg)
(https://www.flickr.com/photos/30478819@N08/51246137208 by [
Marco Verch Professional Photographer](https://www.flickr.com/people/30478819@N08/) / CC BY 2.0 )

### Interpreted languages

A lock file is generally found on a repository & filesystem.

#### Python (requirements.txt)

> Requirements files serve as a list of items to be installed by pip, when using pip install. Files that use this format are often called “pip requirements.txt files”, since requirements.txt is usually what these files are named (although, that is not a requirement).
>
> --- https://pip.pypa.io/en/stable/reference/requirements-file-format/#requirements-file-format

```
SomeProject
SomeProject == 1.3
SomeProject >= 1.2, < 2.0
SomeProject[foo, bar]
SomeProject ~= 1.4.2
SomeProject == 5.4 ; python_version < '3.8'
SomeProject ; sys_platform == 'win32'
requests[security] >= 2.8.1, == 2.8.* ; python_version < "2.7"
```

### Compiled languages

A lock file is generally found on a repository & built executable.

#### Java (Maven)

##### What is POM?

> A Project Object Model or POM is the fundamental unit of work in Maven. It is an XML file that contains information about the project and configuration details used by Maven to build the project. It contains default values for most projects.
>
> --- https://maven.apache.org/guides/introduction/introduction-to-the-pom

```xml
<dependencies>
  <dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>
  </dependency>
  <dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.14.1</version>
  </dependency>
</dependencies>
```

Also, [Apache Maven Archiver](https://maven.apache.org/shared/maven-archiver/) automatically creates `pom.properties` with the following content:

```
artifactId=${project.artifactId}
groupId=${project.groupId}
version=${project.version}
```

**org.apache.logging.log4j/log4j-core pom.properties**

```
#Created by Apache Maven 3.5.0
version=2.14.1
groupId=org.apache.logging.log4j
artifactId=log4j-core
```

```bash
wget https://repo1.maven.org/maven2/org/apache/struts/struts2-core/6.1.2/struts2-core-6.1.2.jar
unzip struts2-core-6.1.2.jar -d struts2
yq -o json struts2/META-INF/maven/org.apache.struts/struts2-core/pom.xml | jq .project.dependencies
```

> **Note**
>
> `pom.xml` can be excluded from a built executable by settings `addMavenDescriptor` as `false`.

> addMavenDescriptor
> Whether the created archive will contain these two Maven files:
> The pom file, located in the archive in META-INF/maven/${groupId}/${artifactId}/pom.xml
> A pom.properties file, located in the archive in META-INF/maven/${groupId}/${artifactId}/pom.properties
> The default value is true.
>
> --- https://maven.apache.org/shared/maven-archiver/

## Go & Rust

Modern languages such as Go and Rust have a feature to perform an audit on an executable by embedding metadata in a section.

### Go

`__go_buildinfo` section has lock file equivalent metadata.

![img](https://imgur.com/FIldtkc.png)

### Rust

`dep-v0` section has lock file equivalent the metadata.

![img](https://imgur.com/tjiTc36.png)
