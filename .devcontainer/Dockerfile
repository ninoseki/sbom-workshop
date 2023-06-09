# Java
FROM gradle:7.5.1-jdk17 AS java

WORKDIR /usr/src/app

COPY --chown=gradle:gradle java ./

RUN gradle dependencies --write-locks \
	&& gradle bootJar --no-daemon

# Rust
FROM rust:1.67 as rust

WORKDIR /usr/src/app

COPY rust/Cargo.toml ./
COPY rust/src ./src

RUN cargo install --path . \
	&& cargo install cargo-auditable cargo-audit \
	&& cargo auditable build --release

# Go
FROM golang:1.20 as go

WORKDIR /usr/src/app

COPY go/go.mod go/go.sum go/hello_world.go ./

RUN go build

# Python
FROM python:3.11 as python

WORKDIR /usr/src/app

ENV POETRY_CACHE_DIR /usr/src/app/.cache/pypoetry

COPY ./requirements.txt ./pyproject.toml ./poetry.lock ./

RUN pip install -U pip \
	&& pip install -r requirements.txt \
	&& poetry config virtualenvs.in-project true \
	&& poetry install

COPY ./python/requirements.txt ./runtime.requirements.txt
RUN pip install -r runtime.requirements.txt

# Main build
FROM python:3.11

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# create the user
RUN groupadd --gid $USER_GID $USERNAME \
	&& useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

# setup requirements
RUN apt update \
	&& apt install -y --no-install-recommends \
	sudo \
	cmake \
	pigz \
	default-jdk-headless \
	curl \
	wget \
	git \
	jq \
	vim \
	tree \
	# install HTTPie
	&& curl -SsL https://packages.httpie.io/deb/KEY.gpg | apt-key add - \
	&& curl -SsL -o /etc/apt/sources.list.d/httpie.list https://packages.httpie.io/deb/httpie.list \
	&& apt update \
	&& apt install -y --no-install-recommends httpie \
	# cleanup
	&& apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/* \
	&& echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
	&& chmod 0440 /etc/sudoers.d/$USERNAME

# install yq
COPY --from=mikefarah/yq:4.32.2 /usr/bin/yq /usr/local/bin/yq

# install sbom-tool
RUN curl -Lo sbom-tool https://github.com/microsoft/sbom-tool/releases/download/v1.0.2/sbom-tool-linux-x64 \
	&& chmod +x sbom-tool \
	&& mv sbom-tool /usr/local/bin

# install syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin v0.79.0

# install osv-scanner
RUN curl -Lo osv-scanner https://github.com/google/osv-scanner/releases/download/v1.3.2/osv-scanner_1.3.2_linux_amd64 \
	&& chmod +x osv-scanner \
	&& mv osv-scanner /usr/local/bin

USER $USERNAME

# copy Java executable & lockfile
COPY --chown=$USERNAME --from=java /usr/src/app/build/libs/*.jar /app/java/spring-boot-application.jar
COPY --chown=$USERNAME --from=java /usr/src/app/gradle.lockfile /app/java/gradle.lockfile

# install jbom
RUN curl -Lo /tmp/jbom.jar https://github.com/eclipse/jbom/releases/download/v1.2.1/jbom-1.2.1.jar \
	&& mv /tmp/jbom.jar /app/java/jbom.jar

# copy Rust executable & lockfile
COPY --chown=$USERNAME --from=rust /usr/src/app/target/release/hello_world /app/rust/hello_world
COPY --chown=$USERNAME --from=rust /usr/src/app/Cargo.lock /app/rust/Cargo.lock

# copy Go executable & lockfile
COPY --chown=$USERNAME --from=go /usr/src/app/hello_world /app/go/hello_world
COPY --chown=$USERNAME --from=go /usr/src/app/go.sum /app/go/go.sum

# copy Python site-packages
COPY --from=python /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python /usr/local/bin/pip /usr/local/bin/pip
COPY --from=python /usr/local/bin/poetry /usr/local/bin/poetry
COPY --from=python /usr/local/bin/uvicorn /usr/local/bin/uvicorn

# copy Python app
COPY --chown=$USERNAME python /app/python

# copy Poetry cache
COPY --chown=$USERNAME --from=python /usr/src/app/.cache/pypoetry /home/vscode/.cache/pypoetry

# copy post create/start command
COPY --chown=$USERNAME postCreateCommand.sh /app/
COPY --chown=$USERNAME postStartCommand.sh /app/
