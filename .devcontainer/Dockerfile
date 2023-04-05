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

COPY ./requirements.txt ./pyproject.toml ./poetry.lock ./poetry.toml ./
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

# install SBOM tools
WORKDIR /tools

RUN curl -Lo sbom-tool https://github.com/microsoft/sbom-tool/releases/download/v0.3.3/sbom-tool-linux-x64 \
	&& chmod +x sbom-tool \
	&& sudo mv sbom-tool /usr/local/bin \
	&& curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin \
	&& curl -Lo osv-scanner https://github.com/google/osv-scanner/releases/download/v1.3.1/osv-scanner_1.3.1_linux_amd64 \
	&& chmod +x osv-scanner \
	&& sudo mv osv-scanner /usr/local/bin

USER $USERNAME

# copy Java executable & lockfile
COPY --chown=$USERNAME --from=java /usr/src/app/build/libs/*.jar /app/java/spring-boot-application.jar
COPY --chown=$USERNAME --from=java /usr/src/app/gradle.lockfile /app/python/gradle.lockfile

# copy Rust executable & lockfile
COPY --chown=$USERNAME --from=rust /usr/src/app/target/release/hello_world /app/rust/hello_world
COPY --chown=$USERNAME --from=rust /usr/src/app/Cargo.lock /app/rust/Cargo.lock

# copy Go executable & lockfile
COPY --chown=$USERNAME --from=go /usr/src/app/hello_world /app/go/hello_world
COPY --chown=$USERNAME --from=go /usr/src/app/go.sum /app/go/go.sum

# copy Python site-packages
COPY --from=python /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python /usr/local/bin/poetry /usr/local/bin/poetry
COPY --from=python /usr/local/bin/uvicorn /usr/local/bin/uvicorn

# copy Python app
COPY --chown=$USERNAME python /app/python

# copy .venv
WORKDIR /workspaces/sbom-workshop

COPY --chown=$USERNAME --from=python /usr/src/app/.venv /workspaces/sbom-workshop/.venv

# set post start commadn
WORKDIR /app

COPY --chown=$USERNAME postStartCommand.sh /app/
