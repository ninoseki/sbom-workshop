import typer
from cyclonedx.model.component import Component
from packageurl import PackageURL

from sbom_workshop.cyclonedx import components_to_bom, convert_as_json

from .app import app


def normalize_version(version: str) -> str:
    if version.startswith("v"):
        return version[1:]

    return version


def dep_to_component(dep: str) -> Component:
    _, name, version, _ = dep.split()
    normalized_version = normalize_version(version)
    return Component(
        name=name,
        version=normalized_version,
        purl=PackageURL(type="golang", name=name, version=normalized_version),
    )


def parse_binary(path: str) -> list[Component]:
    import lief

    binary = lief.parse(path)

    build_info_section = next(
        (section for section in binary.sections if section.name == "__go_buildinfo"),
        None,
    )
    if build_info_section is None:
        return []

    data = bytes(build_info_section.content)
    # very dirty hack to parse build info...
    text = data.decode(errors="ignore")
    deps: list[str] = []
    for line in text.splitlines():
        if line.startswith("dep\t"):
            deps.append(line.strip())

    return [dep_to_component(dep) for dep in deps]


@app.command(help="Parse buildinfo section and build CycloneDX SBOM")
def build_info(path: str = typer.Argument(..., help="Path to Go executable")) -> None:
    components = parse_binary(path)
    bom = components_to_bom(components)
    print(convert_as_json(bom))  # noqa: T201
