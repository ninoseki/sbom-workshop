import json
import zlib

import typer
from cyclonedx.model.component import Component
from elftools.elf.elffile import ELFFile
from packageurl import PackageURL

from sbom_workshop.cyclonedx import components_to_bom, convert_as_json

from .app import app


def normalize_version(version: str) -> str:
    if version.startswith("v"):
        return version[1:]

    return version


def package_to_component(package: dict) -> Component:
    name = package.get("name", "")
    version = package.get("version", "")
    return Component(
        name=name,
        version=version,
        purl=PackageURL(type="cargo", name=name, version=version),
    )


def parse_binary(path: str) -> list[Component]:
    with open(path, "rb") as f:
        elf = ELFFile(f)

        audit_data_section = next(
            (section for section in elf.iter_sections() if section.name == ".dep-v0"),
            None,
        )
        if audit_data_section is None:
            return []

        json_string = zlib.decompress(audit_data_section.data())

    json_data = json.loads(json_string)

    packages: list[dict] = json_data.get("packages", [])
    return [package_to_component(package) for package in packages]


@app.command(help="Parse audit data section and build CycloneDX SBOM")
def audit_data(path: str = typer.Argument(..., help="Path to Rust executable")) -> None:
    components = parse_binary(path)
    bom = components_to_bom(components)
    print(convert_as_json(bom))  # noqa: T201
