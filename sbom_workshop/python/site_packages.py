from cyclonedx.model.component import Component

from sbom_workshop.cyclonedx import components_to_bom, convert_as_json

from .app import app


def site_package_to_components(path: str) -> list[Component]:
    """Convert a site package into a list of components"""
    raise NotImplementedError()


@app.command(help="Build CycloneDX SBOM based on site packages")
def site_packages(path: str) -> None:
    components: list[Component] = site_package_to_components(path)
    bom = components_to_bom(components)
    print(convert_as_json(bom))  # noqa: T201
