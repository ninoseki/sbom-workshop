# Python near runtime SBOM with site packages

- [Demystifying Python Module Search Path](#demystifying-python-module-search-path)
- [pkg_resources module](#pkg_resources-module)
- [The challenge](#the-challenge)
- [How to test the challenge](#how-to-test-the-challenge)

## Demystifying Python Module Search Path

![img](https://imgs.xkcd.com/comics/python_environment.png)

(https://xkcd.com/1987/ by Randall Munroe)

```bash
$ python -c "import sys;print(sys.path)"
['', '/usr/local/lib/python310.zip', '/usr/local/lib/python3.10', '/usr/local/lib/python3.10/lib-dynload', '/workspaces/sbom_workshop/.venv/lib/python3.10/site-packages', '/workspaces/jsac2023']
```

| Path                            | Desc.                     |
| ------------------------------- | ------------------------- |
| `~/lib/pythonXY.zip`            | Zipped standard libraries |
| `~/lib/pythonX.Y`               | Standard libraries        |
| `~/lib/pythonX.Y/lib-dynload`   | Standard C libraries      |
| `~/lib/pythonX.Y/site-packages` | Third party libraries     |

```bash
$ python -c "import site;print(site.getsitepackages())"
['/workspaces/sbom_workshop/.venv/lib/python3.10/site-packages']
# or
$ python -m site
sys.path = [
    '/workspaces/jsac2023',
    '/usr/local/lib/python310.zip',
    '/usr/local/lib/python3.10',
    '/usr/local/lib/python3.10/lib-dynload',
    '/workspaces/sbom_workshop/.venv/lib/python3.10/site-packages',
]
USER_BASE: '/home/vscode/.local' (exists)
USER_SITE: '/home/vscode/.local/lib/python3.10/site-packages' (exists)
ENABLE_USER_SITE: False
```

- System site: system level site packages
- User site: user (virtual environment) level site packages

A virtual environment is entirely isolated from the system-level site-packages by default.([PEP405](https://peps.python.org/pep-0405/))

## pkg_resources module

> The `pkg_resources` module distributed with setuptools provides an API for Python libraries to access their resource files, and for extensible applications and frameworks to automatically discover plugins. It also provides runtime support for using C extensions that are inside zipfile-format eggs, support for merging packages that have separately-distributed modules or subpackages, and APIs for managing Python’s current “working set” of active packages.
>
> --- https://setuptools.pypa.io/en/latest/pkg_resources.html

```python
import pkg_resources

# ref. https://setuptools.pypa.io/en/latest/pkg_resources.html#getting-or-creating-distributions
for dist in pkg_resources.find_distributions("path/to/site_packages"):
    print([dist.project_name, dist.version])
```

## The challenge

Implement a function to compose components based on a path of a site package.

- Implement `get_site_packages()` in `sbom_workshop/python/site_packages.py`

```python
# sbom_workshop/python/site_packages.py

def site_package_to_components(path: str) -> list[Component]:
    """Convert a site package into a list of components"""
    raise NotImplementedError()
```

### How to test the challenge

```bash
pytest tests/python/test_site_packages.py
```

Also you can produce CycloneDX SBOM with the following command along with the function.

```bash
sbom-workshop-cli python site-packages /path/to/site_packages | jq .
```

```bash
sbom-workshop-cli python site-packages /workspaces/sbom_workshop/.venv/lib/python3.10/site-packages | jq .
```
