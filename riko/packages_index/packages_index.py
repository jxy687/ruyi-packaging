import os
import semver
import tomllib

from pathlib import Path
from typing import Dict, List

from .manifests import Category, Package, PackageVersion

class PackagesIndex:

    def __init__(self, path: Path):
        self._path: Path = path
        self._categories: Dict[str, Category] = {}

    def load(self) -> None:
        if not os.path.exists(self._path / 'manifests'):
            raise FileNotFoundError(self._path / 'manifests')

        for cat in os.listdir(self._path / 'manifests'):
            mycat = Category(cat)

            for pkg in os.listdir(self._path / 'manifests' / cat):
                mypkg = Package(pkg)

                for ver in os.listdir(self._path / 'manifests' / cat / pkg):
                    tml = self._path / 'manifests' / cat / pkg / ver
                    if tml.suffix.lower() != '.toml':
                        raise NotImplementedError(f"file type {tml.suffix.lower()} not supported")

                    data = tomllib.loads(tml.read_text())
                    version = semver.Version.parse(tml.stem)
                    upstream_version = data.get('metadata').get('upstream_version')

                    mypkg.add_version(PackageVersion(version, upstream_version, data))

                mycat.add_package(mypkg)

            self._categories.update({cat: mycat})

    def get_category(self, name: str) -> Category | None:
        return self._categories.get(name)
