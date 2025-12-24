import json
import logging
import semver
import tomli_w

from typing import Dict, List

from .config.const import ruyi_cache_dir, nvchecker_config, nvchecker_result, nvchecker_old_ver, nvchecker_new_ver, \
    ruyi_pkgs_dir
from .nvchecker.results import NvcheckerResults
from .packages_index.packages_index import PackagesIndex
from .packages_index.manifests import PackageVersion
from .ruyi_packages.ruyi_packages import RuyiPackages, UpstreamConfig

logger = logging.getLogger(__name__)

class Riko:

    def __init__(self):
        self._packages_index: PackagesIndex = PackagesIndex(ruyi_cache_dir / "ruyi" / "packages-index")
        self._ruyi_packages: RuyiPackages = RuyiPackages(ruyi_pkgs_dir)
        self._nvchecker_result: NvcheckerResults = NvcheckerResults(nvchecker_result)

    def load_from_cache(self) -> None:
        """
        Start riko from local cache
        :return:
        """
        try:
            self._ruyi_packages.load()
            self._packages_index.load()
            self._nvchecker_result.load()
        except FileNotFoundError:
            logger.warning("Riko cache not found, please run `riko check` first")

    def generate_nvchecker_config(self) -> None:
        nvchecker_cfg: Dict = {
            "__config__": {
                "oldver": str(nvchecker_old_ver.name),
                "newver": str(nvchecker_new_ver.name),
            }
        }
        for c in self._ruyi_packages.get_upstreams().values():
            nvchecker_cfg[c.get_name()] = c.get_nvchecker_dat()

        with open(nvchecker_config, "wb") as f:
            tomli_w.dump(nvchecker_cfg, f)

    def generate_nvchecker_old_ver(self) -> None:
        """
        Generate old_ver.json from packages-index for nvchecker on cli.check
        :return:
        """
        self._packages_index.load()

        nvchecker_ver = 2
        old_data = {}

        for up in self._ruyi_packages.get_upstreams().values():
            name = up.get_name()
            cat = self._packages_index.get_category(up.get_category())

            # find latest version among all combos
            version = semver.Version(0, 0, 0)
            upstream_version = ""

            for pkg in up.get_combos():
                ver = self.get_packages_index_latest(cat.get_name(), pkg)
                if ver.version.compare(version) > 0:
                    version = ver.version
                    upstream_version = ver.upstream_version

            old_data[name] = {"version": upstream_version}

        format_data = {
            "version": nvchecker_ver,
            "data": old_data,
        }

        with open(nvchecker_old_ver, "w") as f:
            json.dump(format_data, f, indent=2)

    def generate_local_inventory(self, out_path: str) -> None:
        """
        生成“本地库存版本清单”，用于版本缺失检查：
        - 对每个 upstream(name)，收集本地 packages-index 中存在的所有 upstream_version
        - 同时计算 latest_upstream_version（基于 semver.Version 的 v.version 最大）
        
        输出 JSON 结构示例：
        {
        "version": 1,
        "data": {
            "openwrt-sifiveu": {
            "latest": "24.10.4",
            "versions": ["23.10.4", "24.10.4"]
            },
            ...
        }
        }
        """
        self._packages_index.load()

        data: Dict[str, Dict] = {}

        for up in self._ruyi_packages.get_upstreams().values():
            name = up.get_name()
            cat = self._packages_index.get_category(up.get_category())

            # 收集“本地所有版本”
            all_versions: Dict[str, semver.Version] = {}  # upstream_version -> semver.Version
            latest_sem = semver.Version(0, 0, 0)
            latest_upstream = ""

            for pkg in up.get_combos():
                # 取某个 pkg 在 packages-index 里的所有版本（过滤空 upstream_version）
                versions = self.get_packages_index_all_versions(cat.get_name(), pkg)

                for pv in versions:
                    if pv.upstream_version is None or pv.upstream_version == "":
                        continue
                    # 用 upstream_version 去重；并保存其 semver 值（用于排序/选最新）
                    all_versions[pv.upstream_version] = pv.version

                    if pv.version.compare(latest_sem) > 0:
                        latest_sem = pv.version
                        latest_upstream = pv.upstream_version

            # 排序输出（按 semver 从小到大）
            sorted_versions = sorted(all_versions.items(), key=lambda kv: kv[1])
            versions_list = [u for u, _ in sorted_versions]

            data[name] = {
                "latest": latest_upstream if latest_upstream else None,
                "versions": versions_list,
            }

        output = {"version": 1, "data": data}
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)


    def get_packages_index_all_versions(self, category: str, pkg: str) -> List["PackageVersion"]:
        """
        返回 packages-index 中某个 (category, pkg) 的所有可用版本（manifest对象列表），
        过滤 upstream_version 为空的条目。
        """
        out: List["PackageVersion"] = []
        p = self._packages_index.get_category(category).get_package(pkg)

        for v in p.get_versions():
            if v.upstream_version is None or v.upstream_version == "":
                continue
            # 为了和你现有 get_packages_index_latest() 一致，这里返回 manifest（而不是裸 v）
            manifest = self.get_packages_index_manifest(category, pkg, v.upstream_version)
            if manifest is not None:
                out.append(manifest)

        return out
    def get_nvchecker_results(self, event_or_level: str) -> List[Dict]:
        if event_or_level == "any":
            return self._nvchecker_result.get_data()
        else:
            return self._nvchecker_result.get_event_data(event_or_level)

    def get_nvchecker_result(self, up_name: str) -> Dict | None:
        for r in self._nvchecker_result.get_data():
            if r.get("name") == up_name:
                return r

        return None

    def get_packages_index(self) -> PackagesIndex:
        return self._packages_index

    def get_packages_index_latest(self, category: str, pkg: str) -> PackageVersion:
        version = semver.Version(0, 0, 0)
        package_version = None

        for v in self._packages_index.get_category(category).get_package(pkg).get_versions():
            if v.version.compare(version) > 0:
                if v.upstream_version is None or v.upstream_version == "":
                    continue
                version = v.version
                package_version = v

        return self.get_packages_index_manifest(category, pkg, package_version.upstream_version)

    def get_packages_index_manifest(self, category: str, pkg: str, up_ver: str) -> PackageVersion | None:
        for v in self._packages_index.get_category(category).get_package(pkg).get_versions():
            if v.upstream_version == up_ver:
                return v

        return None

    def get_ruyi_packages(self) -> RuyiPackages:
        return self._ruyi_packages

    def get_ruyi_package(self, up_name: str) -> UpstreamConfig | None:
        """
        ruyi packages described by riko.toml
        :param up_name: upstream package name
        :return: riko.toml in UpstreamConfig
        """
        return self._ruyi_packages.get_upstream(up_name)


_myriko: Riko | None = None

def get_riko() -> Riko:
    global _myriko

    if _myriko is None:
        _myriko = Riko()

    return _myriko
