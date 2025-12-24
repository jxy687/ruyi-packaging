
import ast
import copy
import hashlib
import importlib.util
import logging
import os
import re
import semver
import subprocess
import tomli_w
import traceback
import yaml

from typing import Callable, Dict, List, Tuple
from pathlib import Path

from .utils import ensure_dir
from ..api import RikoPkg
from ..config.const import riko_cache_dir, riko_manifests_dir, ruyi_pkgs_dir, nvchecker_miss_ver, \
    nvchecker_config,nvchecker_datadir,nvchecker_local_ver
from ..packages_index.manifests import PackageVersion
from ..rikoriko import get_riko
from ..upstreams.github import GithubUpstream
from ..upstreams.regex import RegexUpstream

import json
from ..nvchecker.missing_check2 import MissingVersionChecker, load_local_versions_from_dir, write_report,load_local_versions_from_inventory_json


logger = logging.getLogger(__name__)

def _load_missing_report(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _ensure_missing_report(up_name: str) -> dict:
    """
    生成/刷新缺失报告，并返回 dict：
    {
      name, local_versions, remote_versions, missing_all, missing_newer,
      latest_local, latest_remote, ...
    }
    """
    get_riko().generate_local_inventory(nvchecker_local_ver)
    checker = MissingVersionChecker(nvchecker_config)
    local_versions = load_local_versions_from_inventory_json(nvchecker_local_ver, up_name)
    report = checker.compare(up_name, local_versions)

    # 避免多 upstream 覆盖同一个 nvchecker_miss_ver（建议按 up_name 分文件）
    base = Path(nvchecker_miss_ver)
    miss_path = str(base.with_name(f"{up_name}.missing_versions.json"))
    miss_path = base


    write_report(report, miss_path)
    return _load_missing_report(miss_path)

def manifests(up_name: str, gen_vers: List[str], down_grade: bool):
    """
    Generate packages-index manifests
    :param up_name: upstream name
    :param gen_vers: will generate versions
    :param down_grade: will generate downgrade manifests
    :return:
    """
    # nvchecker result：只用于判断 upstream 是否存在
    result = get_riko().get_nvchecker_result(up_name)
    if result is None:
        logger.error("No such nvchecker upstream %s", up_name)
        logger.error("May be new package")
        return

    # 缺失报告：版本决策的唯一来源
    try:
        miss_report = _ensure_missing_report(up_name)
    except Exception as e:
        logger.warning(f"missing report failed for {up_name}: {e}")
        logger.debug(traceback.format_exc())
        miss_report = None

    if miss_report is None:
        logger.error(f"Cannot load missing report for {up_name}, abort.")
        return

    local_versions = miss_report.get("local_versions", [])
    local_set = set(local_versions)
    latest_local = miss_report.get("latest_local") or ""
    missing_all = miss_report.get("missing_all", [])

    # --------- 版本决策：根据是否传入 gen_vers ---------
    requested = list(gen_vers)

    if len(gen_vers) == 0:
        # 未指定版本：生成所有缺失版本
        gen_vers[:] = list(missing_all)
        if len(gen_vers) == 0:
            logger.warning("Already updated and no missing versions")
            return
    else:
        # 指定版本：只生成本地没有的版本（差集）
        gen_vers[:] = [v for v in gen_vers if v not in local_set]

        skipped = [v for v in requested if v in local_set]
        if skipped:
            logger.info(f"Skip existing local versions for {up_name}: {skipped}")

        if len(gen_vers) == 0:
            logger.warning("All requested versions already exist locally; nothing to generate.")
            return

    # --------- 是否允许降级（生成低版本） ---------
    # down_grade=False：不允许生成低于 latest_local 的缺失版本
    # down_grade=True：允许生成任何缺失版本（包括历史版本）
    if (not down_grade) and latest_local:
        def _simple_ver_key(v: str):
            v = v.strip().strip("/")
            if v.lower().startswith("v"):
                v = v[1:]
            if not re.fullmatch(r"\d+(?:\.\d+)*", v):
                return None
            return tuple(int(x) for x in v.split("."))

        base = _simple_ver_key(latest_local)
        if base is not None:
            before = list(gen_vers)
            gen_vers[:] = [
                v for v in gen_vers
                if (_simple_ver_key(v) is None) or (_simple_ver_key(v) >= base)
            ]
            removed = [v for v in before if v not in gen_vers]
            if removed:
                logger.info(f"down_grade=False, drop older-than-latest_local versions: {removed}")

        if len(gen_vers) == 0:
            logger.warning("All candidate versions are older than latest_local; nothing to generate.")
            return

    # 去重（保持顺序）
    gen_vers[:] = list(dict.fromkeys(gen_vers))

    # --------- old_ver：仅作为“base manifest”使用，不参与版本决策 ---------
    # 让后续 get_packages_index_manifest(..., old_ver) 有个合理基准
    old_ver = latest_local  # 为空则后面会走 fake base

    logger.info(f"Generate {up_name} manifests for versions {gen_vers}")

    # load riko.toml config
    riko_toml = get_riko().get_ruyi_package(up_name)
    if riko_toml is None:
        raise FileNotFoundError(f"No riko upstream package `{up_name}` found")

    # load old packages-index manifest
    gen_cbs: List[str] = riko_toml.get_combos()
    gen_cbs_ov: List[PackageVersion] = []
    for c in gen_cbs:
        if old_ver:
            pkg_ver = get_riko().get_packages_index_manifest(riko_toml.get_category(), c, old_ver)
            if pkg_ver is None:
                if "keep_back" in riko_toml.get_policy(c):
                    pkg_ver = get_riko().get_packages_index_latest(riko_toml.get_category(), c)
                    pkg_ver.add_policies(riko_toml.get_policy(c))
                    logger.debug(f"no ruyi packages-index manifest for category `{riko_toml.get_category()}` "
                                 f"package {c} version {old_ver} found")
                    logger.debug(f"use `keep_back` policy, find ruyi packages-index manifest of category "
                                 f"`{riko_toml.get_category()}` package {c} version {pkg_ver.upstream_version}")
                    logger.info(f"{up_name} manifest {c} combo base on old version `{pkg_ver.upstream_version}`")
                else:
                    logger.info(f"No ruyi packages-index manifest for category `{riko_toml.get_category()}` "
                                f"package {c} version {old_ver} found")
            gen_cbs_ov.append(pkg_ver)
        else:
            # TODO: when empty old_ver, push fake old ver
            # TODO: * we should design a version base support
            # TODO: * design a list of manual maintained toml list
            # TODO: * design a list of ignored upstream version list
            gen_cbs_ov.append(PackageVersion(semver.Version.parse("0.0.0"), "0.0.0", {}))

    # output dir
    ensure_dir(riko_cache_dir)
    ensure_dir(riko_manifests_dir)

    riko_py_p = ruyi_pkgs_dir / riko_toml.get_category() / up_name / "riko.py"
    riko_yaml_p = ruyi_pkgs_dir / riko_toml.get_category() / up_name / "riko.yaml"

    if not riko_yaml_p.exists():
        logger.fatal("You must ues riko.yaml in this riko version")
        return

    riko_yaml_orig: Dict = yaml.safe_load(riko_yaml_p.read_text())
    assert riko_yaml_orig["format"] == "v1"

    # riko.yaml parsing functions
    def tree_parse_inner(key: str, value: Dict | List | str) -> Dict:
        if isinstance(value, Dict):
            tree_new = {}
            for k, v in value.items():
                tree_new.update(tree_parse_inner(k, v))

            return {key: tree_new}
        elif isinstance(value, List):
            list_new = []
            if isinstance(value[0], Dict):
                for v in value:
                    list_new.append(tree_parse_inner("k", v)["k"])
            elif isinstance(value[0], str):
                for s in value:
                    list_new.append(tree_parse_inner("k", s)["k"])
            else:
                raise RuntimeError(f"Unexpected type {type(value)}")
            return {key: list_new}
        elif isinstance(value, str):
            # remain some str unchanged as str
            if re.match(r"^[a-zA-Z0-9 ,\-+.]+$", value):
                return {key: value}
            # treat rest str as expr
            return {key: ast.parse(value, mode="eval")}
        elif value is None:
            return {key: ""}
        else:
            raise RuntimeError(f"Unexpected type {type(value)}")

    def tree_update_inner(tree_old: Dict, tree_up: Dict) -> None:
        for k in tree_up.keys():
            if k in tree_old.keys() and isinstance(tree_old[k], Dict) and isinstance(tree_up[k], Dict):
                # keep old keys in old Dict
                tree_update_inner(tree_old[k], tree_up[k])
            else:
                tree_old[k] = tree_up[k]

    def tree_update(tree_old: Dict, tree_raw: Dict) -> Dict:
        """
        update tree_raw to tree_old, and turn str value to ast
        :param tree_old:
        :param tree_raw:
        :return:
        """
        tree_new = copy.deepcopy(tree_old)

        tree_update_inner(tree_new, tree_parse_inner("k", tree_raw)["k"])

        return tree_new

    # riko.yaml ast check function
    def riko_yaml_ast_check(exp: ast.Expression, g_vars: Dict, g_calls: Dict) -> bool:
        _ast_allowed = (ast.Expression, ast.Call, ast.Name, ast.Load, ast.Constant, ast.Tuple)
        # TODO:
        return True

    # riko.yaml running functions
    def riko_yaml_run(_up, _ov: semver.Version, nm: Dict, ym: Dict) -> Dict:
        # riko.yaml vals
        _upstream_version = nm["metadata"]["upstream_version"]
        _files = {}
        _label = []

        # riko.yaml utils
        def _file(_name_url: Tuple[str, str]) -> str:
            if _name_url[0] not in _files.keys():
                _files[_name_url[0]] = {}

            _files[_name_url[0]]["url"] = _name_url[1]
            return _name_url[0]

        def _uncompress(_orig: str) -> str:
            """
            unpack package
            See: https://github.com/ruyisdk/ruyi/blob/main/ruyi/ruyipkg/unpack_method.py
            :param _orig:
            :return:
            """
            _tars = [".tar.gz", ".tar.bz2", ".tar.lz4", ".tar.xz", ".tar.zst", ".gz", ".bz2", ".lz4", ".xz", ".zst", ".zip"]
            for t in _tars:
                if _orig.endswith(t):
                    return _orig[:-len(t)]
            return _orig

        def _map_and_uncompress(_name: str, _map: str):
            if _name not in _files.keys():
                _files[_name] = {}

            _files[_name]["map"] = _map
            _files[_name]["uncompressed"] = _uncompress(_name)

        # riko.yaml api
        def _version(major=None, minor=None, patch=None) -> str:
            _nv = _ov
            if major is not None:
                _nv = _nv.replace(major=major)
            if minor is not None:
                _nv = _nv.replace(minor=minor)
            if patch is not None:
                _nv = _nv.replace(patch=patch)

            return str(_nv)

        def _assign(_parm) -> str:
            return str(_parm)

        def _substring(_sub: str) -> Tuple[str, str]:
            if _label[-1] == "name" and _label[-2] == "distfiles":
                if isinstance(_up, GithubUpstream):
                    return _up.get_release_assert_substring(_sub)
                elif isinstance(_up, RegexUpstream):
                    return _up.get_release_assert_substring(_sub)
                else:
                    raise NotImplementedError(f"upstream source {_up.source} not supported")
            else:
                raise NotImplementedError(f"substream not implemented for _label {_label}")

        def _regex(_pat: str) -> Tuple[str, str]:
            if _label[-1] == "name" and _label[-2] == "distfiles":
                if isinstance(_up, GithubUpstream):
                    return _up.get_release_assert_regex(_pat)
                elif isinstance(_up, RegexUpstream):
                    return _up.get_release_assert_regex(_pat)
                else:
                    raise NotImplementedError(f"upstream source {_up.source} not supported")
            else:
                raise NotImplementedError(f"substream not implemented for _label {_label}")

        def _titan(_name_url: Tuple[str, str]) -> str:
            _map_and_uncompress(_name_url[0], "titan")
            return _file(_name_url)

        def _live(_name_url: Tuple[str, str]) -> str:
            _map_and_uncompress(_name_url[0], "live")
            return _file(_name_url)

        def _disk(_name_url: Tuple[str, str]) -> str:
            _map_and_uncompress(_name_url[0], "disk")
            return _file(_name_url)

        def _root(_name_url: Tuple[str, str]) -> str:
            _map_and_uncompress(_name_url[0], "root")
            return _file(_name_url)

        def _boot(_name_url: Tuple[str, str]) -> str:
            _map_and_uncompress(_name_url[0], "boot")
            return _file(_name_url)

        def _uboot(_name_url: Tuple[str, str]) -> str:
            _map_and_uncompress(_name_url[0], "uboot")
            return _file(_name_url)

        # bfs run ast
        def _ast_run(_ym_t: Dict):
            for k, v in _ym_t.items():
                _label.append(k)

                if isinstance(v, ast.Expression):
                    _g_vars = {"upstream_version": _upstream_version,}
                    _g_calls = {"assign": _assign,
                                "version": _version,
                                "substring": _substring,
                                "regex": _regex,
                                "titan": _titan,
                                "live": _live,
                                "disk": _disk,
                                "root": _root,
                                "boot": _boot,
                                "uboot": _uboot,}
                    if riko_yaml_ast_check(v, _g_vars, _g_calls):
                        _ym_t[k] = eval(compile(v, filename="<expr>", mode="eval"), _g_vars | _g_calls)
                        if not isinstance(_ym_t[k], str):
                            _ym_t[k] = f"value not str but {type(_ym_t[k])}"
                    else:
                        _ym_t[k] = "AST check failed"
                elif isinstance(v, str):
                    pass
                elif isinstance(v, Dict):
                    _ast_run(v)
                elif isinstance(v, List):
                    for d in v:
                        _ast_run(d)
                else:
                    raise RuntimeError(f"Unexpected type {type(v)}")

                _label.pop()

        _ast_run(ym)

        # info in _files
        if "provisionable" not in ym.keys():
            ym["provisionable"] = {"partition_map": {}}
        for ff in ym["distfiles"]:
            ff["urls"] = [_files[ff["name"]]["url"]]
            ym["provisionable"]["partition_map"][_files[ff["name"]]["map"]] = _files[ff["name"]]["uncompressed"]

        # info of _upstream_version
        ym["metadata"]["upstream_version"] = _upstream_version

        return ym

    # manifests reasoning rule set
    def manifests_r1(_facts: Dict) -> bool:
        """
        from provisionable.partition_map to provisionable.strategy
        :param _facts:
        :return: fact is upgraded
        """
        if "provisionable" not in _facts.keys():
            return False

        _map = _facts.get("provisionable")
        if _map is None or "partition_map" not in _map.keys() or "strategy" in _map.keys():
            return False

        _map: Dict = _map["partition_map"]
        _strategy = ""
        if len(_map) == 1:
            if "disk" in _map.keys() or "live" in _map.keys():
                _strategy = "dd-v1"
            elif "uboot" in _map.keys():
                _strategy = "fastboot-v1(lpi4a-uboot)"
            elif "titan" in _map.keys():
                _strategy = "spacemit-k1-v1"
                _map.update({"gpt": "partition_universal.json",
                             "bootinfo": "factory/bootinfo_sd.bin",
                             "fsbl": "factory/FSBL.bin",
                             "env": "env.bin",
                             "opensbi": "fw_dynamic.itb",
                             "uboot": "u-boot.itb",
                             "bootfs": "bootfs.ext4",
                             "rootfs": "rootfs.ext4"})
                _map.pop("titan")
        elif len(_map) == 2:
            if "boot" in _map.keys() and "root" in _map.keys():
                _strategy = "fastboot-v1"

        if _strategy != "":
            _facts["provisionable"]["strategy"] = _strategy
            return True

        return False

    def manifests_r5(_facts: Dict) -> bool:
        """
        from distfiles.name to blob
        :param _facts:
        :return:
        """
        if "blob" not in _facts.keys():
            _facts["blob"] = {}
        _blob = _facts.get("blob")
        if "distfiles" in _blob.keys():
            return False

        if "provisionable" not in _facts.keys():
            return False

        _map = _facts.get("provisionable")
        if _map is None or "partition_map" not in _map.keys() or "strategy" not in _map.keys():
            return False

        _strategy = _facts["provisionable"]["strategy"]
        _distfiles = []
        if _strategy in ["dd-v1", "fastboot-v1(lpi4a-uboot)", "fastboot-v1", "spacemit-k1-v1"]:
            for _f in _facts["distfiles"]:
                _distfiles.append(_f["name"])

        if len(_distfiles) > 0:
            _facts["blob"]["distfiles"] = _distfiles
            return True

        return False

    def manifests_r9(_facts: Dict) -> bool:
        """
        distfiles size, checksums and restrict
        :param _facts:
        :return:
        """
        if "distfiles" not in _facts.keys():
            return False
        if not isinstance(_facts["distfiles"], List) or len(_facts["distfiles"]) == 0:
            return False

        _sizes = []
        _sha256sums = []
        _sha512sums = []

        for _d in _facts["distfiles"]:

            if "checksums" in _d.keys() or "size" in _d.keys():
                continue

            _url: str = _d["urls"][0]
            _f_loc = riko_cache_dir / _d["name"]
            # TODO: do not use curl
            _cmd: List[str] = ["curl", "-C", "-", "--retry", "3", "--retry-delay", "2", "--retry-all-errors",
                              "-L", _url, "-o", str(_f_loc), ]
            _env = os.environ.copy()

            if _f_loc.exists():
                _f_loc.unlink()

            _process = subprocess.Popen(_cmd, env=_env)
            _ret = _process.wait()
            if _ret != 0:
                raise subprocess.CalledProcessError(_ret, _cmd)

            # get size
            _sizes.append(os.path.getsize(_f_loc))

            # calculate hash
            _sha256 = hashlib.sha256()
            _sha512 = hashlib.sha512()

            with open(_f_loc, "rb") as _f:
                while True:
                    _c = _f.read(4 * 1024)
                    if not _c:
                        break

                    _sha256.update(_c)
                    _sha512.update(_c)

            _sha256sums.append(_sha256.hexdigest())
            _sha512sums.append(_sha512.hexdigest())

        if len(_facts["distfiles"]) == len(_sizes) == len(_sha256sums) == len(_sha512sums):
            for _i in range(0, len(_sizes)):
                _facts["distfiles"][_i]["size"] = _sizes[_i]
                _facts["distfiles"][_i]["checksums"] = {"sha256": _sha256sums[_i], "sha512": _sha512sums[_i]}
                _facts["distfiles"][_i]["restrict"] = ["mirror"]
            return True

        return False

    def manifests_reasoning(_ma: Dict):
        """
        generate full manifests by rules
        :param _ma:
        :return:
        """
        _rules: List[Callable[[Dict], bool]] = [
            manifests_r1,
            manifests_r5,
            manifests_r9,
        ]
        _update = False
        _count = 0

        while _count < 100:
            for r in _rules:
                _update = _update or r(_ma)

            if not _update:
                break

            _count += 1
            _update = False

        if _update and _count >= 100:
            logger.warning("rule reasoning run so many times")

    def manifests_validate(_ma: Dict) -> bool:
        """
        check manifests dict keys and values
        :param _ma:
        :return:
        """

        # empty type to show its type, List cannot be empty, Dict can be empty
        # but List and Dict cannot be empty in real manifests
        # if str not empty, value in manifest must be equal to that in the template
        _key_must = {
            "format": "v1",
            "metadata": {
                "desc": "",
                "vendor": {"name": "", "eula": "", },
                "upstream_version": "",
            },
            "distfiles": [{
                "name": "",
                "size": "",
                "urls": ["", ],
                "restrict": ["", ],
                "checksums": {"sha256": "", "sha512": "", },
            }, ],
            "blob": {
                "distfiles": ["", ],
            },
            "provisionable": {
                "strategy": "",
                "partition_map": {},
            },
        }
        _key_may = {
            "provisionable": {
                "disk": "",
                "root": "",
                "boot": "",
                "uboot": "",
            },
        }

        def dfs_validate(_templt: Dict, _type: str, _rkeys: Dict) -> bool:
            if _type not in ["must", "may"]:
                return False

            _histories: List[int] = [0, ]
            _keys: List[List[str]] = [[], ]
            _trees: List[Dict] = [{}, ]
            _branch: List[str] = []

            _ts: List[str] = []
            for _k in _templt.keys():
                _ts.append(_k)
            _keys.append(_ts)
            _histories.append(0)
            _trees.append(_templt)
            _i = 1

            while _i > 0:
                while _histories[_i] < len(_keys[_i]):
                    _k = _keys[_i][_histories[_i]]
                    _v = _trees[_i][_k]
                    _branch.append(_k)

                    if isinstance(_v, str | List):
                        _rv = None
                        for _b in _branch:
                            if _rv is None:
                                _rv = _rkeys.get(_b)
                            else:
                                _rv = _rv.get(_b)

                            if _rv is None:
                                break

                        if _rv is None:
                            if _type == "must":
                                logger.debug(f"no such key in check dict: {_branch}")
                                return False
                            elif _type == "may":
                                pass
                        else:
                            if type(_rv) != type(_v):
                                logger.debug(f"type not same: {_rv} != {_v} of {_branch}")
                                return False
                            if isinstance(_rv, List) and ( len(_rv) == 0 or type(_rv[0]) != type(_v[0]) ):
                                logger.debug(f"type not same: {_rv} != {_v} of {_branch}")
                                return False
                            if isinstance(_rv, str) and _v != "" and _rv != _v:
                                logger.debug(f"type is str but value must same: {_rv} != {_v} of {_branch}")
                                return False

                        # check end on this branch
                        _branch.pop()
                        # next branch
                        _histories[_i] += 1

                    elif isinstance(_v, Dict):
                        # entre this tree
                        _ts: List[str] = []
                        for _k in _v.keys():
                            _ts.append(_k)
                        _keys.append(_ts)
                        _trees.append(_v)
                        _histories.append(0)
                        _i += 1

                # finish this depth
                _histories.pop()
                _keys.pop()
                _trees.pop()
                _i -= 1
                if _i > 0:
                    _branch.pop()
                _histories[_i] += 1

            return True

        if not dfs_validate(_key_must, "must", _ma):
            logger.error(f"key must check failed")
            return False
        if not dfs_validate(_key_may, "may", _ma):
            logger.error(f"key may check failed")
            return False

        return True
    
    def _format_gen_error(e: Exception) -> str:
        # subprocess 错误：最常见（curl / ruyi admin format-manifest）
        if isinstance(e, subprocess.CalledProcessError):
            cmd = e.cmd if isinstance(e.cmd, str) else " ".join(map(str, e.cmd))
            return f"CalledProcessError: returncode={e.returncode}, cmd={cmd}"

        if isinstance(e, FileNotFoundError):
            return f"FileNotFoundError: {e}"

        if isinstance(e, AssertionError):
            return f"AssertionError: {e or 'assert failed'}"

        return f"{type(e).__name__}: {e}"


    # generating
    success_vers: List[str] = []
    failed_vers: List[Tuple[str, str]] = []  # (version, reason)
    skipped_vers: List[str] = []  # 可选：没有异常但没生成出 toml 的版本
    for gv in gen_vers:
        try:
            # get UpstreamLike from riko.toml
            riko_toml_nvdat = riko_toml.get_nvchecker_dat()
            riko_toml_source = riko_toml_nvdat["source"]
            if riko_toml_source == "github":
                riko_toml_upstream = GithubUpstream(riko_toml_nvdat["github"], gv)
            elif riko_toml_source == "regex":
                source = riko_toml.get_source()

                file_url = source["regex_file_url"]
                file_url = file_url.replace("{{nvchecker.url}}", riko_toml_nvdat["url"])
                file_url = file_url.replace("{{upstream_version}}", gv)

                riko_toml_upstream = RegexUpstream(riko_toml_nvdat["url"], riko_toml_nvdat["regex"], file_url, source["regex_file_regex"])
            else:
                raise NotImplementedError(f"upstream source {riko_toml_source} not supported")

            riko_yaml = copy.deepcopy(riko_yaml_orig)

            riko_yaml_source = {}
            riko_yaml_cbs = {}
            # initial packages-index toml cfgs from "source" section in riko.yaml
            if "source" in riko_yaml.keys():
                riko_yaml_source = tree_update({"format": riko_yaml["format"]}, riko_yaml["source"])

            for i in range(0, len(gen_cbs)):
                if gen_cbs[i] in riko_yaml.keys():
                    # update toml cfgs from each package section in riko.yaml
                    riko_yaml_ast = tree_update(riko_yaml_source, riko_yaml[gen_cbs[i]])

                    old_version = gen_cbs_ov[i].get_version()
                    new_manifests = {"metadata": {"upstream_version": gv}}

                    manifest_stage1 = riko_yaml_run(riko_toml_upstream, old_version, new_manifests, riko_yaml_ast)

                    new_version = str(old_version)
                    if "version" in manifest_stage1:
                        new_version = manifest_stage1["version"]
                        manifest_stage1.pop("version")
                    riko_yaml_cbs[gen_cbs[i]] = (new_version, manifest_stage1)

            # check riko.py
            riko_py_rikoring = None
            riko_py_post_rikoring = None
            if riko_py_p.exists():

                # find functions
                riko_py_spec = importlib.util.spec_from_file_location(f"{up_name}/riko.py", riko_py_p)
                riko_py_module = importlib.util.module_from_spec(riko_py_spec)
                riko_py_spec.loader.exec_module(riko_py_module)

                try:
                    riko_py_rikoring = getattr(riko_py_module, "rikoring")
                except AttributeError as e:
                    logger.debug(e)

                try:
                    riko_py_post_rikoring = getattr(riko_py_module, "post_rikoring")
                except AttributeError as e:
                    logger.debug(e)

            # old version
            old_versions: List[RikoPkg] = []
            for i in range(0, len(gen_cbs_ov)):
                pkg = RikoPkg(riko_toml.get_category(), gen_cbs[i], riko_toml.get_name(), gen_cbs_ov[i].version,
                            gen_cbs_ov[i].upstream_version)
                pkg.set_manifest(gen_cbs_ov[i].manifest)
                pkg.add_policies([p for p in gen_cbs_ov[i].policies])
                old_versions.append(pkg)

            # new version
            new_versions: List[RikoPkg] = []
            for i in range(0, len(gen_cbs_ov)):
                pkg = RikoPkg(riko_toml.get_category(), gen_cbs[i], riko_toml.get_name(), semver.Version.parse(riko_yaml_cbs[gen_cbs[i]][0]), gv, riko_toml_upstream)
                pkg.set_manifest(riko_yaml_cbs[gen_cbs[i]][1])
                new_versions.append(pkg)

            # rikoring
            if riko_py_rikoring is not None:
                try:
                    riko_py_rikoring(old_versions, new_versions)
                except Exception as e:
                    logger.error(e)
                    traceback.print_exc()

            # manifests generate rules
            for n, m in riko_yaml_cbs.items():
                manifests_reasoning(m[1])

            # manifests validate
            for v in new_versions:
                ma, rd = v.get_manifest()
                assert not rd

                if manifests_validate(ma):
                    v.set_manifest_ready()
                else:
                    # logger.error(f"manifest validation failed for package {v.get_combo()} version {ma["metadata"]["upstream_version"]}")
                    logger.error(f"manifest validation failed for package {v.get_combo()} version {ma['metadata']['upstream_version']}")
                    logger.info(f"see failed manifests content: {ma}")

            # post_rikoring
            if riko_py_post_rikoring is not None:
                try:
                    riko_py_post_rikoring(old_versions, new_versions)
                except Exception as e:
                    logger.error(e)
                    traceback.print_exc()

            # check `keep_back` policy
            for i in range(0, len(new_versions)):
                if old_versions[i].accept_policy("keep_back"):
                    ma, rd = new_versions[i].get_manifest()
                    oma, _ = old_versions[i].get_manifest()
                    if not rd:
                        continue
                    if len(oma["distfiles"]) != len(ma["distfiles"]):
                        continue

                    sums = {}
                    osums = {}
                    for d in ma["distfiles"]:
                        sums[d["name"]] = (d["checksums"]["sha256"], d["checksums"]["sha512"])
                    for d in oma["distfiles"]:
                        osums[d["name"]] = (d["checksums"]["sha256"], d["checksums"]["sha512"])

                    same = True
                    for n, s in sums.items():
                        if n not in osums.keys():
                            same = False
                            break
                        if osums[n][0] != s[0] or osums[n][1] != s[1]:
                            same = False
                            break
                    if same:
                        new_versions[i].set_manifest_not_ready()
                        # logger.info(f"`keep_back` for package {new_versions[i].get_combo()}, version "
                        #             f"{ma["metadata"]["upstream_version"]} and version "
                        #             f"{oma["metadata"]["upstream_version"]} have same checksums")
                        logger.info(f"`keep_back` for package {new_versions[i].get_combo()}, version "
                                    f"{ma['metadata']['upstream_version']} and version "
                                    f"{oma['metadata']['upstream_version']} have same checksums")

            # write toml
            new_gen = False
            for v in new_versions:
                ma, rd = v.get_manifest()
                if not rd:
                    continue

                ensure_dir(riko_manifests_dir / v.get_category())
                ensure_dir(riko_manifests_dir / v.get_category() / v.get_combo())
                new_toml = riko_manifests_dir / v.get_category() / v.get_combo() / f"{str(v.get_version())}.toml"
                with open(new_toml, "wb") as nt:
                    tomli_w.dump(ma, nt)

                cmd: List[str] = ["ruyi", "admin", "format-manifest", str(new_toml), ]
                env = os.environ.copy()

                process = subprocess.Popen(cmd, env=env)
                ret = process.wait()
                if ret != 0:
                    raise subprocess.CalledProcessError(ret, cmd)

                new_gen = True
                # logger.info(f"new manifest for package {v.get_combo()} version {ma["metadata"]["upstream_version"]}")
                logger.info(f"new manifest for package {v.get_combo()} version {ma['metadata']['upstream_version']}")


            if not new_gen:
                logger.warning(f"no manifest for upstream {riko_toml.get_name()} version {gv}")
        except Exception as e:
            reason = _format_gen_error(e)
            failed_vers.append((gv, reason))
            logger.error(f"[FAIL] upstream={up_name}, version={gv}, reason={reason}")
            logger.debug(traceback.format_exc())
            continue

    # 循环结束后输出汇总
    if success_vers:
        logger.info(f"[SUMMARY] {up_name} success versions ({len(success_vers)}): {success_vers}")

    if skipped_vers:
        logger.warning(f"[SUMMARY] {up_name} skipped(no toml generated) versions ({len(skipped_vers)}): {skipped_vers}")

    if failed_vers:
        logger.error(f"[SUMMARY] {up_name} failed versions ({len(failed_vers)}):")
        for v, r in failed_vers:
            logger.error(f"  - {v}: {r}")