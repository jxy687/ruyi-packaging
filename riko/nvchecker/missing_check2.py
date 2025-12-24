"""
missing_version_tool.py

一个“小工具”模块：基于 nvchecker.toml( regex entry ) 抓取远端版本列表，
并扫描本地 cache 目录得到本地版本集合，然后输出“版本缺失”报告到 json 文件。

特点：
- 可作为命令行工具运行
- 也可被其它 .py 文件 import 调用
- 不强制依赖 packaging：有则用更准确的版本比较；没有也可运行（支持常见数字/点分版本和8位日期）
- 兼容 Python 3.11+（tomllib）。若 Python <3.11，需要额外安装 tomli 并按注释修改。

用法（命令行）：
python3 missing_version_tool.py \
  --toml nvchecker.toml \
  --name openwrt-sifiveu \
  --local-dir /path/to/cache \
  --out reports/openwrt-sifiveu.missing.json

或用 old_ver.json 作为本地版本基线（只有一个版本时）：
python3 missing_version_tool.py \
  --toml nvchecker.toml \
  --name openwrt-sifiveu \
  --oldver old_ver.json \
  --out reports/openwrt-sifiveu.missing.json

在其它文件中调用：
from missing_version_tool import MissingVersionChecker, load_local_versions_from_dir, write_report
checker = MissingVersionChecker("nvchecker.toml")
local_versions = load_local_versions_from_dir("/path/to/cache", "openwrt-sifiveu", max_depth=5)
report = checker.compare("openwrt-sifiveu", local_versions)
write_report(report, "reports/openwrt-sifiveu.missing.json")
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.request import Request, urlopen

# Python 3.11+ 标准库 tomllib
try:
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore

# 尝试使用 packaging（更强的版本解析）；没有也能跑
try:
    from packaging.version import Version as PkgVersion  # type: ignore

    HAS_PACKAGING = True
except ModuleNotFoundError:
    PkgVersion = None  # type: ignore
    HAS_PACKAGING = False


# -------------------------
# 基础工具函数
# -------------------------
def _fetch_text(url: str, ua: str = "Mozilla/5.0") -> str:
    """下载网页内容（用于 regex 抓版本）。"""
    req = Request(url, headers={"User-Agent": ua})
    with urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="ignore")


def _ver_key_fallback(v: str) -> Optional[Tuple[int, ...]]:
    """
    无第三方依赖的简单版本 key：
    - 支持：24.10.4 / 15.0 / 20251202 / v3.0.1
    - 不支持：rc/beta/1.0.0-rc1 等复杂版本（返回 None）
    """
    v = v.strip().strip("/")
    if v.lower().startswith("v"):
        v = v[1:]
    if not re.fullmatch(r"\d+(?:\.\d+)*", v):
        return None
    return tuple(int(x) for x in v.split("."))


def _sort_versions(versions: List[str]) -> List[str]:
    """对版本列表排序（尽量用 packaging，否则用 fallback）。"""
    versions = list(dict.fromkeys(v.strip().strip("/") for v in versions if v))  # 去重+清理

    if HAS_PACKAGING:
        ok = []
        for v in versions:
            try:
                PkgVersion(v)  # type: ignore
                ok.append(v)
            except Exception:
                pass
        ok.sort(key=lambda x: PkgVersion(x))  # type: ignore
        return ok

    ok = []
    for v in versions:
        if _ver_key_fallback(v) is not None:
            ok.append(v)
    ok.sort(key=lambda x: _ver_key_fallback(x))  # type: ignore
    return ok


def _is_newer(v: str, base: str) -> bool:
    """判断 v 是否比 base 新。"""
    if HAS_PACKAGING:
        try:
            return PkgVersion(v) > PkgVersion(base)  # type: ignore
        except Exception:
            return False

    vk = _ver_key_fallback(v)
    bk = _ver_key_fallback(base)
    if vk is None or bk is None:
        return False
    return vk > bk


def _load_toml(path: Path) -> Dict:
    """
    读取 toml 配置（Python 3.11+）。
    Python <3.11：请安装 tomli，并把此函数改为 tomli.loads(...)
    """
    if tomllib is None:
        raise RuntimeError("tomllib not found (Python<3.11). Install tomli or upgrade Python.")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _extract_versions(html: str, pattern: str) -> List[str]:
    """用正则从网页中提取版本（建议 pattern 含 1 个捕获组）。"""
    found = re.findall(pattern, html)
    if not found:
        return []
    if isinstance(found[0], tuple):
        found = [x[0] for x in found]  # type: ignore
    return [str(x).strip().strip("/") for x in found]  # type: ignore


# -------------------------
# 报告结构
# -------------------------
@dataclass
class MissingReport:
    name: str
    source_url: str
    local_versions: List[str]
    remote_versions: List[str]
    missing_all: List[str]       # 远端存在但本地没有
    missing_newer: List[str]     # 仅远端比本地“最新版本”更高的缺失
    latest_local: Optional[str]
    latest_remote: Optional[str]


# -------------------------
# 核心类：MissingVersionChecker
# -------------------------
class MissingVersionChecker:
    """
    读取 nvchecker.toml 的 entry(url/regex)，抓取远端版本列表，
    与本地版本集合对比，输出缺失版本报告。

    当前只支持 source=regex 的条目（因为我们要拿“远端全量版本列表”）。
    """

    def __init__(self, nvchecker_toml: str | Path):
        self.nvchecker_toml = Path(nvchecker_toml)
        self.conf = _load_toml(self.nvchecker_toml)

    def get_entry(self, name: str) -> Dict:
        if name not in self.conf:
            raise KeyError(f"Entry not found in nvchecker toml: {name}")

        entry = self.conf[name]
        if entry.get("source") != "regex":
            raise ValueError(
                f"Only source=regex is supported for missing-list now. Got: {entry.get('source')}"
            )
        if "url" not in entry or "regex" not in entry:
            raise ValueError(f"Entry {name} must contain url and regex")
        return entry

    def fetch_remote_versions(self, name: str) -> Tuple[str, List[str]]:
        entry = self.get_entry(name)
        url = entry["url"]
        pattern = entry["regex"]
        html = _fetch_text(url)
        versions = _extract_versions(html, pattern)
        versions = _sort_versions(versions)
        return url, versions

    def compare(self, name: str, local_versions: Set[str]) -> MissingReport:
        url, remote_versions = self.fetch_remote_versions(name)
        local_sorted = _sort_versions(list(local_versions))

        latest_local = local_sorted[-1] if local_sorted else None
        latest_remote = remote_versions[-1] if remote_versions else None

        remote_set = set(remote_versions)
        missing_all = _sort_versions(list(remote_set - set(local_sorted)))

        missing_newer: List[str] = []
        if latest_local is not None:
            missing_newer = _sort_versions([v for v in missing_all if _is_newer(v, latest_local)])

        return MissingReport(
            name=name,
            source_url=url,
            local_versions=local_sorted,
            remote_versions=remote_versions,
            missing_all=missing_all,
            missing_newer=missing_newer,
            latest_local=latest_local,
            latest_remote=latest_remote,
        )


# -------------------------
# 本地版本集合的三种来源
# -------------------------
def load_local_versions_from_inventory_json(path: str, entry_name: str) -> Set[str]:
    """
    读取 generate_local_inventory() 输出的 inventory json：
    data[entry_name]["versions"] -> Set[str]
    """
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    versions: List[str] = obj.get("data", {}).get(entry_name, {}).get("versions", [])
    return {str(v) for v in versions if v}

def load_local_versions_from_oldver(old_ver_json: str | Path, name: str) -> Set[str]:
    """从 old_ver.json 读取本地版本（通常只有 1 个版本）。"""
    p = Path(old_ver_json)
    data = json.loads(p.read_text(encoding="utf-8"))
    v = data.get("data", {}).get(name, {}).get("version")
    return {v} if v else set()


def load_local_versions_from_dir(
    root_dir: str | Path,
    entry_name: str,
    *,
    version_regex: str = r"(v?\d+(?:\.\d+)+|\d{8})",
    max_depth: int = 4,
) -> Set[str]:
    """
    从本地 cache 目录扫描出某个条目的“所有版本集合”。

    支持：
    - 版本作为目录名：.../openwrt-sifiveu/24.10.4/...
    - 版本出现在文件名：.../openwrt-24.10.5-xxx.img.gz
    - 版本出现在路径任意段落：.../revyos-meles/20251115/...

    参数：
    - root_dir：cache 根目录（可以是总目录，也可以直接指到 entry 子目录）
    - entry_name：条目名（如 openwrt-sifiveu）
    - version_regex：提取版本的正则（按条目可自定义更严格）
    - max_depth：最大扫描深度（避免扫太深太慢）

    返回：{"24.10.4", "24.10.5", ...}
    """
    root = Path(root_dir)
    if not root.exists():
        return set()

    ver_pat = re.compile(version_regex)

    def iter_limited(base: Path, depth: int):
        if depth < 0:
            return
        try:
            for p in base.iterdir():
                yield p
                if p.is_dir():
                    yield from iter_limited(p, depth - 1)
        except PermissionError:
            return

    candidates: List[Path] = []
    for p in iter_limited(root, max_depth):
        # root_dir 若直接是 entry 子目录，则无需过滤 entry_name；
        # 否则要求路径含 entry_name 来缩小范围
        if root.name == entry_name or entry_name in str(p):
            candidates.append(p)

    versions: Set[str] = set()
    for p in candidates:
        # 从路径每一段提版本
        for part in p.parts:
            m = ver_pat.search(part)
            if m:
                versions.add(m.group(1).strip("/"))
        # 从文件/目录名提版本
        m2 = ver_pat.search(p.name)
        if m2:
            versions.add(m2.group(1).strip("/"))

    cleaned: Set[str] = set()
    for v in versions:
        cleaned.add(v.strip().strip("/"))
    return cleaned


# -------------------------
# 输出/读取工具
# -------------------------
def write_report(report: MissingReport, out_path: str | Path) -> None:
    """将报告写入 json 文件。"""
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(asdict(report), indent=2, ensure_ascii=False), encoding="utf-8")


def load_missing_all_from_report(path: str | Path) -> List[str]:
    """
    读取报告 json 文件里的 missing_all，返回 List[str]。
    （报告结构是 write_report 输出的 MissingReport 字典）
    """
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    missing_all = data.get("missing_all", [])
    return [str(x) for x in missing_all if x is not None]


# -------------------------
# CLI
# -------------------------
def main():
    ap = argparse.ArgumentParser(description="Missing version checker based on nvchecker regex entry.")
    ap.add_argument("--toml", required=True, help="Path to nvchecker.toml")
    ap.add_argument("--name", required=True, help="Entry name in nvchecker.toml, e.g. openwrt-sifiveu")
    ap.add_argument("--out", required=True, help="Output report json file path")

    # 二选一：--local-dir 或 --oldver
    ap.add_argument("--local-dir", help="Scan this cache directory as local inventory")
    ap.add_argument("--oldver", help="Path to old_ver.json (used as local baseline)")

    ap.add_argument("--max-depth", type=int, default=4, help="Max scan depth for local-dir (default 4)")
    ap.add_argument(
        "--version-regex",
        default=r"(v?\d+(?:\.\d+)+|\d{8})",
        help="Regex to extract versions from local cache paths/filenames",
    )

    args = ap.parse_args()
    checker = MissingVersionChecker(args.toml)

    if args.local_dir:
        local_versions = load_local_versions_from_dir(
            args.local_dir,
            args.name,
            max_depth=args.max_depth,
            version_regex=args.version_regex,
        )
    elif args.oldver:
        local_versions = load_local_versions_from_oldver(args.oldver, args.name)
    else:
        raise SystemExit("Either --local-dir or --oldver must be provided.")

    report = checker.compare(args.name, local_versions)
    write_report(report, args.out)

    print(f"[OK] wrote report: {args.out}")
    print(f"local latest : {report.latest_local}")
    print(f"remote latest: {report.latest_remote}")
    print(f"missing_all  : {report.missing_all}")
    print(f"missing_newer: {report.missing_newer}")


if __name__ == "__main__":
    main()
