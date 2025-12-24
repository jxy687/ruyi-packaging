"""
Check latest and setup riko local cache
"""

import json
import logging
import os
import subprocess

from typing import Dict, List

from .utils import ensure_dir
from ..config.const import basedir, nvchecker_datadir, riko_datadir, ruyi_datadir, ruyi_cache_dir, ruyi_state_dir, \
    ruyi_data_dir, ruyi_config_dir, ruyi_config, ruyi_config_extra, nvchecker_config, nvchecker_result, nvchecker_key, nvchecker_local_ver
from ..rikoriko import get_riko

logger = logging.getLogger(__name__)


def _ensure_riko_path() -> None:
    ensure_dir(riko_datadir)


def _ensure_nvchecker_path() -> None:
    ensure_dir(nvchecker_datadir)


def _ensure_ruyi_path() -> None:
    ensure_dir(ruyi_datadir)
    ensure_dir(ruyi_config_dir)
    ensure_dir(ruyi_config_dir / 'ruyi')
    ensure_dir(ruyi_data_dir)
    ensure_dir(ruyi_cache_dir)
    ensure_dir(ruyi_state_dir)


def _ensure_paths() -> None:
    """
    Ensures that the data directories exist.
    :return:
    """
    _ensure_riko_path()
    _ensure_nvchecker_path()
    _ensure_ruyi_path()


def _ensure_nvchecker_env(env: Dict) -> None:
    env['PYTHONPATH'] = str(basedir)


def _ensure_ruyi_env(env: Dict) -> None:
    env['XDG_CONFIG_HOME'] = str(ruyi_config_dir)
    env['XDG_DATA_HOME'] = str(ruyi_data_dir)
    env['XDG_CACHE_HOME'] = str(ruyi_cache_dir)
    env['XDG_STATE_HOME'] = str(ruyi_state_dir)


def check() -> None:
    """
    Sets up all
    :return:
    """
    _ensure_paths()
    #'/home/jxy/桌面/PR3/ruyi-packaging-checker/cache/ruyi/config/ruyi/config.toml'
    with open(ruyi_config_dir / "ruyi" / "config.toml", "w") as cfg:
        cfg.write(ruyi_config + "\n" + ruyi_config_extra)

    # ruyi update
    logger.info("run `ruyi update`")
    cmd: List[str] = ["ruyi", "update"]
    env = os.environ.copy()
    rfd, wfd = os.pipe()

    _ensure_ruyi_env(env)
    process = subprocess.Popen(cmd, stdout=wfd, stderr=wfd, env=env)
    os.close(wfd)

    out = os.fdopen(rfd)
    output = out.read()
    out.close()

    ret = process.wait()
    if ret != 0:
        raise subprocess.CalledProcessError(ret, cmd, output)

    #'/home/jxy/桌面/PR3/ruyi-packaging-checker/cache/ruyi/cache'/ruyi/packages-index
    if not (ruyi_cache_dir / "ruyi" / "packages-index").exists():
        raise FileNotFoundError(ruyi_cache_dir / "ruyi" / "packages-index")

    # nvchecker config/old_ver
    logger.info("prepare for `nvchecker`")
    get_riko().generate_nvchecker_config()##/home/jxy/桌面/PR3/ruyi-packaging-checker/cache/nvchecker/nvchecker.toml
    get_riko().generate_nvchecker_old_ver()#根据ruyi_packages，packages-index生成ruyi_packages的old_ver.json供nvchecker使用
    get_riko().generate_local_inventory(nvchecker_local_ver)#根据ruyi_packages，packages-index生成ruyi_packages的old_ver.json供nvchecker使用


    # run nvchecker
    logger.info("run `nvchecker`")
    rfd, wfd = os.pipe()
    cmd: List[str] = ["nvchecker", "--logger", "both", "--json-log-fd", str(wfd), "-c", nvchecker_config]
    env = os.environ.copy()
    _ensure_nvchecker_env(env)

    if nvchecker_key.exists():
        cmd.extend(['--keyfile', nvchecker_key])

    process = subprocess.Popen(cmd, pass_fds=(wfd, ), env=env)
    os.close(wfd)

    out = os.fdopen(rfd)
    with open(nvchecker_result, "w") as f:
        f.write("[")
        for l in out:
            f.write(f"{l.strip()},")
        f.seek(f.tell() - 1, os.SEEK_SET)
        f.write("]")
    out.close()

    ret = process.wait()
    if ret != 0:
        raise subprocess.CalledProcessError(ret, cmd, output)

    # format json file
    with open(nvchecker_result, "r") as f:
        output = f.read()
    with open(nvchecker_result, "w") as f:
        json.dump(json.loads(output), f, indent=2)

    if not nvchecker_result.exists():
        raise FileNotFoundError(nvchecker_result)




