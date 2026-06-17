from __future__ import annotations

import importlib.util
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.egg_info import egg_info as _egg_info
from setuptools.command.sdist import sdist as _sdist


def _load_sync_assets():
    script = Path(__file__).resolve().parent / "scripts" / "sync_assets.py"
    if not script.exists():
        return lambda: None
    spec = importlib.util.spec_from_file_location("_canaryweave_sync_assets", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load asset sync script: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.sync_assets


sync_assets = _load_sync_assets()


class SyncAssetsMixin:
    def run(self):
        sync_assets()
        super().run()


class build_py(SyncAssetsMixin, _build_py):
    pass


class egg_info(SyncAssetsMixin, _egg_info):
    pass


class sdist(SyncAssetsMixin, _sdist):
    pass


setup(
    cmdclass={
        "build_py": build_py,
        "egg_info": egg_info,
        "sdist": sdist,
    }
)
