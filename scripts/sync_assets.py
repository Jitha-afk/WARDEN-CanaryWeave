from __future__ import annotations

import shutil
from pathlib import Path


ASSET_DIRS = ("rules", "conf", "data", "yara")


def sync_assets(root: Path | str | None = None) -> None:
    repo_root = Path(root) if root is not None else Path(__file__).resolve().parents[1]
    asset_root = repo_root / "src" / "canaryweave_fides" / "assets"
    missing = [name for name in ("rules", "conf", "data") if not (repo_root / name).is_dir()]
    if missing:
        existing_mirror = all((asset_root / name).is_dir() for name in ("rules", "conf", "data"))
        if existing_mirror:
            return
        raise FileNotFoundError(f"missing asset source directories: {', '.join(missing)}")

    asset_root.mkdir(parents=True, exist_ok=True)

    for name in ASSET_DIRS:
        source = repo_root / name
        target = asset_root / name
        if target.exists():
            shutil.rmtree(target)
        if source.exists():
            if not source.is_dir():
                raise NotADirectoryError(f"asset source is not a directory: {source}")
            shutil.copytree(source, target)


if __name__ == "__main__":
    sync_assets()
