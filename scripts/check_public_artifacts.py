from __future__ import annotations

# Public-artifact "disallowed raw shape" scanning has been intentionally removed.
#
# CanaryWeave FIDES is MIT-licensed and published as an open security benchmark.
# Detection signatures (regexes for credential-file paths, LOLBin command shapes,
# prompt-injection phrasings, etc.) are defensive content that the community needs
# in order to reproduce and extend the benchmark, so they are allowed in committed
# rules and datasets. This script is kept as a no-op so existing eval/demo runners
# and documented commands continue to work.


def main() -> int:
    print("public artifact safety ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
