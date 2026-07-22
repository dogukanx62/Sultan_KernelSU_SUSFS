#!/usr/bin/env python3
"""Fail closed if the tested Sultan/Baseband Guard safecred2 design drifts."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def read(path: Path) -> str:
    require(path.is_file(), f"missing required source file: {path}")
    return path.read_text(encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: validate_safecred2.py <kernel-tree> <ksu-tree>")

    kernel = Path(sys.argv[1]).resolve()
    ksu = Path(sys.argv[2]).resolve()

    makefile = read(kernel / "security/baseband-guard/Makefile")
    guard = read(kernel / "security/baseband-guard/baseband_guard.c")
    tracing_c = read(kernel / "security/baseband-guard/tracing/tracing.c")
    tracing_h = read(kernel / "security/baseband-guard/tracing/tracing.h")
    app_profile = read(ksu / "kernel/policy/app_profile.c")

    require(
        'BBG_VERSION=\\"cef0daae-sultan-safecred2\\"' in makefile,
        "Baseband Guard safecred2 version marker is missing",
    )
    require("case BLKROSET:" in guard, "BLKROSET protection is missing")
    require("case BLKSETRO:" not in guard, "invalid BLKSETRO constant returned")

    direct_block = re.search(
        r"if \(unlikely\(S_ISBLK\(inode->i_mode\)\)\).*?\{"
        r"(?P<body>.*?)\n\s*\}",
        guard,
        flags=re.DOTALL,
    )
    require(direct_block is not None, "direct block-device branch is missing")
    direct_body = direct_block.group("body")
    require("block_add(inode->i_rdev);" in direct_body, "block cache update is missing")
    require(
        re.search(r"block_add\(inode->i_rdev\);\s*return 1;", direct_body) is not None,
        "protected direct block device does not return protected=true",
    )

    forbidden_exec_hooks = (
        "bb_bprm_set_creds",
        "bprm_creds_for_exec",
        "LSM_HOOK_INIT(bprm_set_creds",
        "security_cred_getsecid",
    )
    combined_guard = guard + tracing_c
    for token in forbidden_exec_hooks:
        require(token not in combined_guard, f"unsafe early exec hook returned: {token}")

    require("LSM_HOOK_INIT(cred_prepare" in guard, "cred_prepare hook is missing")
    require("LSM_HOOK_INIT(cred_transfer" in guard, "cred_transfer hook is missing")
    require("void bbg_mark_cred_untrusted(struct cred *cred)" in tracing_c,
            "direct KernelSU credential marker is missing")
    require("if (unlikely(!cred || !cred->security))" in tracing_h,
            "null-safe credential blob access is missing")
    require("return !bbg_tsec || !bbg_tsec->is_untrusted_process;" in tracing_h,
            "null-safe trusted-process check is missing")

    marker = "bbg_mark_cred_untrusted(cred);"
    require(
        app_profile.count(marker) == 2,
        "KernelSU must mark exactly both tested root credential paths",
    )
    require("bbg_cred(cred)->is_untrusted_process" not in app_profile,
            "KernelSU bypasses the null-safe Baseband Guard marker")

    print("safecred2 source invariants verified")


if __name__ == "__main__":
    main()
