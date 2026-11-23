#!/usr/bin/env python3
"""Fail if a plugin QML file misses PlainText or uses a native text control."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BANNED = re.compile(r"\b(TextField|TextArea|TextInput|TextEdit|StdioCollector)\b")
TEXT = re.compile(r"\b(Text|Label|TextEdit|StyledText)\s*\{")


def block_end(src, start):
    depth = 1
    i = start
    while i < len(src) and depth:
        depth += (src[i] == "{") - (src[i] == "}")
        i += 1
    return i


def main():
    failed = False
    for path in sorted(ROOT.glob("*.qml")):
        src = path.read_text(encoding="utf-8")
        if "\x00" in src:
            print(f"NUL byte in {path.name}")
            failed = True
        if BANNED.search(src):
            print(f"banned control in {path.name}")
            failed = True
        for match in TEXT.finditer(src):
            end = block_end(src, match.end())
            if "textFormat:" not in src[match.end():end]:
                line = src[:match.start()].count("\n") + 1
                print(f"MISSING textFormat {path.name}:{line}")
                failed = True
    if failed:
        return 1
    print("qml audit passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
