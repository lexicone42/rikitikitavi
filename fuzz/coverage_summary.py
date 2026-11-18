"""Summarise `llvm-cov report -show-functions` (stdin) for parser and classifier functions."""

import re
import sys

PARSER = re.compile(
    r"^(parse|classify|decode|decrypt|extract|read_ber|analy[sz]e|identify|skip_name"
    r"|detect_framework|is_default|is_directory|find_wan)"
)

rows: dict[tuple[str, str], tuple[int, int]] = {}
for line in sys.stdin:
    p = line.split()
    if len(p) < 10 or not p[-1].endswith("%") or p[0] in ("TOTAL", "Name"):
        continue
    name = " ".join(p[:-9])
    if "::tests::" in name or "::fuzz::" in name:
        continue
    parts = re.sub(r"(::\{closure#\d+\})+$", "", name).split("::")
    if len(parts) < 3:
        continue
    key = ("::".join(parts[:-1]).replace("rikitikitavi_", ""), parts[-1])
    lines, missed = rows.get(key, (0, 0))
    rows[key] = (lines + int(p[-6]), missed + int(p[-5]))

sel = [(m, f, n, x) for (m, f), (n, x) in rows.items() if PARSER.match(f) and n >= 8]
total = sum(r[2] for r in sel)
missed = sum(r[3] for r in sel)
never = sorted((r for r in sel if r[3] == r[2]), key=lambda r: -r[2])
partial = sorted((r for r in sel if 0 < r[3] < r[2] and r[3] / r[2] > 0.3), key=lambda r: -r[3])
print(f"{len(sel)} functions, {total - missed}/{total} lines ({100 * (total - missed) // total}%)")
print(f"never entered: {len(never)}")
for m, f, n, _ in never:
    print(f"  {m}::{f}  {n} lines")
print(f"under 70%: {len(partial)}")
for m, f, n, x in partial:
    print(f"  {m}::{f}  {n - x}/{n}")
