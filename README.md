# rea-raw-preflight

Decide **before** you burn a REA run whether a binary file falls inside the limits that
REA's own raw-binary provider documents for itself — offline, with byte-level witnesses.

Why now: `morluto/rea` is trending and its raw path is the entry point people reach for
when they have a firmware blob with no container. That path documents two hard refusals,
but nothing tells you *which files* they apply to until the run has already failed.

Upstream: https://github.com/morluto/rea

## What the upstream does, and where the gap is

REA reverse-engineers binaries through an agent/MCP workflow. Its raw-binary provider is
what you use for a headerless blob, and its docs state the boundary explicitly
([`docs/providers/raw-binary.md#limitations`](https://github.com/morluto/rea/blob/main/docs/providers/raw-binary.md#limitations),
verified line 150–153 on `main`):

> Headers are not discovered from file bytes. This increment does not guess load
> addresses, vector tables, or memory maps.
>
> Big-endian ARM, Thumb-only, Cortex-M, and other Ghidra processor variants are
> unsupported.

A second doc says the limits are structural, not best-effort
([`docs/design/limits-and-recovery.md`](https://github.com/morluto/rea/blob/main/docs/design/limits-and-recovery.md),
lines 27–29): it *"cannot change a client deadline, extend accepted work, release
retained resources, or remove a fixed representation limit."*

So the gap is an admission-control gap: the limits are written down for humans, but there
is no offline way to ask "**is this specific file one of the files this paragraph is about,
and which bytes say so?**" You find out by wiring the file into a Ghidra-backed run.

## What this tool does / does not do

Does:

- classifies a file by documented magic numbers (ELF, Mach-O, PE, Electron ASAR) and
  headerless raw;
- for headerless files, reports the documented REA blocker that applies
  (`FIXED_LOAD_ADDRESS_REQUIRED`, `THUMB_ONLY_OR_CORTEX_M_UNSUPPORTED`,
  `BIG_ENDIAN_ARM_UNSUPPORTED`);
- prints a **byte-offset witness** for every blocker (hex bytes, word values, match score)
  and a `confidence` of `high` / `medium` / `low`, plus `ABSTAIN` when the file is too
  small or too ambiguous to classify honestly;
- is a plain CLI: deterministic, no network, no writes, no third-party packages.

Does not:

- call REA, Ghidra, or any network service;
- prove that a file *will* decompile correctly on a supported variant;
- replace REA's own validation — it is a preflight, not a verdict about REA's internals.

## Install

```bash
git clone <this repo> && cd rea-raw-preflight
python3 --version   # 3.8+; no dependencies
```

## Usage

```bash
python3 bin/rea-raw-preflight examples/in/firmware-cortex-m.bin
python3 bin/rea-raw-preflight examples/in/firmware-cortex-m.bin --json
python3 bin/rea-raw-preflight examples/in/example.elf --json
```

Regenerate the synthetic fixtures and their golden reports:

```bash
python3 examples/gen_fixtures.py && python3 examples/gen_golden.py
```

### `--json` output (real run, `examples/in/firmware-cortex-m.bin`)

```json
{
  "blockers": [
    {
      "code": "THUMB_ONLY_OR_CORTEX_M_UNSUPPORTED",
      "doc_url": "https://github.com/morluto/rea/blob/main/docs/providers/raw-binary.md#limitations",
      "witness": {
        "endian": "little",
        "offset": 0,
        "score": "15/15",
        "thumb_handlers": [{"index": 1, "offset": 4, "target": "0x100", "value": "0x101"}],
        "word0_stack_pointer": {"offset": 0, "value": "0x20001000"}
      }
    }
  ],
  "confidence": "high",
  "container": "raw",
  "sha256_12": "9ba0d6ffb8d2",
  "verdict": "BLOCKED"
}
```

(The file above is abbreviated to the fields that matter; `examples/out/*.json` are the
full golden reports and the test suite asserts them byte-for-byte.)

### Exit codes

| code | meaning |
| --- | --- |
| `0` | a container path exists — REA can read this file without the raw-binary workarounds |
| `1` | a documented blocker applies, or the file is too ambiguous to classify (`ABSTAIN`) |
| `2` | usage or input error (missing file, unreadable file, bad `--min-thumb`) |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

14 tests, all stdlib, no network. They cover the four container magics, the
Cortex-M/Thumb and big-endian witnesses, the opaque-blob and tiny-file paths, all three
exit codes through real subprocess runs, JSON parseability, run-to-run byte identity, and
golden-file equality.

## 局限

- The Cortex-M/Thumb and big-endian judgements are **heuristics**: word 0 must be a
  plausible RAM pointer and at least `--min-thumb` (default 12 of 15) handlers must carry
  the Thumb bit and land inside the file. Raise `--min-thumb` to make it stricter; below
  the threshold the tool says `NEEDS_ENTRY_POINT` instead of claiming a blocker.
- The bundled fixtures under `examples/in/` are **synthetic**, built from each format's
  documented on-disk layout. No real device firmware is shipped, so this repo makes no
  statement about real-world detection rates.
- Only the containers listed are recognised; other formats become `raw` and are treated as
  `NEEDS_ENTRY_POINT`.
- Blocker text is quoted from the upstream docs as of the commit verified on 2026-11-13;
  if upstream changes those paragraphs, re-check the links.

## 本轮创新

把上游文档里写给人的两条 raw-binary 限制条款，编译成对**具体文件**的、带字节级见证与显式
abstain 的离线准入判定，并给出 `--min-thumb` 阈值让召回/保守可调。与「再写一个静态格式
linter」不同：结论由文件字节本身支撑（offset / word / score），证据不足时拒绝下结论。

## 与同类项目的差异

`LaurieWired/GhidraMCP`、`bethington/ghidra-mcp` 等做的是让 agent 调 Ghidra；本工具不做
反编译，只在调用前判断某个文件是否落在 REA 明文不支持的范围，输出可断言的退出码与见证。

## License

MIT — see `LICENSE`.
