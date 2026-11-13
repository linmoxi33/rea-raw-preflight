#!/usr/bin/env python3
"""Behavioural tests: 11 CLI-level cases plus core-level assertions, all stdlib-only."""
import hashlib
import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from rea_raw_preflight import analyze_bytes, analyze_file  # noqa: E402

BIN = os.path.join(ROOT, "bin", "rea-raw-preflight")
IN = os.path.join(ROOT, "examples", "in")
OUT = os.path.join(ROOT, "examples", "out")

CASES = {
    "example.elf": ("ELF", "CONTAINER_PATH", 0),
    "example.macho": ("Mach-O", "CONTAINER_PATH", 0),
    "example.pe": ("PE", "CONTAINER_PATH", 0),
    "example.asar": ("ASAR", "CONTAINER_PATH", 0),
    "firmware-cortex-m.bin": ("raw", "BLOCKED", 1),
    "firmware-big-endian.bin": ("raw", "BLOCKED", 1),
    "opaque.bin": ("raw", "NEEDS_ENTRY_POINT", 1),
    "tiny.bin": ("raw", "ABSTAIN", 1),
}


def run(*args):
    return subprocess.run([sys.executable, BIN, *args], capture_output=True, text=True)


class ClassifierTest(unittest.TestCase):
    def test_each_fixture_gets_expected_container_verdict_and_exit_code(self):
        for name, (container, verdict, rc) in CASES.items():
            with self.subTest(name=name):
                rep = analyze_file(os.path.join(IN, name))
                self.assertEqual(container, rep["container"])
                self.assertEqual(verdict, rep["verdict"])

    def test_exit_codes_via_real_process(self):
        for name, (_c, _v, rc) in CASES.items():
            with self.subTest(name=name):
                proc = run(os.path.join(IN, name))
                self.assertEqual(rc, proc.returncode, proc.stderr)

    def test_missing_file_is_usage_error_rc2(self):
        proc = run(os.path.join(IN, "does-not-exist.bin"))
        self.assertEqual(2, proc.returncode)
        self.assertIn("no such file", proc.stderr)

    def test_no_argument_is_usage_error_rc2(self):
        self.assertEqual(2, run().returncode)

    def test_bad_min_thumb_is_usage_error_rc2(self):
        self.assertEqual(2, run(os.path.join(IN, "opaque.bin"), "--min-thumb", "99").returncode)

    def test_json_flag_parses_and_carries_witness(self):
        proc = run(os.path.join(IN, "firmware-cortex-m.bin"), "--json")
        rep = json.loads(proc.stdout)
        self.assertEqual("THUMB_ONLY_OR_CORTEX_M_UNSUPPORTED", rep["blockers"][0]["code"])
        w = rep["blockers"][0]["witness"]
        self.assertEqual(0, w["offset"])
        self.assertEqual("0x20001000", w["word0_stack_pointer"]["value"])
        self.assertEqual("little", w["endian"])
        self.assertTrue(rep["blockers"][0]["doc_url"].startswith("https://github.com/morluto/rea/"))

    def test_min_thumb_raises_the_bar_for_calling_it_cortex_m(self):
        strict = analyze_file(os.path.join(IN, "firmware-cortex-m.bin"), min_thumb=16)
        self.assertEqual("NEEDS_ENTRY_POINT", strict["verdict"])
        loose = analyze_file(os.path.join(IN, "firmware-cortex-m.bin"), min_thumb=15)
        self.assertEqual("BLOCKED", loose["verdict"])

    def test_big_endian_witness_is_marked_big_endian(self):
        rep = analyze_file(os.path.join(IN, "firmware-big-endian.bin"))
        self.assertEqual("big", rep["blockers"][0]["witness"]["endian"])
        self.assertEqual("medium", rep["confidence"])

    def test_sha256_12_matches_hashlib(self):
        path = os.path.join(IN, "opaque.bin")
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()[:12]
        self.assertEqual(digest, analyze_file(path)["sha256_12"])

    def test_repeated_runs_are_byte_identical(self):
        first = run(os.path.join(IN, "firmware-cortex-m.bin"), "--json").stdout
        second = run(os.path.join(IN, "firmware-cortex-m.bin"), "--json").stdout
        self.assertEqual(first, second)

    def test_human_output_prints_the_documented_source(self):
        proc = run(os.path.join(IN, "opaque.bin"))
        self.assertIn("FIXED_LOAD_ADDRESS_REQUIRED", proc.stdout)
        self.assertIn("raw-binary.md#limitations", proc.stdout)

    def test_golden_reports_match_live_output(self):
        for name, (_c, _v, rc) in CASES.items():
            with self.subTest(name=name):
                golden = json.load(open(os.path.join(OUT, name + ".json")))
                live = json.loads(run(os.path.join(IN, name), "--json").stdout)
                live["file"] = name
                self.assertEqual(golden, live)
                self.assertEqual(rc, run(os.path.join(IN, name)).returncode)

    def test_small_blob_never_claims_a_container(self):
        self.assertEqual("raw", analyze_bytes(b"\x00" * 16)["container"])
        self.assertEqual("ABSTAIN", analyze_bytes(b"\x00" * 16)["verdict"])

    def test_mz_without_pe_signature_is_not_called_pe(self):
        self.assertEqual("raw", analyze_bytes(b"MZ" + b"\x00" * 200)["container"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
