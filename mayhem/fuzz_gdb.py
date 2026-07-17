#!/usr/bin/env python3
"""Atheris fuzz harness for pygdbmi.

Exercises the GDB Machine-Interface (GDB/MI) response parser on arbitrary
input. Atheris instruments the imported pygdbmi modules (coverage), so
libFuzzer drives the parser toward new code paths.

Run modes (driven by the compiled launcher `pygdbmi_fuzzer` / `-standalone`):
  * fuzzing      - `python3 fuzz_gdb.py [libFuzzer args]`
  * single input - `python3 fuzz_gdb.py <file>` (libFuzzer runs it once)
"""
import sys

import atheris

import fuzz_helpers

# Instrument ONLY the library under test (scope the include list so import time
# stays low in libFuzzer fork mode - a bare instrument_imports() would pull in
# hundreds of stdlib modules and stall every fork child at startup).
with atheris.instrument_imports(include=["pygdbmi"]):
    from pygdbmi import gdbmiparser
    from pygdbmi.gdbescapes import unescape, advance_past_string_with_gdb_escapes
    from pygdbmi.StringStream import StringStream


def TestOneInput(data: bytes) -> None:
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    text = fdp.ConsumeRandomString()
    rest = fdp.ConsumeRemainingString()

    # 1) Core GDB/MI response parser.
    try:
        gdbmiparser.parse_response(text)
    except ValueError:
        # ValueErrors on malformed input (bad quotes/escapes) are expected.
        pass
    except TypeError:
        # parse_response requires a str; a non-str is harness misuse.
        pass

    # 2) The lower-level escape handling + string stream, on the rest.
    try:
        unescape(rest)
    except ValueError:
        pass
    try:
        advance_past_string_with_gdb_escapes(rest)
    except (ValueError, IndexError):
        pass
    try:
        stream = StringStream(rest)
        stream.advance_past_chars(["\n"])
    except (ValueError, IndexError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
