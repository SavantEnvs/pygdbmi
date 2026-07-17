# Known finding: infinite loop on an unterminated array

Reproducer: `unterminated-array-hang` (the input `^done,a=[`, no trailing newline).

- **Cause:** `gdbmiparser.parse_response` -> `_parse_array` loops forever. `StringStream.read()`
  keeps returning `""` past the end of the stream, and the loop never sees the closing `]`.
- **Impact:** any caller feeding unterminated GDB/MI output (e.g. a truncated pipe) hangs (DoS).
- **Fix (upstream):** in `_parse_array`, raise `ValueError` when `stream.read(1)` returns `""`.

The harness does not guard this. Reproduced locally, libFuzzer `-timeout=5` reports it as
`libFuzzer: timeout` with a `_parse_array` frame. On Mayhem the run did not record it as a defect:
the stored corpus from earlier, guarded runs holds inputs that hit this same hang, and the workers
stalled on them (60 execs in a 300s run). The reproducer is kept out of `testsuite/` so seeds do not
replay it every run.
