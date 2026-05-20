# feature snapshot fixtures

This directory holds [capa freeze](../../../../capa/features/freeze/__init__.py) files that
serve as snapshot fixtures for feature extraction. They're consumed by
[`tests/test_feature_snapshots.py`](../../../test_feature_snapshots.py), which regenerates a
freeze from each sample and asserts it matches the committed `.frz` byte-for-byte. Any change
that perturbs what capa extracts (a backend fix, a new feature, a refactor that drops a
feature) shows up as a test failure with a feature-count delta and a truncated unified diff.

Each fixture is produced with `python -m capa.features.freeze --reproducible SAMPLE OUTPUT`.
The `--reproducible` flag zeros out dynamic header metadata (notably the capa version that
is otherwise embedded in the freeze) so fixtures stay stable across capa version bumps —
only changes to extracted features cause test failures.

This directory lives under `tests/fixtures/snapshots/features/`; the enclosing
`tests/fixtures/snapshots/` namespace is where future snapshot kinds (e.g. rendered
capabilities, verbose output) will live alongside this one.

## layout

- `manifest.json` — JSON list of snapshots (validated by `tests/feature_snapshot_util.py`).
  Each entry has:
  - `name`, `sample` (path under `tests/data/`), `freeze` (filename in this directory);
  - a human-written `explanation` describing why the sample was picked;
  - `generated_at_commit` — informational-only: the capa HEAD at which this fixture was last
    regenerated. Surfaced in test failure output so a reviewer can run
    `git log <commit>..HEAD -- capa/` to see what's changed since. Not validated at test
    time; humans keep it accurate when regenerating.
  - optional `format`/`backend`/`os` overrides that get passed through to the freeze CLI.
- `*.frz` — a `capa.features.freeze` byte stream (magic `capa0000` + zlib(utf-8(json(...)))).

## how the sample set was picked

The goal is to exercise every major (format, backend) pair capa supports with the smallest
reasonable sample, so running the snapshot suite stays under ~1 minute on a laptop while
still catching regressions in many extraction code paths. Each fixture's `explanation` field
in `manifest.json` spells out why that specific file is in the set and flags any candidate
for removal.

Backends/formats currently covered:

| fixture          | backend    | format           |
|------------------|------------|------------------|
| `pma01-01-dll`   | viv        | PE 32-bit DLL    |
| `mimikatz-exe`   | viv        | PE 32-bit EXE    |
| `pma21-01-exe`   | viv        | PE 64-bit EXE    |
| `7351f-elf`      | viv        | ELF              |
| `1c444-dotnet`   | dotnet     | .NET             |
| `mimikatz-exe-ida` | ida (idalib) | PE 32-bit EXE |

Backends deliberately not covered here today:
- BinExport2,
- Binary Ninja
- dynamic sandbox formats (CAPE, DRAKVUF, VMRay).

## regenerating a fixture after an intentional change

```
python -m capa.features.freeze --reproducible \
    tests/data/<sample> tests/fixtures/snapshots/features/<name>.frz
```

The freeze CLI logs a ready-to-paste manifest entry to its INFO output — including a
`generated_at_commit` taken from the current git HEAD — so updating `manifest.json` is
copy/paste.

## adding a new fixture

1. Add an entry to the `snapshots` list in `manifest.json`. At minimum specify `name`,
   `sample`, `freeze`, and `explanation`. Use `format`/`backend`/`os` only if the defaults
   don't pick the right extractor.
2. Generate the `.frz` file using the command above.
3. Copy the `generated_at_commit` the CLI suggested into the manifest entry.
4. Commit the updated manifest and the new `.frz` file together.
