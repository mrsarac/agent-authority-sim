# Spec lock v0.1.0

This directory holds an immutable snapshot of the authority-model specification.
The simulator and its tests read these files as their canonical input.

**Do not edit these files directly.**

`spec-lock.json` records the size and SHA-256 of every file in this snapshot and of `requirements.lock`.
If any of these files changes, `scripts/verify_spec_lock.py` and the spec-lock tests fail.

The `Status:` line at the top of each document records the state when the spec was written, before any simulator code existed.
The top-level README says what the simulator covers today.

For publication, internal project and host names in these files were replaced with neutral terms
(for example "coordinator", "operator" and "decision plane"), and `spec-lock.json` was regenerated.
The rules themselves were not changed.
