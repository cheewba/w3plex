# Config resource ownership evidence

Recorded on 2026-10-21 before changing parser or Runner behavior. The prepared
linked worktree was clean at `a22c65d9806277abb54a4f8fa8cc465ee8e2ee54`.
Environment: native macOS 26.5.2 arm64, CPython 3.12.12, pytest 9.0.2.

Inspected `test_config.py`, `test_protected_config_tree.py`,
`test_config_reading_baseline.py`, `test_reference_config_tree.py`,
`test_config_compatibility.py` and `test_resources.py`. Inspected the related
w3ext `test_chain_provider_cleanup.py` at
`8ddcd1c8df482eb2551250d2ba51d9f7370f21b4`; w3ext was not edited.

Added eight missing cases in `tests/test_config_resource_ownership.py` and
verified them on unchanged library behavior. They cover parser and Runner
defaults, real descriptor lifetime after successful construction and later
constructor failure/cancellation, alias deduplication, repeat close, reset
Runner state, and propagation of closer failure. Together with existing config,
protected config, resource and w3ext provider cleanup tests, the run passed:
**54 passed, 14 warnings, 7.31 seconds**. The prepared application interpreter
ran `-B -m pytest -q -p no:cacheprovider` against those five test files.

No checkout, reset, environment synchronization, staging, commit, merge or
publication was performed. These characterization tests are preserved.

## Optional caller ownership

`Runner.init` and config loader `parse` accept an optional
`resource_owner: AsyncExitStack`. Without it, defaults remain unchanged: parse
closes resources on failure, ConfigTree owns successful resources, and Runner
finalizes failed initialization. With it, the caller must close its stack on
success or failure and finalize its Runner. ConfigTree does not also close
caller-owned callbacks. A host can therefore retain and shield its actual
failed-construction cleanup, rather than trying to close an unavailable tree.

The same test file adds 18 caller-owner cases. Parser and Runner paths cover
success, later constructor failure and cancellation for objects with close
methods, generators and async generators. Real descriptors stay open through
tree/Runner close until the caller closes its stack, then close exactly once.

The final application/config/library selection passed 166 tests, 116 warnings
in 23.34 seconds. A disjoint storage/layout/protected-reference selection passed
169 tests, 13 warnings in 17.02 seconds. Owned library files passed Ruff 0.16.8
lint/format and Pyright 1.1.414 with zero errors/warnings using prepared imports.

This is a local additive API based on `a22c65d`, not a published revision.
Reviewed editable sources can support local integration and application tests.
Distribution still requires authorized publication, a compatible public
dependency pin and lock, and a fresh locked installation check. Existing public
pins were not changed by this work.
