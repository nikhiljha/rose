# Version Control

This project uses [Jujutsu (jj)](https://github.com/jj-vcs/jj) instead of raw git. Use `jj` commands for all version control operations (e.g., `jj describe`, `jj new`, `jj log`, `jj diff`). Do NOT use `git commit`, `git add`, etc.

# Project Commands

## Building

Do NOT do release builds, unless explicitly testing performance. This just wastes time.

```
cargo build
```

## Testing

All of these must pass in CI.

```
cargo fmt --all
cargo clippy --workspace --all-targets --fix --allow-dirty
cargo nextest run --all --no-fail-fast
cargo +nightly llvm-cov-easy nextest --workspace --branch
```

### Testing philosophy

Every test must:

- Call real production code (not just test helpers)
- Exercise a distinct code path
- Test something interesting (edge case, error condition, specific behavior)

**What makes a test interesting?**
- It goes down a different code path than other tests
- It tests an edge case (empty input, boundary values, overflow)
- It tests error handling
- It verifies a specific invariant

**What makes a test superfluous?**
- It exercises the exact same code path as another test
- It only differs in input values that don't affect control flow
- It tests obvious behavior that can't reasonably break

Testing does not end with coverage. For example, end-to-end tests are extremely valuable. You should think about building infrastructure for end-to-end tests where neccesary (add to TODO.org triage list, but do NOT edit anything else in that file because that is the job of the project manager).

### Lint allow policy

- Allows must be as narrow as possible (line-level preferred over function-level and module-level)
- Every allow must include a comment justifying why it's necessary
- Consider whether the need for an allow indicates a design problem
  - If it does, fix the design problem. If this requires a larger refactor, add it to the TODO.org triage list (do NOT edit any other TODOs in ANY way, that is the job of the project manager).

### Coverage allow policy

The goal is 100% coverage on all regions, functions, lines, and branches. You should always aim for 100% but if there is really no way to cover some code then you may exclude it from coverage. You should leave a comment explaining why you can't cover it. Below is an example of coverage exclusion:

```
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

/// This cfg_attr works on functions and modules. Untested code should be kept
/// to a minimum because it requires extra scrutiny and manual testing when things
/// change.
/// COVERAGE: This function is excluded from coverage because blablabla.
#[cfg_attr(coverage_nightly, coverage(off))]
fn exclude_fn_from_coverage() {
    // ...
}
```

To find coverage gaps, run:

```bash
cargo +nightly llvm-cov-easy nextest --workspace --branch
```

This shows uncovered lines, branches, and functions in a simple, self-explanatory format.

## Benchmarks

If you make changes that may cause a performance regression you should run performance benchmarks. No need to run these for changes that are definitely unrelated. If you write a function that is pure (lots of pure functions are generally good) and seems potentially complex, you should make a microbenchmark for it.

```
cargo bench -p rose
```

## Code Duplication

You should avoid code duplication as much as possible. You can use polydup (from `cargo install --git https://github.com/nikhiljha/polydup-fork`, if not installed) to scan for duplicates.

```
# Zero duplicates are allowed at 75, but consider also running at 50 to catch more things
polydup scan ./src -t 75

# Also caching for fast incremental scans
polydup cache build
polydup scan . --git-diff origin/main..HEAD
```

## Security

```
cargo deny check
```

# Code Processes

## Bug Fixes

When fixing a bug, always write a regression test first:

1. Write a test that reproduces the bug
2. Verify the test fails
3. Fix the bug
4. Verify the test passes

Never skip step 2. If your test doesn't fail before the fix, you're not actually testing the bug—you're testing something else. This discipline ensures you understand the bug and that your fix actually addresses it.

## Mocking Policy

Avoid mocks wherever possible. Prefer:

1. Real implementations (even if slower)
2. In-memory implementations of traits (not mocks, actual implementations)
3. Test fixtures with real data

Mocks are acceptable only when:
- External services cannot be reasonably simulated
- Real implementation would be prohibitively slow or flaky
- Testing error conditions that are hard to trigger naturally

## External Libraries

- Don't manually add dependencies by editing `Cargo.toml`. Use `cargo add`.
- Don't guess at the API for external libraries. Add them to the project and look at the source code in `target/`.

## Conventions

- Selected MachineApplicable clippy pedantic + nursery lints are enforced as warnings (CI fails on warnings)
- All public items must be documented
- Tests use `cargo nextest` and `insta` for snapshot testing
- Benchmarks use `criterion`

# Architecture

RoSE (Remote Shell Environment) is a Mosh-inspired remote terminal over QUIC. See `doc/spec.md` for the full specification.

This is a Cargo workspace with two crates:

- `lib/` — library crate (`rose`) containing core logic (terminal emulation via wezterm, state synchronization protocol, QUIC transport via quinn, PTY management via portable-pty). Uses `thiserror` for errors and `tracing` for instrumentation.
- `cli/` — binary crate (`rose-cli`, binary name `rose`) providing subcommands: `connect`, `server`, `keygen`. Uses `tokio`, `anyhow`, `clap`, and `tracing-subscriber`.

# Code Review Checklist

Besides obvious things like correctness...

## Documentation

- If things in the `AGENTS.md` should have been updated, were they updated?
- No overzealous checking off of tasks in `TODO.org` or similar TODO files.

## Allows

- Allows for lints should almost never be used. Basically 100% of the time, there is some underlying structural issue with how the code was written, and it is worth refactoring to fix the issue, even if "no no, it is actually fine in this case". Papering over things when they are small problems is how you get big problems later. Strongly considering rejecting code review if there are allows.

## Security

- Is the code secure and using best practices?

