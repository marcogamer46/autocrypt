# Adding a new solver

A solver is just a **match rule** and a **generator**. You write one function, decorate it, and the search loop picks it up automatically — no wiring into `core.py` required. This page walks through the whole contract. The complete catalog of all 146 registered solvers and their module map lives in [SOLVERS.md](../SOLVERS.md).

## The three moving parts

Every solver is declared with the `@solver(name, matches)` decorator from `autocrypt/core.py`:

```python
@solver("my-cipher", _my_prior)
def solve_my_cipher(data, ctx):
    ...
```

- **`name`** — a stable identifier shown in result chains (e.g. `trifid`, `nihilist`).
- **`matches(fp)`** — returns a **prior probability** in `[0, 1]` given the fingerprint dict. `0.0` skips the solver entirely; higher priors schedule it earlier in the best-first heap.
- **the decorated function** — a generator `solve(data, ctx)` that `yield`s candidate plaintexts.

The decorator (`core.py`) appends a `Solver(name, matches, fn)` record to the module-level `REGISTRY`. If you add your function in a `solvers*.py` file, it is registered for the when `autocrypt/solvers.py` imports that module — which `core.search()` and every worker process do automatically.

## `matches(fp)`: when should your solver fire?

`fp` is the dict returned by `core.fingerprint()`: `charset`, `length`, `entropy`, `ic`, `magic`, `classes`, `hypotheses`, `prior_map`, and the raw `_text`. Look at the structural stats, not the content. Return `0.0` for anything you cannot handle so you never waste a time slice.

A compact example from `solvers_pack5.py`:

```python
def _trifid_prior(fp):
    if fp["charset"] != "ascii-text" or not 18 <= fp["length"] <= 5000:
        return 0.0
    if not re.fullmatch(r"[A-Za-z.\s]+", fp.get("_text", "").strip()):
        return 0.0
    return .45
```

`charset` is the most useful gate: `ascii-text` for letter ciphers, `binary` for byte transforms, plus the encoding classes for frame formats.

## The generator contract

`solve(data, ctx)` is a generator that yields a 4-tuple per candidate:

```python
yield plaintext, method, params, claimed_score
```

- **`plaintext`** — `bytes`, or a ready-to-display `str`.
- **`method`** — a short display label, e.g. `"trifid"` or `"Cracked EC-DLP"`. It appears in the result chain.
- **`params`** — a dict of key parameters, shown in the chain as `method(k=v)`. Treat it as a display detail.
- **`claimed_score`** — a float in `[0, 1]`. **Be honest about it** (see below).

Two rules of thumb inside the generator:

- **Check `ctx.expired()` in your loops.** Each solver gets a per-solver time slice (default ~4s, extendable once to 2× if the global deadline has room). Stop yielding when the deadline passes.
- **Yield from a `for` loop, or `return` when there is nothing to say.** The search stops when you stop yielding or your slice ends.

A minimal skeleton:

```python
@solver("my-cipher", _my_prior)
def solve_my_cipher(data, ctx):
    text = data.decode("ascii")
    for key in candidate_keys:
        if ctx.expired():
            return
        pt = decrypt(text, key)
        if pt:
            yield pt, "my-cipher", {"key": key}, max(assess(pt)[0], flag_plausibility(pt))
```

## Scoring honestly: `ctx.assess` and `_statistical`

Core **re-assesses every candidate** with its own scoring model (`ctx.assess(pt)` returns `(score, reason)`) unless you opt out. So:

- **A verified exact recovery** — the attack math checks out, a crib decodes deterministically, an encoding round-trips — may claim high confidence. Core keeps verified recoveries in a higher trust tier and ranks them above guesses.
- **A statistical guess** — a hill-climb, a best-key-by-plaintext-model, an exhaustive-key winner — should **not** overclaim. Set `params["_statistical"] = True`. Core then trusts your `claimed_score` but caps the row's trust relative to verified ones, so a lucky wrong key cannot masquerade as a confirmed flag.

The common pattern (from `solvers_pack5.py`): score every key/period variant with the shared English model, sort, pick the decisive winner, and mark *only* that winner `_statistical` with a conservative score:

```python
if i == 0 and boost:
    params["_statistical"] = True
    yield out, "trifid", params, min(0.95, 0.55 + 0.35 * english_confidence(out))
else:
    yield out, "trifid", params, max(assess(out)[0], flag_plausibility(out))
```

Flags are never hardcoded into a solver, and every candidate is an algorithmic transform of the input — keep it that way.

## Parsing labeled values: `_vals` / `_pick`

If your solver reads labeled values (`n=…`, `c=…`, `key=…`, …), use the helpers in `solvers_more.py` instead of regexing raw text:

- **`_vals(data, ctx)`** — returns a dict of `name -> int` parsed from `name = value` / `name: value` lines in the input, merged with any `ctx.rsa_params` passed on the command line.
- **`_pick(v, *names)`** — returns the first present, truthy value among the given names.

```python
vals = _vals(data, ctx)
n = _pick(vals, "n", "modulus")
e = _pick(vals, "e", "pub")
```

These already understand the labeled-line extraction that `challenge.py` input produces, so your solver works both on raw text and on `.py` + output challenge pairs.

## Getting it registered and tested

1. Put your function in a `solvers*.py` module (e.g. `solvers_pack5.py`). `autocrypt/solvers.py` imports every pack, and worker processes import `autocrypt.solvers`, so registration is automatic.
2. Add a **regression test** in `tests/` (see [testing](testing.md)) that asserts your deterministic expected output.
3. If your solver has a deterministic expected flag, add a **row to `run_tests.sh`** — the 43-case table asserts exact recoveries.

Then run `bash run_tests.sh` and your test standalone to confirm.

## Related pages

- [How to run the test suites](testing.md) — verifying your new solver.
- [Solver families](solvers.md) — what is already implemented so you do not duplicate it.
- [How results are scored](scoring.md) — the evidence model your `claimed_score` interacts with.
- Full contract: [SOLVERS.md](../SOLVERS.md).
