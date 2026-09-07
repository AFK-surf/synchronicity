# Formal checks

The canonical [Rust/Lean architecture and proof contract](../docs/RUST-LEAN-PROOFS.md)
contains the user-facing goals, evidence scopes, recovery-model limitations and
migration/proof plan. Lean checks executable core properties; TLC checks bounded
recovery schedules; native tests check host integration.

## Lean

```sh
cd specs/lean
lake build --wfail
```

See the [proof package README](lean/README.md) for prerequisites and the
[bounded standalone kernel check](../docs/RUST-LEAN-PROOFS.md#validation-and-completion-gates).

## Recovery model

TLC requires JRE 11+ and [tla2tools.jar](https://github.com/tlaplus/tlaplus/releases).
CI pins v1.7.4 by checksum. From the repository root:

```sh
java -jar tla2tools.jar -config specs/RecoveryCI.cfg -workers auto -deadlock specs/Recovery.tla
```

`-deadlock` disables deadlock reporting because bounded terminal states are
intentional. `Recovery.cfg` runs the larger local bounds. Run it after changing
recovery behavior. `RecoveryPartitioned.cfg` must report the documented
`NoObservableFork` violation; CI expects that counterexample. The model does not
establish eventual consistency of the actual mptsync implementation.
