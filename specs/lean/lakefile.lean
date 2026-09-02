import Lake

open Lake DSL

package synchronicity_specs where
  version := v!"0.1.0"

@[default_target]
lean_lib Synchronicity where
  srcDir := "."

/-- Dumps every `(anchor, declaration)` pair the `rust_impl` attribute
recorded; `check-anchors.sh` diffs it against the Rust sources. -/
lean_exe anchors where
  root := `AnchorsDump
  supportInterpreter := true
