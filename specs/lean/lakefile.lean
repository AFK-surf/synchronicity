import Lake

open Lake DSL

package synchronicity_specs where
  version := v!"0.1.0"
  weakLeanArgs := #["-j1", "-M4096"]

require synch_verified from "../../crates/synch-verified/lean"

/-- Proofs about the executable Lean core: the same source Cargo compiles
and links, checked here with warnings as errors. -/
@[default_target]
lean_lib Synchronicity where
  srcDir := "."
