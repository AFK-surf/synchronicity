import Synchronicity.Anchors

/-!
`lake exe anchors`: print every `(anchor, declaration)` pair the `rust_impl`
attribute recorded across the `Synchronicity` library, one per line, sorted.
`check-anchors.sh` compares the output with the `LEAN-MODEL` comments in the
Rust sources.
-/

open Lean

def main : IO UInt32 := do
  initSearchPath (← findSysroot)
  let env ← importModules #[{ module := `Synchronicity }] {} (trustLevel := 0)
  let strip (n : Name) : String :=
    let s := n.toString
    if s.startsWith "Synchronicity." then (s.drop "Synchronicity.".length).toString else s
  let pairs := (Synchronicity.Anchors.anchors env).map fun (a, d) => (a, strip d)
  let sorted := pairs.qsort fun a b => a.1 < b.1 || (a.1 == b.1 && a.2 < b.2)
  for (anchor, decl) in sorted do
    IO.println s!"{anchor} {decl}"
  return 0
