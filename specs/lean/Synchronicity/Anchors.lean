import Lean

/-!
The Rust/Lean anchor attribute.

Every declaration that models a Rust linearization point carries
`@[rust_impl "anchor-name"]`.  The attribute is parametric, so the anchor is
stored in the environment against the declaration it sits on: renaming or
deleting the declaration moves or removes the anchor with it.  `lake exe
anchors` dumps every `(anchor, declaration)` pair, and `check-anchors.sh`
compares that against the `LEAN-MODEL: anchor (declaration)` comments in the
Rust sources, so the review anchors stay bidirectional in both name and target.
-/

namespace Synchronicity.Anchors

open Lean

syntax (name := rust_impl) "rust_impl " str+ : attr

initialize rustImplAttr : ParametricAttribute (Array String) ←
  registerParametricAttribute {
    name := `rust_impl
    descr := "the Rust linearization points this declaration models"
    getParam := fun _ stx =>
      match stx with
      | `(attr| rust_impl $anchors:str*) => pure (anchors.map (·.getString))
      | _ => throwError "rust_impl: expected one or more string literals"
  }

/-- Every `(anchor, declaration)` pair recorded in `env`, imported modules
included. -/
def anchors (env : Environment) : Array (String × Name) := Id.run do
  let mut out := #[]
  for i in [:env.header.moduleNames.size] do
    for (decl, names) in rustImplAttr.ext.getModuleEntries env i do
      for a in names do
        out := out.push (a, decl)
  for (decl, names) in (rustImplAttr.ext.getState env).2.toList do
    for a in names do
      out := out.push (a, decl)
  return out

end Synchronicity.Anchors
