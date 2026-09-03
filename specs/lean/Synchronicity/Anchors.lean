import Lean
import Batteries.Tactic.Lint

/-!
The Rust/Lean anchor attributes.

A declaration that *models* a Rust linearization point — a transition, a
predicate, a walk — carries `@[rust_impl "anchor-name"]`.  A theorem that
*justifies* a Rust site — the reason a memo may be written, a check may be
skipped, a pairing may be trusted — carries `@[rust_justifies "anchor-name"]`.
Both are parametric, so the anchor is stored in the environment against the
declaration it sits on: renaming or deleting the declaration moves or removes
the anchor with it.  `lake exe anchors` dumps every `(anchor, declaration)`
pair from both, and `check-anchors.sh` compares that against the
`LEAN-MODEL: anchor (declaration)` comments in the Rust sources, so the review
anchors stay bidirectional in both name and target.
-/

/-- The simp set that opens transition definitions down to their guards and
successors; every transition definition in the package is tagged
`@[transition]`, so a preservation proof opens them all at once.  Registered
here because a simp attribute is usable only by modules importing the one that
declares it. -/
register_simp_attr transition

namespace Synchronicity.Anchors

open Lean

/-- `@[rust_impl "anchor" …]`: the Rust linearization points a definition
models. -/
syntax (name := rust_impl) "rust_impl " str+ : attr

/-- `@[rust_justifies "anchor" …]`: the Rust sites a theorem is the argument
for. -/
syntax (name := rust_justifies) "rust_justifies " str+ : attr

/-- The `rust_impl` registry: each tagged declaration with its anchors. -/
initialize rustImplAttr : ParametricAttribute (Array String) ←
  registerParametricAttribute {
    name := `rust_impl
    descr := "the Rust linearization points this definition models"
    getParam := fun _ stx =>
      match stx with
      | `(attr| rust_impl $anchors:str*) => pure (anchors.map (·.getString))
      | _ => throwError "rust_impl: expected one or more string literals"
  }

/-- The `rust_justifies` registry: each tagged theorem with its anchors. -/
initialize rustJustifiesAttr : ParametricAttribute (Array String) ←
  registerParametricAttribute {
    name := `rust_justifies
    descr := "the Rust sites this theorem justifies"
    getParam := fun _ stx =>
      match stx with
      | `(attr| rust_justifies $anchors:str*) => pure (anchors.map (·.getString))
      | _ => throwError "rust_justifies: expected one or more string literals"
  }

/-- Every `(anchor, declaration)` pair one attribute recorded in `env`,
imported modules included. -/
def anchorsOf (attr : ParametricAttribute (Array String)) (env : Environment) :
    Array (String × Name) := Id.run do
  let mut out := #[]
  for i in [:env.header.moduleNames.size] do
    for (decl, names) in attr.ext.getModuleEntries env i do
      for a in names do
        out := out.push (a, decl)
  for (decl, names) in (attr.ext.getState env).2.toList do
    for a in names do
      out := out.push (a, decl)
  return out

/-- Every `(anchor, declaration)` pair either attribute recorded in `env`. -/
def anchors (env : Environment) : Array (String × Name) :=
  anchorsOf rustImplAttr env ++ anchorsOf rustJustifiesAttr env

end Synchronicity.Anchors

#lint
