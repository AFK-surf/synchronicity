import Lake

open Lake DSL

package synchronicity_specs where
  version := v!"0.1.0"

@[default_target]
lean_lib Synchronicity where
  srcDir := "."
