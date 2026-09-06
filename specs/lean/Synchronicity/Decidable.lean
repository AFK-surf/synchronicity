/-! Core Lean leaves `Except` without decidable equality. The program proofs
compare whole operation outcomes, traces included, with `decide`, so this
package derives it here rather than in the executable core. -/
deriving instance DecidableEq for Except
