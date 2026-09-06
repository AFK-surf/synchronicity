import VerifiedCore.Host

/-! Raw conflict expressions. These describe one atomic database statement,
not application metadata or domain-specific conflict decisions. -/
namespace VerifiedCore.Host

/-- Column references are validated identifiers, never interpolated SQL.
`coalesce` and `max` use the backing database's raw cell/null semantics. -/
inductive ConflictValue where
  | current (column : String)
  | excluded (column : String)
  | coalesce (left right : ConflictValue)
  | max (left right : ConflictValue)
  deriving BEq, DecidableEq

/-- INSERT with a targeted ON CONFLICT DO UPDATE. Expressions are evaluated
in the same statement against the conflicting row, not host-prepared snapshots.
Empty assignments mean DO NOTHING; each assignment names one target column. -/
inductive Upsert : Type → Type where
  | write (tx : Transaction) (relation : String) (values : Fields)
      (conflicts : List String) (assignments : List (String × ConflictValue)) : Upsert (Reply Unit)

end VerifiedCore.Host
