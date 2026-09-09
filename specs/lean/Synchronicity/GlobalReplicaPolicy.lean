import Synchronicity.MaterializationInputs

/-! Device-wide replica policy at one raw database observation.

`Materialize.prepare` reads an origin-specific scope, but every successful call
decodes replica targets from the same release-floor setting and `replicas`
table.  The Rust/SQLite boundary currently supplies uniqueness of that decoder;
the existential read prevents the contract from being satisfied vacuously.
-/
namespace Synchronicity.GlobalReplicaPolicy
open VerifiedCore VerifiedCore.Replication SimulatedHost

structure Holds (db : Database) (replicas : List Materialize.Target) : Prop where
  readable : ∃ origin scope, MaterializationInputs.ReadPolicy db origin scope replicas
  unique : ∀ origin scope actual,
    MaterializationInputs.ReadPolicy db origin scope actual → actual = replicas

end Synchronicity.GlobalReplicaPolicy
