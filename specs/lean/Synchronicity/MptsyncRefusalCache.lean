import Synchronicity.ScopeChangeRefinement

/-! Process-local refusal invalidation at the Rust/runtime boundary.

The verified host state contains the durable scope-change transaction, but the
Rust `Syncer` deliberately keeps structural promotion verdicts in a separate
in-memory set.  Production calls `scope_changed` only after the durable command
reports that the scope moved.  `callbackCleared` is the narrow auditable host
seam for that Rust callback; native tests exercise the same cache projection
passed to `try_promote` before and after a real `set_read_scope` change.

This module proves only cache invalidation. It assumes no promotion result,
semantic completion, or `PromotionProgress.Ready` witness. -/
namespace Synchronicity.MptsyncRefusalCache
open VerifiedCore VerifiedCore.Host VerifiedCore.Replication SimulatedHost

/-- The scope-independent key used by the production process-local cache.
Absence of scope in this key is why every verdict must be discarded when the
effective scope moves. -/
structure Verdict where
  origin : String
  seq : UInt64
  root : ByteArray
  oldRoot : ByteArray
deriving DecidableEq

/-- Logical observation of the Rust `HashSet<Verdict>`. -/
structure Cache where
  refused : List Verdict

def Cache.hits (cache : Cache) (verdict : Verdict) : Prop :=
  verdict ∈ cache.refused

def Cache.cleared (_cache : Cache) : Cache :=
  ⟨[]⟩

/-- The origin-specific tuple list passed by the Rust adapter to both Fetch
and promotion. Keeping this projection in the boundary model makes clearing
the cache observable at the verified command call. -/
def Cache.forOrigin (cache : Cache) (origin : String) :
    List (UInt64 × ByteArray × ByteArray) :=
  cache.refused.filterMap fun verdict =>
    if verdict.origin = origin then some (verdict.seq, verdict.root, verdict.oldRoot) else none

inductive CommandKind where
  | fetch
  | promote

/-- Exact process-memory snapshot supplied to one verified command call. The
kind is documentary but prevents a proof from silently treating a Fetch's
captured vector as a later promotion's freshly loaded vector. -/
structure CommandProjection (kind : CommandKind) (cache : Cache)
    (origin : Origin.Parsed)
    (actual : List (UInt64 × ByteArray × ByteArray)) : Prop where
  exact : actual = cache.forOrigin (Origin.canonical origin)

/-- Only the target origin's projection needs to remain unchanged between a
scope callback and its later fresh command. Other origins may add verdicts or
the bounded process cache may be compacted in the meantime. -/
def OriginProjectionCarry (origin : Origin.Parsed) (before after : Cache) : Prop :=
  after.forOrigin (Origin.canonical origin) = before.forOrigin (Origin.canonical origin)

/-- A changed durable scope command followed by the production runtime
callback. The durable execution is fully verified; `callbackCleared` is the
explicit seam for process memory, which is outside `SimulatedHost.State`. -/
structure ScopeResetObservation
    (spaces : Option (List String)) (now : Int64)
    (before after : SimulatedHost.State) (report : ScopeChange.ChangeReport)
    (cacheBefore cacheAfter : Cache) : Prop where
  durable : ScopeChangeRefinement.Successful spaces now before after report
  callbackCleared : cacheAfter = cacheBefore.cleared

/-- Domain refinement of the combined durable/runtime scope reset. -/
def InvalidatesOldVerdicts
    (spaces : Option (List String)) (now : Int64)
    (before after : SimulatedHost.State) (report : ScopeChange.ChangeReport)
    (cacheBefore cacheAfter : Cache) : Prop :=
  ScopeChangeRefinement.Successful spaces now before after report ∧
    ∀ verdict, cacheBefore.hits verdict → ¬cacheAfter.hits verdict

/-- The real changed scope command plus the audited runtime callback invalidates
every process-local decision made under the previous permission. -/
theorem scope_reset_invalidates_old_verdicts
    (observed : ScopeResetObservation spaces now before after report cacheBefore cacheAfter) :
    InvalidatesOldVerdicts spaces now before after report cacheBefore cacheAfter := by
  refine ⟨observed.durable, fun verdict _ oldHit => ?_⟩
  rw [observed.callbackCleared] at oldHit
  exact List.not_mem_nil oldHit

/-- In particular, retrying the identical origin/sequence/root tuple after the
scope reset cannot be suppressed by its old-scope verdict. -/
theorem same_head_misses_old_scope_verdict
    (observed : ScopeResetObservation spaces now before after report cacheBefore cacheAfter)
    (verdict : Verdict) :
    ¬cacheAfter.hits verdict := by
  intro hit
  rw [observed.callbackCleared] at hit
  exact List.not_mem_nil hit

/-- The actual argument projected for Fetch/promotion is empty after the
scope-change callback, rather than merely carrying differently tagged stale
verdicts. -/
theorem scope_reset_clears_command_projection
    (observed : ScopeResetObservation spaces now before after report cacheBefore cacheAfter)
    (origin : String) :
    cacheAfter.forOrigin origin = [] := by
  rw [observed.callbackCleared]
  rfl

theorem carried_scope_reset_projection
    (observed : ScopeResetObservation spaces now before after report cacheBefore cacheReset)
    (carry : OriginProjectionCarry origin cacheReset cacheAtCall)
    (projection : CommandProjection kind cacheAtCall origin actual) :
    actual = [] := by
  rw [projection.exact, carry]
  exact scope_reset_clears_command_projection observed (Origin.canonical origin)

end Synchronicity.MptsyncRefusalCache
