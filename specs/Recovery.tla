------------------------------ MODULE Recovery ------------------------------
(***************************************************************************)
(* Key-loss recovery (DESIGN.md §3.4), model-checked.                      *)
(*                                                                         *)
(* One origin node publishes signed heads <<seq, root>> for its own trie.  *)
(* Peers replicate them under the §5.2 acceptance rule: a head is adopted  *)
(* iff it is lexicographically greater than the slot it displaces, and     *)
(* every head a peer ever verified is retained as evidence — which is      *)
(* exactly what makes a same-seq fork *observable*.  The node can crash,   *)
(* losing its database (own head, observations, publishing floor) while    *)
(* peers keep theirs.  Recovery reads peers' unauthenticated summaries and *)
(* raises a durable floor above everything observed (§3.4 step 3), so the *)
(* node's next publish cannot collide with history its reachable peers     *)
(* hold.                                                                   *)
(*                                                                         *)
(* The theorem this spec checks is deliberately the conditional one the    *)
(* design document states.  Recovery is "not a global no-fork property":   *)
(* a peer holding newer pre-loss heads that stays partitioned through the  *)
(* whole recovery makes a fork, and the protocol only promises to surface  *)
(* it, not to prevent it.  So:                                             *)
(*                                                                         *)
(*   PARTITIONED = FALSE  models the connected cluster — every peer's      *)
(*     summary reaches the node before a post-loss publish, and the        *)
(*     quiesce reaches every peer.  NoObservableFork must HOLD.            *)
(*   PARTITIONED = TRUE   frees those two assumptions.  NoObservableFork   *)
(*     must FAIL, and the counterexample TLC prints is precisely the       *)
(*     documented fork (§3.4 "Be precise about what recovery does not      *)
(*     guarantee").  CI checks both directions: the guarantee, and that    *)
(*     the admitted limitation is still exactly where the document says.   *)
(*                                                                         *)
(* What is abstracted away, and why it is safe to: signatures (perfect —   *)
(* only this node's key signs its heads, so `published` is ground truth),  *)
(* the trie itself (a head stands for its trie; pending-head promotion is  *)
(* atomic here, its own interleavings being a separate spec's concern),    *)
(* and the quiesce timer (the adversary schedule already contains every    *)
(* "too early" interleaving a timer could produce).                        *)
(*                                                                         *)
(* Code this models:                                                       *)
(*   crates/synch-store/src/recovery.rs   observations, publish floor      *)
(*   crates/synch-engine/src/recovery.rs  detection, ensure_publishable,   *)
(*                                        recover()                        *)
(*   crates/synch-engine/src/node.rs      next_seq, publish                *)
(*   crates/synch-net/src/reconcile.rs    the §5.2 acceptance rule         *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    PEERS,        \* model values: the peers replicating this origin's trie
    ROOTS,        \* 1..n: content roots, ordered as hashes are (§4.4)
    MAX_SEQ,      \* bound on seqs the node may publish
    GAP,          \* seq_gap: how far above the observed max the floor lands
    MAX_CRASHES,  \* bound on database losses
    PARTITIONED   \* FALSE: the connected-cluster assumption (see above)

ASSUME GAP >= 1          \* recover() rejects gap = 0 outright
ASSUME MAX_SEQ >= 2
ASSUME ROOTS \subseteq Nat \ {0}

VARIABLES
    head,       \* the node's own complete head, NONE if it holds none
    floor,      \* the durable publishing floor (0 = unset)
    observed,   \* max-merged peer summary for our origin (observed_heads row)
    recovering, \* a `synch recover` quiesce is in progress
    reached,    \* peers whose summary arrived during this quiesce
    crashes,    \* how many databases this origin has lost so far
    slot,       \* [PEERS -> head-or-NONE]: each peer's current complete slot
    seen,       \* [PEERS -> set of heads]: everything a peer ever verified —
                \*   "heads verified while their signer was bound remain
                \*    provable history" (§4.4); forks are observable here
    published   \* ghost: every head this origin's keys ever signed, across
                \*   all incarnations; never read by any action

vars == <<head, floor, observed, recovering, reached, crashes,
          slot, seen, published>>

NONE == <<0, 0>>
Heads == {<<s, r>> : s \in 1..MAX_SEQ, r \in ROOTS}

(* The §4.4 order: seq first, root as tie-break — the same lexicographic   *)
(* comparison SignedHead::order_key/supersedes and the observed_heads      *)
(* ON CONFLICT clause all use.                                             *)
GT(a, b) == \/ a[1] > b[1]
            \/ (a[1] = b[1] /\ a[2] > b[2])

Max2(a, b) == IF a >= b THEN a ELSE b

(* node.rs::next_seq — one past the current head (or 1), never below the   *)
(* floor.                                                                  *)
NextSeq == Max2(IF head = NONE THEN 1 ELSE head[1] + 1, floor)

(* engine recovery.rs::recovery_state — holding a head of our own settles  *)
(* the question; otherwise a peer advertising at or above what we would    *)
(* publish means the publish would be correctly rejected.                  *)
InRecovery == head = NONE /\ observed # NONE /\ observed[1] >= NextSeq

(* The connected-cluster assumption, stated as a guard rather than left    *)
(* implicit: every peer currently holding a head has already had a summary *)
(* at least that high merged into `observed`.  In the running system this  *)
(* is what continuous Hello exchanges deliver; PARTITIONED = TRUE drops it *)
(* and with it the guarantee.                                              *)
Covered == \A p \in PEERS : slot[p] = NONE \/ ~GT(slot[p], observed)

-----------------------------------------------------------------------------

Init ==
    /\ head = NONE
    /\ floor = 0
    /\ observed = NONE
    /\ recovering = FALSE
    /\ reached = {}
    /\ crashes = 0
    /\ slot = [p \in PEERS |-> NONE]
    /\ seen = [p \in PEERS |-> {}]
    /\ published = {}

(* The node publishes a batch as one signed head (node.rs::publish).  The  *)
(* root is chosen nondeterministically: content is irrelevant, only which  *)
(* (seq, root) pairs can coexist.  ensure_publishable is the ~InRecovery   *)
(* conjunct — remove it and NoObservableFork falls over immediately, which *)
(* is a good way to convince yourself the model is load-bearing.           *)
Publish(r) ==
    /\ ~InRecovery
    /\ ~PARTITIONED => (head # NONE \/ Covered)
    /\ NextSeq <= MAX_SEQ
    /\ head' = <<NextSeq, r>>
    /\ published' = published \union {<<NextSeq, r>>}
    /\ UNCHANGED <<floor, observed, recovering, reached, crashes, slot, seen>>

(* A peer adopts the node's current head under the §5.2 rule.  Trie fetch  *)
(* and promotion are collapsed into one atomic step (see the header).      *)
AdoptFromNode(p) ==
    /\ head # NONE
    /\ GT(head, slot[p])
    /\ slot' = [slot EXCEPT ![p] = head]
    /\ seen' = [seen EXCEPT ![p] = @ \union {head}]
    /\ UNCHANGED <<head, floor, observed, recovering, reached, crashes,
                   published>>

(* Peers relay heads among themselves (reconcile.rs: heads are admitted    *)
(* from any trusted peer, judged only by signer binding and order).        *)
AdoptRelay(p, q) ==
    /\ p # q
    /\ slot[p] # NONE
    /\ GT(slot[p], slot[q])
    /\ slot' = [slot EXCEPT ![q] = slot[p]]
    /\ seen' = [seen EXCEPT ![q] = @ \union {slot[p]}]
    /\ UNCHANGED <<head, floor, observed, recovering, reached, crashes,
                   published>>

(* A Hello summary from p arrives and is max-merged, exactly the           *)
(* observed_heads ON CONFLICT clause (store recovery.rs).  Reaching a peer *)
(* that holds nothing still counts as reaching it — "no peer claims this   *)
(* origin ever published" is itself an answer.                             *)
Observe(p) ==
    /\ observed' = IF slot[p] # NONE /\ GT(slot[p], observed)
                   THEN slot[p] ELSE observed
    /\ reached' = IF recovering THEN reached \union {p} ELSE reached
    /\ UNCHANGED <<head, floor, recovering, crashes, slot, seen, published>>

(* `synch recover` begins its quiesce.  The code puts no in_recovery guard *)
(* on it — recovery is operator-driven — so neither does the model.        *)
StartRecover ==
    /\ ~recovering
    /\ recovering' = TRUE
    /\ reached' = {}
    /\ UNCHANGED <<head, floor, observed, crashes, slot, seen, published>>

(* The quiesce elapses and the floor is raised (engine recovery.rs::       *)
(* recover, store recovery.rs::raise_publish_floor).  In the connected     *)
(* model the quiesce must actually have reached every peer; PARTITIONED    *)
(* lets it end with any subset, including none — the "--wait elapsed while *)
(* the NAS was asleep" schedule.  No observation means a genuinely fresh   *)
(* node: the floor stays put and seq 1 remains correct.                    *)
FinishRecover ==
    /\ recovering
    /\ PARTITIONED \/ reached = PEERS
    /\ recovering' = FALSE
    /\ floor' = IF observed = NONE
                THEN floor
                ELSE Max2(observed[1] + GAP, NextSeq)
    /\ UNCHANGED <<head, observed, reached, crashes, slot, seen, published>>

(* Key-plus-database loss.  Everything durable on the node goes — head,    *)
(* observations, floor — while peers keep both their slots and their       *)
(* evidence.  The old key's heads remain provable history (§4.4); the new  *)
(* incarnation's heads are judged by peers under the same order rule,      *)
(* which is precisely how a same-seq fork would be caught.                 *)
Crash ==
    /\ crashes < MAX_CRASHES
    /\ head' = NONE
    /\ floor' = 0
    /\ observed' = NONE
    /\ recovering' = FALSE
    /\ reached' = {}
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<slot, seen, published>>

Next ==
    \/ \E r \in ROOTS : Publish(r)
    \/ \E p \in PEERS : AdoptFromNode(p) \/ Observe(p)
    \/ \E p, q \in PEERS : AdoptRelay(p, q)
    \/ StartRecover
    \/ FinishRecover
    \/ Crash

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK ==
    /\ head \in Heads \union {NONE}
    /\ floor \in 0..(MAX_SEQ + GAP)
    /\ observed \in Heads \union {NONE}
    /\ recovering \in BOOLEAN
    /\ reached \subseteq PEERS
    /\ crashes \in 0..MAX_CRASHES
    /\ slot \in [PEERS -> Heads \union {NONE}]
    /\ seen \in [PEERS -> SUBSET Heads]
    /\ published \subseteq Heads

(* The theorem.  No peer ever holds two verified heads at the same seq     *)
(* with different roots — across every incarnation of the origin, every    *)
(* crash, every recovery, every relay path.  This is what "peers would     *)
(* flag it as equivocation" must never have material for, in a connected   *)
(* cluster.  Note `published` is deliberately NOT constrained: heads that  *)
(* no peer ever verified can collide (the node published, synced to        *)
(* no one, crashed, republished) and the design accepts that — a fork     *)
(* nobody can observe needs no protocol answer.                            *)
NoObservableFork ==
    \A p \in PEERS :
        \A h1, h2 \in seen[p] : h1[1] = h2[1] => h1[2] = h2[2]

(* The floor never moves down within one database's lifetime — the         *)
(* raise_publish_floor contract ("lowering it could hand out a seq an      *)
(* earlier publish already used").  A crash starts a new lifetime.         *)
FloorMonotone ==
    [][crashes' = crashes => floor' >= floor]_vars

(* A peer's slot only ever advances in the §4.4 order — reconcile's        *)
(* NotNewer rejection, as an action property.                              *)
SlotMonotone ==
    [][\A p \in PEERS : slot'[p] = slot[p] \/ GT(slot'[p], slot[p])]_vars

(* The node's own head only advances within an incarnation: publish always *)
(* lands strictly above what it displaces.                                 *)
HeadMonotone ==
    [][(crashes' = crashes /\ head' # head) => GT(head', head)]_vars

=============================================================================
