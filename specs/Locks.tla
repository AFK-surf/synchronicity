---------------------------- MODULE Locks ----------------------------
(***************************************************************************)
(* Best-effort cluster lock exchange (docs/LOCKS.md §3), one lock name.    *)
(*                                                                         *)
(* A claimant takes a ticket above every ticket it has heard of, records   *)
(* its claim and sends it to every peer. A peer records the claim and      *)
(* answers with its table, its own claim marked when it holds. Once every  *)
(* peer has answered, the claimant holds iff its ticket is the least it    *)
(* knows of and no other claim it knows of is held; otherwise it ends the  *)
(* claim. Peers that never answer are given up on by a timeout.            *)
(*                                                                         *)
(* With Lossy = FALSE every claim and answer is delivered and timeouts     *)
(* never fire: this is the bounded-latency case, where a peer silent past  *)
(* the claim window is one that is not running. MutualExclusion holds.     *)
(* With Lossy = TRUE any message may be lost and any wait may time out:    *)
(* this is a partition, and TLC must report the MutualExclusion violation  *)
(* the design accepts as split brain.                                      *)
(*                                                                         *)
(* Either of two mechanisms alone keeps MutualExclusion, and removing     *)
(* both breaks it (docs/LOCKS.md §3.4): tickets ordered after every claim *)
(* heard of, and a holder marking itself held while the decision also     *)
(* counts claims that reached the claimant during its own wait.           *)
(*                                                                         *)
(* Leases are not modelled. They only end claims whose holder is gone, and *)
(* under bounded latency and bounded clock-rate drift the holder stops     *)
(* before any observer does (docs/LOCKS.md §5).                            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Nodes, MaxTicket, MaxAttempts, Lossy

ASSUME Nodes \subseteq Nat

VARIABLES
    phase,     \* node -> "idle" | "contending" | "held"
    mine,      \* node -> the claim it is contending with or holding
    table,     \* node -> claims it currently believes live
    dead,      \* node -> claims it knows were withdrawn or released
    seen,      \* node -> claims its current attempt has learned of
    awaiting,  \* node -> peers whose answer it still waits for
    clock,     \* node -> Lamport high-water mark
    attempts,  \* node -> attempts begun, to bound the model
    msgs       \* messages in flight

vars == <<phase, mine, table, dead, seen, awaiting, clock, attempts, msgs>>

NoClaim == [o |-> CHOOSE n \in Nodes : TRUE, t |-> 0]

\* A claim is identified by its ticket (t, o); a report adds held, which
\* only a holder sets, about itself, and which is not part of the identity.
Claim(o, t) == [o |-> o, t |-> t]
Id(c) == [o |-> c.o, t |-> c.t]

\* Ticket order: Lamport time, then node name (nodes are numbered).
Less(a, b) == a.t < b.t \/ (a.t = b.t /\ a.o < b.o)

MaxT(S) == IF S = {} THEN 0 ELSE CHOOSE t \in {c.t : c \in S} :
    \A c \in S : c.t <= t

Init ==
    /\ phase = [n \in Nodes |-> "idle"]
    /\ mine = [n \in Nodes |-> NoClaim]
    /\ table = [n \in Nodes |-> {}]
    /\ dead = [n \in Nodes |-> {}]
    /\ seen = [n \in Nodes |-> {}]
    /\ awaiting = [n \in Nodes |-> {}]
    /\ clock = [n \in Nodes |-> 0]
    /\ attempts = [n \in Nodes |-> 0]
    /\ msgs = {}

Send(S) == msgs' = msgs \cup S

\* Take a ticket above every ticket heard of and send the claim (§3.3 step 1).
Begin(n) ==
    LET t == 1 + IF clock[n] > MaxT(table[n]) THEN clock[n] ELSE MaxT(table[n])
        c == Claim(n, t)
    IN /\ phase[n] = "idle"
       /\ attempts[n] < MaxAttempts
       /\ t <= MaxTicket
       /\ phase' = [phase EXCEPT ![n] = "contending"]
       /\ mine' = [mine EXCEPT ![n] = c]
       /\ table' = [table EXCEPT ![n] = @ \cup {c}]
       /\ seen' = [seen EXCEPT ![n] = {}]
       /\ awaiting' = [awaiting EXCEPT ![n] = Nodes \ {n}]
       /\ clock' = [clock EXCEPT ![n] = t]
       /\ attempts' = [attempts EXCEPT ![n] = @ + 1]
       /\ Send({[type |-> "claim", from |-> n, to |-> m, c |-> c] :
                m \in Nodes \ {n}})
       /\ UNCHANGED dead

\* What a node reports: its table, its own claim marked when held.
Report(m, T) ==
    {IF c = mine[m] /\ phase[m] = "held"
        THEN [o |-> c.o, t |-> c.t, held |-> TRUE]
        ELSE [o |-> c.o, t |-> c.t, held |-> FALSE] : c \in T}

\* A peer records the claim and answers with its table.
OnClaim(msg) ==
    LET m == msg.to
        T == IF Id(msg.c) \in dead[m] THEN table[m] ELSE table[m] \cup {msg.c}
    IN /\ msg.type = "claim"
       /\ msgs' = (msgs \ {msg}) \cup
            {[type |-> "reply", from |-> m, to |-> msg.from, c |-> msg.c,
              claims |-> Report(m, T)]}
       /\ table' = [table EXCEPT ![m] = T]
       /\ clock' = [clock EXCEPT ![m] =
                        IF msg.c.t > @ THEN msg.c.t ELSE @]
       /\ UNCHANGED <<phase, mine, dead, seen, awaiting, attempts>>

\* The claimant folds in an answer to its current attempt; a stale answer
\* is dropped. Claims it knows ended, and its own earlier ones, are not live.
OnReply(msg) ==
    LET n == msg.to
        live == {c \in msg.claims : Id(c) \notin dead[n] /\
                                    (c.o # n \/ Id(c) = mine[n])}
    IN /\ msg.type = "reply"
       /\ msgs' = msgs \ {msg}
       /\ IF phase[n] = "contending" /\ msg.c = mine[n]
             THEN /\ seen' = [seen EXCEPT ![n] = @ \cup live]
                  /\ awaiting' = [awaiting EXCEPT ![n] = @ \ {msg.from}]
             ELSE UNCHANGED <<seen, awaiting>>
       /\ UNCHANGED <<phase, mine, table, dead, clock, attempts>>

OnEnd(msg) ==
    LET m == msg.to
    IN /\ msg.type = "end"
       /\ msgs' = msgs \ {msg}
       /\ dead' = [dead EXCEPT ![m] = @ \cup {Id(msg.c)}]
       /\ table' = [table EXCEPT ![m] = {c \in @ : Id(c) # Id(msg.c)}]
       /\ UNCHANGED <<phase, mine, seen, awaiting, clock, attempts>>

\* A silent peer is given up on: allowed only when messages can be lost.
Timeout(n, m) ==
    /\ Lossy
    /\ phase[n] = "contending"
    /\ m \in awaiting[n]
    /\ awaiting' = [awaiting EXCEPT ![n] = @ \ {m}]
    /\ UNCHANGED <<phase, mine, table, dead, seen, clock, attempts, msgs>>

Lose(msg) ==
    /\ Lossy
    /\ msgs' = msgs \ {msg}
    /\ UNCHANGED <<phase, mine, table, dead, seen, awaiting, clock, attempts>>

\* §3.3 step 3: hold iff least ticket among the answers and the claims that
\* reached this node meanwhile, and no other claim among them is held.
Wins(n) ==
    LET known == seen[n] \cup
                 {[o |-> x.o, t |-> x.t, held |-> FALSE] : x \in table[n]}
    IN \A c \in known : Id(c) = mine[n] \/ (Less(mine[n], c) /\ ~c.held)

End(n) ==
    /\ phase' = [phase EXCEPT ![n] = "idle"]
    /\ table' = [table EXCEPT ![n] = {c \in @ : Id(c) # mine[n]}]
    /\ dead' = [dead EXCEPT ![n] = @ \cup {mine[n]}]
    /\ Send({[type |-> "end", from |-> n, to |-> m, c |-> mine[n]] :
             m \in Nodes \ {n}})

Decide(n) ==
    /\ phase[n] = "contending"
    /\ awaiting[n] = {}
    /\ IF Wins(n)
          THEN /\ phase' = [phase EXCEPT ![n] = "held"]
               /\ UNCHANGED <<table, dead, msgs>>
          ELSE End(n)
    /\ UNCHANGED <<mine, seen, awaiting, clock, attempts>>

Release(n) ==
    /\ phase[n] = "held"
    /\ End(n)
    /\ UNCHANGED <<mine, seen, awaiting, clock, attempts>>

Next ==
    \/ \E n \in Nodes : Begin(n) \/ Decide(n) \/ Release(n)
    \/ \E n, m \in Nodes : n # m /\ Timeout(n, m)
    \/ \E msg \in msgs : OnClaim(msg) \/ OnReply(msg) \/ OnEnd(msg) \/ Lose(msg)

Spec == Init /\ [][Next]_vars

MutualExclusion == Cardinality({n \in Nodes : phase[n] = "held"}) <= 1
=============================================================================
