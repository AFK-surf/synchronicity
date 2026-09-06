import VerifiedCore.Host.Generated

/-! Private versioned transport for raw host effects, not domain snapshots.
Replies must match the pending effect tag and consume the entire input; no
host continuation is accepted. The per-effect packets and decoders are
generated from the algebras (`Host/Generated.lean`); this module only steps
a program over any algebra that is on the wire. -/
namespace VerifiedCore.Host.Wire

/-- A terminal result or the pending effect's request. -/
def packet [WireEffect E] : Program E (Reply ByteArray) → ByteArray
  | .pure (.ok result) => octet 1 ++ octet 0 ++ bytes result
  | .pure (.error error) => octet 1 ++ octet 1 ++ failure error
  | .request effect _ => WireEffect.request effect

/-- Invalid host packets become a failure reply to the *pending* operation,
so its verified rollback continuation still runs. Terminal states cannot resume. -/
def resume [WireEffect E] (state : Program E (Reply ByteArray)) (input : ByteArray) :
    Program E (Reply ByteArray) :=
  match state with
  | .pure _ => .pure (.error protocolFailure)
  | .request effect next => next (WireEffect.reply effect input)

/-- Storage-only programs, the shape most CAS commands have before injection. -/
abbrev State := Program Storage (Reply ByteArray)

/-- One native continuation transport, with every capability kept as a
distinct typed algebra. Existing storage packets retain their exact bytes. -/
abbrev WriteEffects := EffectSum Construct
  (EffectSum Upsert (EffectSum Resources (EffectSum Lease (EffectSum SourceIO
    (EffectSum Digest (EffectSum ByteWrites (EffectSum Bao Sweep)))))))
abbrev NativeEffects := EffectSum Storage (EffectSum Crypto
  (EffectSum Access (EffectSum FileIO (EffectSum Clock (EffectSum Output WriteEffects)))))
abbrev NativeState := Program NativeEffects (Reply ByteArray)

@[export synch_lean_operation_packet]
def nativePacket (state : NativeState) : ByteArray := packet state

@[export synch_lean_operation_resume]
def nativeResume (state : NativeState) (input : ByteArray) : NativeState := resume state input

end VerifiedCore.Host.Wire
