//// Who a request is, once its credential has been checked.
////
//// Three credentials reach the product API and they are not the same kind of
//// thing. A **session cookie** is a person: their reach is every org they
//// are a member of, and their role in each is read from `org_members` at the
//// moment they ask. An **API key** is a credential an org holds: it names one
//// org and carries its own role, so it can never reach past the org it was
//// minted in, and never past the role it was minted with. A **join key** is
//// narrower than a role can express: one network, one operation.
////
//// Keeping both in one type is what lets a handler be written once. What it
//// must not do is let the difference blur, so the two facts a handler wants
//// are named apart: `user_id` is who a written row is *attributed* to, and
//// `actor` is who *made* the request. For a person they are the same string.
//// For a key they are not, and the audit trail wants the second.

pub type Principal {
  Principal(
    /// The user the rows this request writes are attributed to — the
    /// signed-in person, or, for a key, the person who minted it. It is
    /// what the `created_by` columns take (they reference `users`, and a
    /// key is not one) and it is read for nothing else: authorisation never
    /// consults it for a key, and neither does the audit trail.
    user_id: String,
    credential: Credential,
  )
}

pub type Credential {
  /// The dashboard: a signed session cookie, plus the per-session secret
  /// the SPA echoes in `x-csrf` on every mutation.
  Cookie(csrf: String)
  /// An org-scoped API key, presented as a bearer token. It carries the org
  /// and role from its own row — never from `org_members`, which a key has
  /// no place in.
  ApiKey(key_id: String, org_id: String, role: String)
  /// A **join key**: scoped to one network, and able to do exactly one thing
  /// — put a device into it.
  ///
  /// It carries no role, because there is no rank at which "may add a member
  /// to this network, and nothing else" sits. That is why it is a separate
  /// constructor rather than a third role string: `api/common.check_org`
  /// refuses this variant outright, so every org-scoped route in the service
  /// is closed to it by construction, and the one endpoint that admits it
  /// checks the network itself.
  JoinKey(key_id: String, org_id: String, network_id: String)
}

/// What the audit trail records as the actor.
///
/// A key names itself rather than the person who minted it: the minter may
/// have changed role or left the org entirely, and the honest answer to "who
/// did this" is the credential that was presented. The `key:` prefix cannot
/// collide with a user id — those are hex from `util/id`.
pub fn actor(who: Principal) -> String {
  case who.credential {
    Cookie(_) -> who.user_id
    ApiKey(key_id, _, _) | JoinKey(key_id, _, _) -> "key:" <> key_id
  }
}
