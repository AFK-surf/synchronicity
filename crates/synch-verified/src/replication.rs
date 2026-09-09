//! Whole metadata exchange planning, executed by the mandatory Lean core.
use crate::operation::{self, terminal, Command};

pub use crate::generated::{
    Advertised, ContactPlan, ExchangePlan, Item as OriginItem, Plan as OriginPlan,
};
pub use crate::operation::OperationError;

/// Select servable heads to push and origins to request. Summary order,
/// duplicates and the choice of complete/pending slot do not affect requests.
/// Every root must contain exactly 32 bytes; no host effects are permitted.
pub fn plan_exchange(
    ours: Vec<Advertised>,
    theirs: Vec<Advertised>,
    servable: Vec<Advertised>,
) -> Result<ExchangePlan, OperationError<std::convert::Infallible>> {
    let bytes = operation::run_pure(&Command::PlanExchange {
        ours,
        theirs,
        servable,
    })?;
    terminal(&bytes).map_err(|()| OperationError::Protocol)
}

/// Select at most `maximum` distinct eligible peers after the completed cursor.
/// Commit the returned cursor only after attempting every selected peer.
/// Peer identifiers and the optional cursor must contain exactly 32 bytes;
/// `maximum` must be between 1 and 256. The command has no host effects.
pub fn plan_contact(
    peers: Vec<Vec<u8>>,
    cursor: Option<Vec<u8>>,
    maximum: u64,
) -> Result<ContactPlan, OperationError<std::convert::Infallible>> {
    let bytes = operation::run_pure(&Command::PlanContact {
        peers,
        cursor,
        maximum,
    })?;
    terminal(&bytes).map_err(|()| OperationError::Protocol)
}

/// Select whole origin groups after the completed cursor without exceeding
/// the record/work budget. Callers commit the cursor only after attempting the
/// selected batch.
pub fn plan_origins(
    items: Vec<OriginItem>,
    cursor: Option<String>,
    maximum: u64,
) -> Result<OriginPlan, OperationError<std::convert::Infallible>> {
    let bytes = operation::run_pure(&Command::PlanOrigins {
        items,
        cursor,
        maximum,
    })?;
    terminal(&bytes).map_err(|()| OperationError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selected(peers: &[Vec<u8>], plan: &ContactPlan) -> Vec<Vec<u8>> {
        plan.positions
            .iter()
            .map(|position| peers[*position as usize].clone())
            .collect()
    }

    #[test]
    fn completed_contact_rounds_reach_every_eligible_peer() {
        for count in [1usize, 2, 3, 4, 7, 32, 100] {
            let mut peers: Vec<_> = (1..=count).rev().map(|i| vec![i as u8; 32]).collect();
            let mut cursor = None;
            let mut reached = std::collections::HashSet::new();
            for round in 0..count.div_ceil(3) {
                let length = peers.len();
                peers.rotate_left(round % length);
                let plan = plan_contact(peers.clone(), cursor, 3).unwrap();
                let batch = selected(&peers, &plan);
                assert_eq!(batch.len(), count.min(3));
                assert_eq!(
                    batch.iter().collect::<std::collections::HashSet<_>>().len(),
                    batch.len()
                );
                reached.extend(batch);
                cursor = plan.cursor;
            }
            assert_eq!(reached.len(), count);
        }
    }

    #[test]
    fn contact_turns_survive_duplicates_and_removal_of_the_cursor_peer() {
        let peers = vec![vec![9; 32], vec![1; 32], vec![5; 32], vec![1; 32]];
        let plan = plan_contact(peers.clone(), Some(vec![3; 32]), 3).unwrap();
        assert_eq!(
            selected(&peers, &plan),
            vec![vec![5; 32], vec![9; 32], vec![1; 32]]
        );
        assert_eq!(plan.cursor, Some(vec![1; 32]));
        let empty = plan_contact(vec![], plan.cursor.clone(), 3).unwrap();
        assert!(empty.positions.is_empty());
        assert_eq!(empty.cursor, plan.cursor);
        let zero = plan_contact(vec![vec![0; 32]], None, 3).unwrap();
        assert_eq!(zero.positions, [0]);
        assert_eq!(zero.cursor, Some(vec![0; 32]));
    }

    #[test]
    fn malformed_contact_plans_are_rejected_at_the_native_boundary() {
        assert!(plan_contact(vec![vec![0; 31]], None, 3).is_err());
        assert!(plan_contact(vec![], Some(vec![0; 33]), 3).is_err());
        assert!(plan_contact(vec![], None, 0).is_err());
        assert!(plan_contact(vec![], None, 257).is_err());
    }

    fn head(origin: &str, seq: u64, root: [u8; 32]) -> Advertised {
        Advertised {
            origin: origin.into(),
            seq,
            root: root.to_vec(),
        }
    }

    #[test]
    fn native_exchange_preserves_unsigned_versions_and_servable_positions() {
        // ExchangeProofs and ExchangeVersionProofs cover the ordering laws.
        // These vectors exercise the native integer and byte-array boundary.
        let mut last_byte = [0; 32];
        last_byte[31] = 255;
        let mut first_byte = [0; 32];
        first_byte[0] = 1;
        for (low, high) in [
            ((i64::MAX as u64, [255; 32]), (1 << 63, [0; 32])),
            ((u64::MAX, [0; 32]), (u64::MAX, last_byte)),
            ((1, last_byte), (1, first_byte)),
        ] {
            let low = head("origin", low.0, low.1);
            let high = head("origin", high.0, high.1);
            let plan = plan_exchange(vec![low.clone()], vec![high.clone()], vec![]).unwrap();
            assert_eq!(plan.want, ["origin"]);
            assert!(plan.push.is_empty());
            // A pending higher head is not a servable entry. Check the
            // actual returned index after a lower, ineligible entry.
            let pending = head("origin", high.seq, [255; 32]);
            let plan = plan_exchange(vec![pending], vec![low.clone()], vec![low, high]).unwrap();
            assert_eq!(plan.push, [1]);
            assert!(plan.want.is_empty());
        }
    }

    #[test]
    fn malformed_hash_width_is_rejected_in_every_input() {
        for width in [0, 31, 33] {
            let malformed = Advertised {
                origin: "origin".into(),
                seq: 1,
                root: vec![0; width],
            };
            for (ours, theirs, servable) in [
                (vec![malformed.clone()], vec![], vec![]),
                (vec![], vec![malformed.clone()], vec![]),
                (vec![], vec![], vec![malformed]),
            ] {
                assert!(matches!(
                    plan_exchange(ours, theirs, servable),
                    Err(OperationError::Protocol)
                ));
            }
        }
    }
}
