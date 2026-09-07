//! Whole metadata exchange planning, executed by the mandatory Lean core.
use crate::operation::{self, terminal, Command};

pub use crate::generated::{Advertised, ExchangePlan};
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
