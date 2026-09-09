import Synchronicity.ScheduledFetchAdmission

/-! Compatibility namespace for the retry-limit bridge. The bridge now lives
in `ScheduledFetchAdmission` so `ResponseOpportunity.afterRetry` can consume it
directly in the main scheduled-liveness API. -/
namespace Synchronicity.ScheduledRetryAdmission
end Synchronicity.ScheduledRetryAdmission
