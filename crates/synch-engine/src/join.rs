//! Running several futures to completion together.

use std::future::Future;

/// Runs several futures to completion together, collecting their outputs.
///
/// A hand-rolled join rather than a `futures` dependency: what the engine needs
/// is the simplest possible shape — no cancellation, no early return, every
/// branch polled to the end — and that is a dozen lines. The outputs come back
/// in completion order, which is all any caller here asks of them.
pub(crate) async fn futures_join<F: Future>(
    futures: impl IntoIterator<Item = F>,
) -> Vec<F::Output> {
    let mut pending: Vec<std::pin::Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut out = Vec::with_capacity(pending.len());
    std::future::poll_fn(move |cx| {
        let mut index = 0;
        while index < pending.len() {
            match pending[index].as_mut().poll(cx) {
                std::task::Poll::Ready(value) => {
                    out.push(value);
                    pending.remove(index);
                }
                std::task::Poll::Pending => index += 1,
            }
        }
        if pending.is_empty() {
            std::task::Poll::Ready(std::mem::take(&mut out))
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}
