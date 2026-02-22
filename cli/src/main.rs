#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

/// COVERAGE: Thin entry point; all logic lives in `rose::cli`.
#[cfg_attr(coverage_nightly, coverage(off))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rose::cli::run().await
}
