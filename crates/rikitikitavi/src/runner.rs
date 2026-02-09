use anyhow::Result;
use rikitikitavi_analysis::{calculate_risk_score, generate_attack_paths};
use rikitikitavi_models::{ScanContext, ScanResults};
use rikitikitavi_scanners::ScannerRegistry;
use std::time::Instant;

/// Orchestrate a full scan run across all applicable scanner modules.
pub async fn run_scan(ctx: &ScanContext) -> Result<ScanResults> {
    let start = Instant::now();
    let registry = ScannerRegistry::new();

    let scanners = if let Some(modules) = &ctx.config.modules {
        // Only run specified modules
        modules
            .iter()
            .filter_map(|id| registry.get(id))
            .collect::<Vec<_>>()
    } else {
        // Run all scanners for this perspective
        registry.for_perspective(ctx.perspective)
    };

    tracing::info!(
        perspective = %ctx.perspective,
        scanner_count = scanners.len(),
        "starting scan"
    );

    let mut all_findings = Vec::new();

    for scanner in &scanners {
        tracing::info!(
            scanner = scanner.id(),
            name = scanner.name(),
            "running scanner"
        );

        match scanner.scan(ctx).await {
            Ok(findings) => {
                tracing::info!(
                    scanner = scanner.id(),
                    findings_count = findings.len(),
                    "scanner completed"
                );
                all_findings.extend(findings);
            }
            Err(e) => {
                tracing::warn!(
                    scanner = scanner.id(),
                    error = %e,
                    "scanner failed, continuing"
                );
            }
        }
    }

    // Generate attack paths if requested
    let attack_paths = if ctx.config.attack_paths {
        generate_attack_paths(&all_findings)
    } else {
        Vec::new()
    };

    let risk_score = calculate_risk_score(&all_findings);
    let duration = start.elapsed().as_secs();

    tracing::info!(
        total_findings = all_findings.len(),
        attack_paths = attack_paths.len(),
        risk_score,
        duration_secs = duration,
        "scan complete"
    );

    Ok(ScanResults {
        findings: all_findings,
        devices: Vec::new(), // TODO: Collect devices from network scanner
        attack_paths,
        risk_score,
        scan_duration_secs: duration,
    })
}
