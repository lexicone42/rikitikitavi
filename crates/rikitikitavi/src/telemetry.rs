//! Logging setup and optional OTLP trace export.
//!
//! Spans: `scan` (root), `discovery`, and one `scanner` per scanner run. With the
//! `otel` feature and `OTEL_EXPORTER_OTLP_ENDPOINT` set, spans are also exported
//! over OTLP/HTTP; without both, nothing leaves the host.

use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::cli::LogFormat;

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

/// Install the global subscriber. `RUST_LOG` overrides `level`.
pub fn init(level: &str, format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_span_events(FmtSpan::CLOSE);
    #[cfg_attr(not(feature = "otel"), allow(unused_mut))]
    let mut layers: Vec<BoxedLayer> = vec![match format {
        LogFormat::Text => fmt_layer.with_filter(filter).boxed(),
        LogFormat::Json => fmt_layer.json().with_filter(filter).boxed(),
    }];
    #[cfg(feature = "otel")]
    if let Some(layer) = otel::layer() {
        layers.push(layer);
    }
    tracing_subscriber::registry().with(layers).init();
}

/// Flush pending spans. Call before the process exits.
#[cfg_attr(not(feature = "otel"), allow(clippy::missing_const_for_fn))]
pub fn shutdown() {
    #[cfg(feature = "otel")]
    otel::shutdown();
}

#[cfg(feature = "otel")]
mod otel {
    use std::sync::OnceLock;

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::filter::Targets;

    use super::BoxedLayer;

    static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

    /// `None` unless `OTEL_EXPORTER_OTLP_ENDPOINT` (or the traces-specific variant) is set.
    pub fn layer() -> Option<BoxedLayer> {
        let configured = [
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        ]
        .iter()
        .any(|var| std::env::var_os(var).is_some_and(|v| !v.is_empty()));
        if !configured {
            return None;
        }
        let exporter = match opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
        {
            Ok(exporter) => exporter,
            Err(e) => {
                eprintln!("Warning: OTLP exporter not started: {e}");
                return None;
            }
        };
        let resource = Resource::builder()
            .with_service_name("rikitikitavi")
            .with_attribute(opentelemetry::KeyValue::new(
                "service.version",
                env!("CARGO_PKG_VERSION"),
            ))
            .build();
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(resource)
            .build();
        let tracer = provider.tracer("rikitikitavi");
        let _ = PROVIDER.set(provider);
        // Independent of the console log level; this workspace's spans only.
        let ours = Targets::new().with_target("rikitikitavi", tracing::Level::INFO);
        Some(
            tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_filter(ours)
                .boxed(),
        )
    }

    pub fn shutdown() {
        if let Some(provider) = PROVIDER.get() {
            let _ = provider.shutdown();
        }
    }
}
