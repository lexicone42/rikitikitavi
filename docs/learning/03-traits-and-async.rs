// ============================================================================
// RIKITIKITAVI LEARNING GUIDE #3: Traits & Async/Await
// ============================================================================
//
// Traits are Rust's version of interfaces. They define shared behavior
// that different types can implement. Our Scanner trait is the backbone
// of the entire project.

// ── WHAT IS A TRAIT? ──────────────────────────────────────────────────────
//
// A trait defines a set of methods that a type must implement.
// Think of it like an interface in Java/Go or a protocol in Swift.

trait Animal {
    fn name(&self) -> &str;      // Required — must implement
    fn sound(&self) -> &str;     // Required

    fn introduce(&self) -> String {  // Default implementation — optional to override
        format!("I'm {} and I say {}", self.name(), self.sound())
    }
}

struct Dog;
impl Animal for Dog {
    fn name(&self) -> &str { "Dog" }
    fn sound(&self) -> &str { "Woof" }
    // introduce() uses the default implementation
}

// ── THE SCANNER TRAIT ─────────────────────────────────────────────────────
//
// From crates/rikitikitavi-scanners/src/traits.rs:
//
// ```
// #[async_trait]
// pub trait Scanner: Send + Sync {
//     fn id(&self) -> &'static str;
//     fn name(&self) -> &'static str;
//     fn supported_perspectives(&self) -> &[Perspective];
//     async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError>;
//
//     // These have default implementations (notice the body):
//     fn estimated_duration_secs(&self) -> u64 { 30 }
//     fn requires_privileges(&self) -> bool { false }
// }
// ```
//
// Key things to notice:
//
// 1. `Scanner: Send + Sync` — This is a "supertrait bound". It means
//    any type implementing Scanner must ALSO be Send + Sync (safe to
//    share between threads). This is needed because we run scanners
//    concurrently with tokio.
//
// 2. `&'static str` — A string that lives for the entire program.
//    String literals like "network" are 'static because they're baked
//    into the binary.
//
// 3. `async fn scan(...)` — An async method. The `#[async_trait]` macro
//    is needed because Rust traits can't natively have async methods
//    that work with dynamic dispatch (Box<dyn Scanner>).

// ── IMPLEMENTING THE TRAIT ────────────────────────────────────────────────
//
// Each scanner module implements the Scanner trait:
//
// ```
// pub struct DnsScanner;  // Unit struct — no fields needed
//
// #[async_trait]
// impl Scanner for DnsScanner {
//     fn id(&self) -> &'static str { "dns" }
//     fn name(&self) -> &'static str { "DNS Security" }
//     fn supported_perspectives(&self) -> &[Perspective] {
//         &[Perspective::Unauthenticated, Perspective::Authenticated]
//     }
//     async fn scan(&self, ctx: &ScanContext) -> Result<Vec<Finding>, ScanError> {
//         // ... actual scanning logic ...
//         Ok(vec![])
//     }
// }
// ```

// ── DYNAMIC DISPATCH (dyn Trait) ──────────────────────────────────────────
//
// The ScannerRegistry stores scanners as `Box<dyn Scanner>`:
//
// ```
// pub struct ScannerRegistry {
//     scanners: Vec<Box<dyn Scanner>>,
//     //              ^^^^^^^^^^^
//     //              "Any type that implements Scanner"
// }
// ```
//
// `Box<dyn Scanner>` is a "trait object" — it erases the concrete type
// and stores just a pointer + a vtable (like a virtual method table in C++).
//
// This lets us put different scanner types in the same Vec:
//   scanners: vec![
//       Box::new(DnsScanner),       // Box<DnsScanner> → Box<dyn Scanner>
//       Box::new(PortScanner),      // Box<PortScanner> → Box<dyn Scanner>
//       Box::new(WifiScanner),      // different types, same trait!
//   ]

// ── ASYNC/AWAIT BASICS ────────────────────────────────────────────────────
//
// Rust's async/await lets you write concurrent code that looks sequential.
// Under the hood, async functions are compiled into state machines.
//
// Key concepts:
//
// 1. `async fn` returns a Future (a value that will complete later)
// 2. `.await` pauses the current task until the Future completes
// 3. An async runtime (tokio) actually runs the Futures

async fn fetch_data() -> String {
    // This doesn't block the thread — it yields to the runtime
    // which can run other tasks while waiting.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    "data".to_string()
}

// #[tokio::main] converts main() into an async runtime entry point.
// Without it, you can't use .await in main.
#[tokio::main]
async fn main() {
    let data = fetch_data().await;
    println!("Got: {data}");
    println!("Read the comments above to learn about traits and async!");
}
