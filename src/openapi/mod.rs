//! OpenAPI 3.x / Swagger 2.0 support: loading, normalization, example
//! generation, schema conversion, and collection import.

pub mod import;
pub mod model;
pub mod schema;

pub use import::{ImportOptions, ImportSummary, import};
pub use model::{Api, Spec, normalize};
