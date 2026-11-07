// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Versioned wire conversions. Domain crates must not depend on this crate.
mod legacy_v1;
pub use legacy_v1::*;
