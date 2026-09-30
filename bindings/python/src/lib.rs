//! Placeholder while the packaging is proven; replaced by the binding itself.

use pyo3::prelude::*;

#[pymodule]
fn swp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("VERSION", swp_sdk::VERSION)?;
    Ok(())
}
