//! Scaffold probe for the Node binding: settles the three napi-rs mechanics the
//! real surface (task #82) is built on, and nothing else.
//!
//! 1. A `#[napi]` function whose failure carries a **JavaScript-defined error
//!    object** — the loader installs an `SwpError` constructor via
//!    [`install_error_factory`], and every boundary failure is built by calling
//!    it on the JS thread. The `Result`-carrying error becomes the thrown value
//!    verbatim (verified at probe time), so no re-wrap layer exists in JS.
//! 2. An async operation that settles its promise exactly once from a worker
//!    thread, rejecting with the same factory-built object.
//! 3. A Rust panic contained by `catch_unwind` inside the worker and surfaced
//!    as `INTERNAL_ERROR` rather than an unwind into the host.

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// The six positions the [docs/SDK_API.md] §8 envelope hands the JS constructor:
/// code, message, path, causedBy, nextStep, rendered.
type FactoryArgs = (String, String, Option<String>, Option<String>, String, String);

thread_local! {
    static ERROR_FACTORY: RefCell<Option<FunctionRef<FnArgs<FactoryArgs>, Unknown<'static>>>> =
        const { RefCell::new(None) };
}

/// Lets the JS loader hand the addon its `SwpError` constructor.
#[napi(ts_args_type = "ctor: new (code: string, message: string, path: string | null, causedBy: string | null, nextStep: string, rendered: string) => Error")]
pub fn install_error_factory(factory: Function<'_, FnArgs<FactoryArgs>, Unknown<'static>>) -> Result<()> {
    let reference = factory.create_ref()?;
    ERROR_FACTORY.with(|cell| {
        *cell.borrow_mut() = Some(reference);
    });
    Ok(())
}

fn build_boundary_error<'e>(
    env: &'e Env,
    code: &str,
    message: &str,
    path: Option<&str>,
    caused_by: Option<&str>,
    next_step: &str,
    rendered: &str,
) -> Result<Unknown<'e>> {
    ERROR_FACTORY.with(|cell| {
        let borrow = cell.borrow();
        let factory = borrow.as_ref().ok_or_else(|| {
            Error::from_reason("the JS loader never installed the SwpError constructor")
        })?;
        let ctor = factory.borrow_back(env)?;
        ctor.new_instance(FnArgs {
            data: (
                code.to_owned(),
                message.to_owned(),
                path.map(str::to_owned),
                caused_by.map(str::to_owned),
                next_step.to_owned(),
                rendered.to_owned(),
            ),
        })
    })
}

/// The build this binding drives, in the words a report's `generator` uses.
#[napi]
pub fn banner() -> String {
    swp_sdk::banner()
}

/// Probe: a synchronous failure arrives as the factory's object, not a
/// napi-synthesized `Error`.
#[napi]
pub fn probe_throw(env: Env, code: String) -> Result<String> {
    let value = build_boundary_error(
        &env,
        &code,
        &format!("the probe {code} failed"),
        Some("some/relative/path"),
        None,
        "run the other thing",
        "USAGE: the probe USAGE failed\n  ...rendered...",
    )?;
    Err(Error::from_unknown_without_coercion(value))
}

/// The `Send` half of a probe failure: plain data carried out of the worker so
/// the JS object is built on the JS thread, after the work settles.
pub struct FailureData {
    code: String,
    message: String,
}

pub enum ProbeOutcome {
    Done(String),
    Failed(FailureData),
    Panicked,
}

/// Probe: an async worker that settles once and rejects with the factory's object.
pub struct ProbeTask {
    mode: String,
}

impl Task for ProbeTask {
    type Output = ProbeOutcome;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        std::thread::sleep(Duration::from_millis(20));
        match self.mode.as_str() {
            "ok" => Ok(ProbeOutcome::Done("settled".to_owned())),
            "fail" => Ok(ProbeOutcome::Failed(FailureData {
                code: "NOT_PROTECTED".to_owned(),
                message: "this project has no releases".to_owned(),
            })),
            "panic" => {
                let caught = catch_unwind(AssertUnwindSafe(|| {
                    panic!("the probe panic");
                }));
                match caught {
                    Err(_) => Ok(ProbeOutcome::Panicked),
                    Ok(()) => Ok(ProbeOutcome::Done("no panic happened".to_owned())),
                }
            }
            other => Ok(ProbeOutcome::Failed(FailureData {
                code: "USAGE".to_owned(),
                message: format!("unknown probe mode {other:?}"),
            })),
        }
    }

    fn resolve(&mut self, env: Env, outcome: Self::Output) -> Result<Self::JsValue> {
        match outcome {
            ProbeOutcome::Done(text) => Ok(text),
            ProbeOutcome::Failed(failure) => {
                let value = build_boundary_error(
                    &env,
                    &failure.code,
                    &failure.message,
                    None,
                    None,
                    "`swp protect` this project first",
                    "NOT_PROTECTED: ...\n",
                )?;
                Err(Error::from_unknown_without_coercion(value))
            }
            ProbeOutcome::Panicked => {
                let value = build_boundary_error(
                    &env,
                    "INTERNAL_ERROR",
                    "SWP-1 panicked across the Node boundary: the probe panic",
                    None,
                    Some("the probe panic"),
                    "report this: https://github.com/theaaqibjavaid/SWP-1/issues",
                    "INTERNAL_ERROR: ...\n",
                )?;
                Err(Error::from_unknown_without_coercion(value))
            }
        }
    }
}

#[napi]
pub fn probe_async(mode: String) -> AsyncTask<ProbeTask> {
    AsyncTask::new(ProbeTask { mode })
}
