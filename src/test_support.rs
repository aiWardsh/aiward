use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    path::PathBuf,
    sync::{Mutex, MutexGuard, OnceLock},
};

pub struct TestEnvironment {
    _guard: MutexGuard<'static, ()>,
    original_cwd: PathBuf,
    original_env: BTreeMap<OsString, OsString>,
}

impl TestEnvironment {
    pub fn lock() -> Self {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let guard = LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self {
            _guard: guard,
            original_cwd: env::current_dir().expect("test current directory should be readable"),
            original_env: env::vars_os().collect(),
        }
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        let current_keys = env::vars_os().map(|(key, _)| key).collect::<Vec<_>>();
        for key in current_keys {
            if !self.original_env.contains_key(&key) {
                env::remove_var(key);
            }
        }
        for (key, value) in &self.original_env {
            env::set_var(key, value);
        }
        let _ = env::set_current_dir(&self.original_cwd);
    }
}
