use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::LitVmError;
use crate::network::{LitVmSettingsFile, SETTINGS_FILE};

static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(1);

pub fn load_settings_file(data_dir: &Path) -> Result<LitVmSettingsFile, LitVmError> {
    let path = data_dir.join(SETTINGS_FILE);
    if !path.exists() {
        return Ok(LitVmSettingsFile::default());
    }
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw).map_err(|e| LitVmError::Settings(e.to_string()))
}

pub fn save_settings_file(data_dir: &Path, file: &LitVmSettingsFile) -> Result<(), LitVmError> {
    fs::create_dir_all(data_dir)?;
    let path = data_dir.join(SETTINGS_FILE);
    let raw =
        serde_json::to_string_pretty(file).map_err(|e| LitVmError::Settings(e.to_string()))?;
    let seq = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
    let tmp = data_dir.join(format!("{SETTINGS_FILE}.tmp.{}.{seq}", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    let write_res = (|| -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(raw.as_bytes())?;
        f.sync_all()?;
        Ok(())
    })();
    drop(f);
    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

pub fn wipe_settings_file(data_dir: &Path) -> Result<(), LitVmError> {
    let path = data_dir.join(SETTINGS_FILE);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
