//! Native paths, keystore, unlock, agent, packaging, and update adapters.

#![forbid(unsafe_code)]

use std::{fs, path::PathBuf};

use directories::ProjectDirs;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformPaths {
    pub data_dir: PathBuf,
    pub database: PathBuf,
}

impl PlatformPaths {
    pub fn discover() -> Result<Self, PlatformError> {
        let project = ProjectDirs::from("dev", "YASC", "YASC")
            .ok_or(PlatformError::DataDirectoryUnavailable)?;
        let data_dir = project.data_local_dir().to_path_buf();
        Ok(Self {
            database: data_dir.join("yasc.db"),
            data_dir,
        })
    }

    pub fn ensure_data_dir(&self) -> Result<(), PlatformError> {
        fs::create_dir_all(&self.data_dir)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("the operating system did not provide an application data directory")]
    DataDirectoryUnavailable,
    #[error("failed to create the application data directory: {0}")]
    CreateDataDirectory(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_lives_inside_data_directory() {
        let paths = PlatformPaths::discover().unwrap();

        assert_eq!(paths.database.parent(), Some(paths.data_dir.as_path()));
        assert_eq!(paths.database.file_name().unwrap(), "yasc.db");
    }
}
