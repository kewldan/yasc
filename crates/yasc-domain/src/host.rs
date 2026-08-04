use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_SSH_PORT: u16 = 22;

/// Stable identifier for an inventory host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostId(Uuid);

impl HostId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for HostId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for HostId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// A normalized direct SSH destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTarget {
    host: String,
    port: u16,
    #[serde(default, skip_serializing)]
    port_explicit: bool,
    username: Option<String>,
}

impl SshTarget {
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn port_is_explicit(&self) -> bool {
        self.port_explicit
    }

    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
}

impl fmt::Display for SshTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(username) = &self.username {
            write!(formatter, "{username}@")?;
        }

        if self.host.contains(':') {
            write!(formatter, "[{}]", self.host)?;
        } else {
            formatter.write_str(&self.host)?;
        }

        if self.port_explicit || self.port != DEFAULT_SSH_PORT {
            write!(formatter, ":{}", self.port)?;
        }

        Ok(())
    }
}

impl FromStr for SshTarget {
    type Err = TargetParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(TargetParseError::Empty);
        }
        if input.trim() != input || input.chars().any(char::is_whitespace) {
            return Err(TargetParseError::Whitespace);
        }

        let (username, host_and_port) = match input.rsplit_once('@') {
            Some((username, host_and_port)) => {
                if username.is_empty() || username.contains('@') {
                    return Err(TargetParseError::InvalidUsername);
                }
                (Some(username.to_owned()), host_and_port)
            }
            None => (None, input),
        };

        let (host, port, port_explicit) = parse_host_and_port(host_and_port)?;
        if host.starts_with('-') || host.chars().any(char::is_control) {
            return Err(TargetParseError::InvalidHost);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            port_explicit,
            username,
        })
    }
}

fn parse_host_and_port(value: &str) -> Result<(&str, u16, bool), TargetParseError> {
    if value.is_empty() {
        return Err(TargetParseError::MissingHost);
    }

    if let Some(bracketed) = value.strip_prefix('[') {
        let closing = bracketed
            .find(']')
            .ok_or(TargetParseError::UnclosedIpv6Address)?;
        let host = &bracketed[..closing];
        if host.is_empty() {
            return Err(TargetParseError::MissingHost);
        }

        let suffix = &bracketed[closing + 1..];
        let (port, port_explicit) = if suffix.is_empty() {
            (DEFAULT_SSH_PORT, false)
        } else {
            (
                parse_port(
                    suffix
                        .strip_prefix(':')
                        .ok_or(TargetParseError::UnexpectedSuffix)?,
                )?,
                true,
            )
        };
        return Ok((host, port, port_explicit));
    }

    if value.matches(':').count() == 1 {
        let (host, port) = value.split_once(':').expect("one separator was counted");
        if host.is_empty() {
            return Err(TargetParseError::MissingHost);
        }
        return Ok((host, parse_port(port)?, true));
    }

    Ok((value, DEFAULT_SSH_PORT, false))
}

fn parse_port(value: &str) -> Result<u16, TargetParseError> {
    let port = value
        .parse::<u16>()
        .map_err(|_| TargetParseError::InvalidPort)?;
    if port == 0 {
        return Err(TargetParseError::InvalidPort);
    }
    Ok(port)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetParseError {
    #[error("SSH target cannot be empty")]
    Empty,
    #[error("SSH target cannot contain whitespace")]
    Whitespace,
    #[error("SSH username is invalid")]
    InvalidUsername,
    #[error("SSH target is missing a host")]
    MissingHost,
    #[error("SSH host is invalid")]
    InvalidHost,
    #[error("bracketed IPv6 address is missing a closing bracket")]
    UnclosedIpv6Address,
    #[error("unexpected text after bracketed IPv6 address")]
    UnexpectedSuffix,
    #[error("SSH port must be an integer between 1 and 65535")]
    InvalidPort,
}

/// A host stored in the local inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: HostId,
    pub label: String,
    pub target: SshTarget,
    pub tags: BTreeSet<String>,
    pub environment: Option<String>,
}

impl Host {
    pub fn new(label: impl Into<String>, target: SshTarget) -> Result<Self, HostError> {
        let label = label.into();
        if label.trim().is_empty() {
            return Err(HostError::EmptyLabel);
        }

        Ok(Self {
            id: HostId::new(),
            label,
            target,
            tags: BTreeSet::new(),
            environment: None,
        })
    }

    pub fn restore(
        id: HostId,
        label: impl Into<String>,
        target: SshTarget,
        tags: BTreeSet<String>,
        environment: Option<String>,
    ) -> Result<Self, HostError> {
        let label = label.into();
        if label.trim().is_empty() {
            return Err(HostError::EmptyLabel);
        }

        Ok(Self {
            id,
            label,
            target,
            tags,
            environment,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostError {
    #[error("host label cannot be empty")]
    EmptyLabel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_target_with_custom_port() {
        let target: SshTarget = "deploy@example.com:2222".parse().unwrap();

        assert_eq!(target.username(), Some("deploy"));
        assert_eq!(target.host(), "example.com");
        assert_eq!(target.port(), 2222);
        assert!(target.port_is_explicit());
        assert_eq!(target.to_string(), "deploy@example.com:2222");
    }

    #[test]
    fn normalizes_bracketed_ipv6_target() {
        let target: SshTarget = "admin@[2001:db8::10]:2200".parse().unwrap();

        assert_eq!(target.host(), "2001:db8::10");
        assert_eq!(target.port(), 2200);
        assert_eq!(target.to_string(), "admin@[2001:db8::10]:2200");
    }

    #[test]
    fn treats_unbracketed_ipv6_as_host_without_port() {
        let target: SshTarget = "2001:db8::10".parse().unwrap();

        assert_eq!(target.host(), "2001:db8::10");
        assert_eq!(target.port(), DEFAULT_SSH_PORT);
        assert!(!target.port_is_explicit());
        assert_eq!(target.to_string(), "[2001:db8::10]");
    }

    #[test]
    fn rejects_zero_port() {
        let error = "example.com:0".parse::<SshTarget>().unwrap_err();

        assert_eq!(error, TargetParseError::InvalidPort);
    }

    #[test]
    fn rejects_option_like_host() {
        let error = "-oProxyCommand=malicious".parse::<SshTarget>().unwrap_err();

        assert_eq!(error, TargetParseError::InvalidHost);
    }
}
