pub mod model {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Severity {
        Error,
        Info,
    }

    #[derive(Debug, Clone)]
    pub struct Finding {
        pub code: String,
        pub message: String,
        pub target: Option<String>,
        pub severity: Severity,
    }

    impl Finding {
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity: Severity::Error,
            }
        }

        pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity: Severity::Info,
            }
        }

        pub fn with_target(mut self, target: impl Into<String>) -> Self {
            self.target = Some(target.into());
            self
        }
    }

    #[derive(Debug, Clone)]
    pub struct CommandReport {
        pub command: String,
        pub findings: Vec<Finding>,
    }

    impl CommandReport {
        pub fn new(command: impl Into<String>) -> Self {
            Self {
                command: command.into(),
                findings: Vec::new(),
            }
        }

        pub fn push(&mut self, finding: Finding) {
            self.findings.push(finding);
        }

        pub fn issue_count(&self) -> usize {
            self.findings
                .iter()
                .filter(|finding| finding.severity == Severity::Error)
                .count()
        }

        pub fn finalize(self) -> Self {
            self
        }
    }
}

pub mod audit {
    use std::path::PathBuf;

    use crate::model::CommandReport;

    #[derive(Debug, Clone)]
    pub struct RepositoryAuditOptions {
        pub path: PathBuf,
        pub profile: String,
        pub additional_required_paths: Vec<String>,
    }

    mod runtime_toml_sidecar;

    pub fn run_sidecar(
        options: &RepositoryAuditOptions,
        report: CommandReport,
    ) -> CommandReport {
        runtime_toml_sidecar::augment_sidecar_runtime_toml_audit(options, report)
    }
}

#[cfg(test)]
mod compatibility_shell_tests {
    use super::model::CommandReport;

    #[test]
    fn compatibility_shell_is_minimal() {
        let report = CommandReport::new("audit repo");
        assert_eq!(report.issue_count(), 0);
    }
}
