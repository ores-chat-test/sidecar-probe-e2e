pub mod model {
    use std::collections::BTreeMap;

    use serde_json::Value;

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
        pub details: BTreeMap<String, Value>,
    }

    impl Finding {
        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity: Severity::Error,
                details: BTreeMap::new(),
            }
        }

        pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                code: code.into(),
                message: message.into(),
                target: None,
                severity: Severity::Info,
                details: BTreeMap::new(),
            }
        }

        pub fn with_target(mut self, target: impl Into<String>) -> Self {
            self.target = Some(target.into());
            self
        }

        pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
            self.details.insert(key.into(), value);
            self
        }
    }

    #[derive(Debug, Clone)]
    pub struct CommandReport {
        pub command: String,
        pub findings: Vec<Finding>,
        pub metadata: BTreeMap<String, Value>,
    }

    impl CommandReport {
        pub fn new(command: impl Into<String>) -> Self {
            Self {
                command: command.into(),
                findings: Vec::new(),
                metadata: BTreeMap::new(),
            }
        }

        pub fn push(&mut self, finding: Finding) {
            self.findings.push(finding);
        }

        pub fn insert_metadata(&mut self, key: impl Into<String>, value: Value) {
            self.metadata.insert(key.into(), value);
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

    mod runtime_toml_env_boundary;

    pub fn run_runtime_env_boundary(
        options: &RepositoryAuditOptions,
        report: CommandReport,
    ) -> CommandReport {
        runtime_toml_env_boundary::augment_runtime_toml_env_boundary_audit(options, report)
    }
}
