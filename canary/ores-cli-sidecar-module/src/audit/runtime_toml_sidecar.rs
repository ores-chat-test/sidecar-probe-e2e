use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Component, Path};

use toml::Value;

use super::RepositoryAuditOptions;
use crate::model::{CommandReport, Finding};

const CONFIG: &str = ".ores-sidecar.toml";
const CONFIG_PROTOCOL: &str = "ores.sidecar-config.v1";
const RUNTIME_CACHE_NAME: &str = "runtime-env";
const MAX_SIDECARS: usize = 64;
const MAX_RUNTIME_KEYS: usize = 128;
const MAX_SEGMENT_BYTES: usize = 64;
const MAX_RUNTIME_KEY_BYTES: usize = 128;
const MAX_LRU_CONFIG_PATH_BYTES: usize = 256;
const SENSITIVE_KEY_PARTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE_KEY",
    "DATABASE_URL",
    "CREDENTIAL",
];
const ROOT_KEYS: &[&str] = &["protocol", "runtimeUpdates", "sidecars"];
const RUNTIME_UPDATE_KEYS: &[&str] = &["provider", "lruConfigPath", "role", "cache"];
const SIDECAR_KEYS: &[&str] = &[
    "name",
    "enabled",
    "bindIp",
    "bindPort",
    "loopbackOnly",
    "runtimeNamespace",
    "runtimeKeys",
];

/// Apply invariants shared by the independently authored Sidecar TypeSpec and
/// Draft 2020-12 JSON Schema plus the fail-closed runtime constraints enforced
/// by `ORESoftware/ores-sidecar.rs`. Full schema equivalence/admission remains
/// owner/TJSV work: TypeSpec and JSON Schema stay independent peer authorities.
pub(super) fn augment_sidecar_runtime_toml_audit(
    options: &RepositoryAuditOptions,
    mut report: CommandReport,
) -> CommandReport {
    let path = options.path.join(CONFIG);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return report.finalize(),
        Err(_) => return report.finalize(),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return report.finalize();
    }
    let Ok(text) = fs::read_to_string(path) else {
        return report.finalize();
    };
    let Ok(document) = toml::from_str::<Value>(&text) else {
        return report.finalize();
    };
    let Some(root) = document.as_table() else {
        return report.finalize();
    };

    let issues_before = report.issue_count();
    audit_closed_keys(root, ROOT_KEYS, "root", &mut report);

    if root.get("protocol").and_then(Value::as_str) != Some(CONFIG_PROTOCOL) {
        push_error(
            &mut report,
            "sidecar-protocol",
            "protocol must equal ores.sidecar-config.v1",
            "protocol",
        );
    }

    audit_runtime_updates(root.get("runtimeUpdates"), &mut report);
    audit_sidecars(root.get("sidecars"), &mut report);

    if report.issue_count() == issues_before {
        report.push(
            Finding::info(
                "sidecar-domain-inspected",
                ".ores-sidecar.toml passed the bounded peer-authority/runtime invariant audit",
            )
            .with_target(CONFIG),
        );
    }

    report.finalize()
}

fn audit_runtime_updates(value: Option<&Value>, report: &mut CommandReport) {
    let Some(table) = value.and_then(Value::as_table) else {
        push_error(
            report,
            "sidecar-runtime-updates-shape",
            "runtimeUpdates must be a TOML table",
            "runtimeUpdates",
        );
        return;
    };

    audit_closed_keys(table, RUNTIME_UPDATE_KEYS, "runtimeUpdates", report);
    require_string_eq(
        table,
        "provider",
        "ores-redis-lru-cache",
        "sidecar-runtime-provider",
        "runtimeUpdates",
        report,
    );
    require_string_eq(
        table,
        "role",
        "server",
        "sidecar-runtime-role",
        "runtimeUpdates",
        report,
    );
    require_string(table, "lruConfigPath", "runtimeUpdates", report);
    require_safe_relative_path(table, "lruConfigPath", "runtimeUpdates", report);
    require_string_eq(
        table,
        "cache",
        RUNTIME_CACHE_NAME,
        "sidecar-runtime-cache",
        "runtimeUpdates",
        report,
    );
}

fn audit_sidecars(value: Option<&Value>, report: &mut CommandReport) {
    let Some(sidecars) = value.and_then(Value::as_array) else {
        push_error(
            report,
            "sidecar-list-shape",
            "sidecars must be an array of TOML tables",
            "sidecars",
        );
        return;
    };

    if sidecars.is_empty() || sidecars.len() > MAX_SIDECARS {
        push_error(
            report,
            "sidecar-count",
            "sidecars must contain 1..=64 entries",
            "sidecars",
        );
    }

    let mut names = BTreeSet::new();
    for (index, sidecar) in sidecars.iter().enumerate() {
        let target = format!("sidecars[{index}]");
        let Some(table) = sidecar.as_table() else {
            push_error(
                report,
                "sidecar-entry-shape",
                "sidecar entries must be TOML tables",
                &target,
            );
            continue;
        };

        audit_closed_keys(table, SIDECAR_KEYS, &target, report);
        require_string(table, "name", &target, report);
        if let Some(name) = table.get("name").and_then(Value::as_str) {
            validate_segment(name, "name", &target, report);
            if !names.insert(name.to_owned()) {
                push_error(
                    report,
                    "sidecar-duplicate-name",
                    "sidecar names must be unique within one config",
                    &format!("{target}.name"),
                );
            }
        }

        require_bool(table, "enabled", &target, report);
        require_string(table, "bindIp", &target, report);
        let bind_ip = table
            .get("bindIp")
            .and_then(Value::as_str)
            .and_then(|value| match value.parse::<IpAddr>() {
                Ok(address) => Some(address),
                Err(_) => {
                    push_error(
                        report,
                        "sidecar-bind-ip",
                        "bindIp must be an IPv4 or IPv6 address",
                        &format!("{target}.bindIp"),
                    );
                    None
                }
            });
        require_u16_nonzero(table, "bindPort", &target, report);
        require_bool(table, "loopbackOnly", &target, report);
        if table
            .get("loopbackOnly")
            .and_then(Value::as_bool)
            .is_some_and(|loopback_only| loopback_only)
            && bind_ip.is_some_and(|address| !address.is_loopback())
        {
            push_error(
                report,
                "sidecar-loopback-bind",
                "loopbackOnly=true requires a loopback bindIp",
                &format!("{target}.bindIp"),
            );
        }

        require_string(table, "runtimeNamespace", &target, report);
        if let Some(namespace) = table.get("runtimeNamespace").and_then(Value::as_str) {
            validate_segment(namespace, "runtimeNamespace", &target, report);
        }
        audit_runtime_keys(table, &target, report);
    }
}

fn audit_closed_keys(
    table: &toml::map::Map<String, Value>,
    allowed: &[&str],
    target: &str,
    report: &mut CommandReport,
) {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            push_error(
                report,
                "sidecar-unknown-field",
                "field is not declared by the peer-authority SidecarConfig shape",
                &format!("{target}.{key}"),
            );
        }
    }
}

fn require_string_eq(
    table: &toml::map::Map<String, Value>,
    field: &str,
    expected: &str,
    code: &str,
    target: &str,
    report: &mut CommandReport,
) {
    if table.get(field).and_then(Value::as_str) != Some(expected) {
        push_error(
            report,
            code,
            "string value does not match the peer-authority/runtime constant",
            &format!("{target}.{field}"),
        );
    }
}

fn require_string(
    table: &toml::map::Map<String, Value>,
    field: &str,
    target: &str,
    report: &mut CommandReport,
) {
    if table.get(field).and_then(Value::as_str).is_none() {
        push_error(
            report,
            "sidecar-string-shape",
            "required field must be a string",
            &format!("{target}.{field}"),
        );
    }
}

fn require_bool(
    table: &toml::map::Map<String, Value>,
    field: &str,
    target: &str,
    report: &mut CommandReport,
) {
    if table.get(field).and_then(Value::as_bool).is_none() {
        push_error(
            report,
            "sidecar-boolean-shape",
            "required field must be boolean",
            &format!("{target}.{field}"),
        );
    }
}

fn require_u16_nonzero(
    table: &toml::map::Map<String, Value>,
    field: &str,
    target: &str,
    report: &mut CommandReport,
) {
    if !table
        .get(field)
        .and_then(Value::as_integer)
        .is_some_and(|value| (1..=65_535).contains(&value))
    {
        push_error(
            report,
            "sidecar-u16-shape",
            "bindPort must be a non-zero integer in the uint16 range",
            &format!("{target}.{field}"),
        );
    }
}

fn require_safe_relative_path(
    table: &toml::map::Map<String, Value>,
    field: &str,
    target: &str,
    report: &mut CommandReport,
) {
    let Some(value) = table.get(field).and_then(Value::as_str) else {
        return;
    };
    let path = Path::new(value);
    let unsafe_component = path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if value.is_empty()
        || value.len() > MAX_LRU_CONFIG_PATH_BYTES
        || path.is_absolute()
        || unsafe_component
    {
        push_error(
            report,
            "sidecar-runtime-lru-path",
            "lruConfigPath must be a bounded repository-relative path without parent traversal",
            &format!("{target}.{field}"),
        );
    }
}

fn validate_segment(value: &str, field: &str, target: &str, report: &mut CommandReport) {
    if value.is_empty()
        || value.len() > MAX_SEGMENT_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        push_error(
            report,
            "sidecar-segment-shape",
            "sidecar name/runtimeNamespace must be 1..=64 ASCII alphanumeric, '.', '_' or '-' bytes",
            &format!("{target}.{field}"),
        );
    }
}

fn audit_runtime_keys(
    table: &toml::map::Map<String, Value>,
    target: &str,
    report: &mut CommandReport,
) {
    let Some(values) = table.get("runtimeKeys").and_then(Value::as_array) else {
        push_error(
            report,
            "sidecar-string-array-shape",
            "runtimeKeys must be an array of strings",
            &format!("{target}.runtimeKeys"),
        );
        return;
    };
    if values.len() > MAX_RUNTIME_KEYS {
        push_error(
            report,
            "sidecar-runtime-key-count",
            "runtimeKeys must contain at most 128 entries",
            &format!("{target}.runtimeKeys"),
        );
    }

    let mut seen = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let Some(key) = value.as_str() else {
            push_error(
                report,
                "sidecar-string-array-shape",
                "runtimeKeys must contain only strings",
                &format!("{target}.runtimeKeys[{index}]"),
            );
            continue;
        };
        if !seen.insert(key.to_owned()) {
            push_error(
                report,
                "sidecar-runtime-key-duplicate",
                "runtimeKeys must not contain duplicate names",
                &format!("{target}.runtimeKeys[{index}]"),
            );
        }
        if !is_env_key(key) {
            push_error(
                report,
                "sidecar-runtime-key-shape",
                "runtime keys must be bounded uppercase environment-variable names",
                &format!("{target}.runtimeKeys[{index}]"),
            );
        }
        if is_sensitive_runtime_key(key) {
            push_error(
                report,
                "sidecar-runtime-key-sensitive",
                "runtime keys must not expose secret-bearing configuration names",
                &format!("{target}.runtimeKeys[{index}]"),
            );
        }
    }
}

fn is_env_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_uppercase() || first == b'_')
        && value.len() <= MAX_RUNTIME_KEY_BYTES
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_sensitive_runtime_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SENSITIVE_KEY_PARTS
        .iter()
        .any(|part| upper.contains(part))
}

fn push_error(report: &mut CommandReport, code: &str, message: &str, target: &str) {
    report.push(Finding::error(code, message).with_target(target.to_owned()));
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::augment_sidecar_runtime_toml_audit;
    use crate::audit::RepositoryAuditOptions;
    use crate::model::CommandReport;

    const OWNER_EXAMPLE: &str = r#"
protocol = "ores.sidecar-config.v1"

[runtimeUpdates]
provider = "ores-redis-lru-cache"
lruConfigPath = ".ores-lru.toml"
role = "server"
cache = "runtime-env"

[[sidecars]]
name = "api"
enabled = true
bindIp = "127.0.0.1"
bindPort = 7410
loopbackOnly = true
runtimeNamespace = "example-api"
runtimeKeys = ["REQUEST_TIMEOUT_MS"]

[[sidecars]]
name = "worker"
enabled = true
bindIp = "127.0.0.1"
bindPort = 7420
loopbackOnly = true
runtimeNamespace = "example-worker"
runtimeKeys = ["WORKER_BATCH_SIZE"]
"#;

    fn audit(contents: &str) -> CommandReport {
        let root = tempdir().expect("temporary repository");
        fs::write(root.path().join(".ores-sidecar.toml"), contents).expect("write config");
        augment_sidecar_runtime_toml_audit(
            &RepositoryAuditOptions {
                path: root.path().to_path_buf(),
                profile: "baseline".to_owned(),
                additional_required_paths: Vec::new(),
            },
            CommandReport::new("audit repo"),
        )
    }

    fn has(report: &CommandReport, code: &str) -> bool {
        report.findings.iter().any(|finding| finding.code == code)
    }

    #[test]
    fn owner_example_passes_bounded_peer_authority_audit() {
        let report = audit(OWNER_EXAMPLE);
        assert_eq!(report.issue_count(), 0, "{:#?}", report.findings);
        assert!(has(&report, "sidecar-domain-inspected"));
    }

    #[test]
    fn protocol_unknown_field_and_port_range_fail_closed() {
        let report = audit(
            &OWNER_EXAMPLE
                .replace("ores.sidecar-config.v1", "ores.sidecar-config.v2")
                .replace(
                    "bindPort = 7410",
                    "bindPort = 65536\nplaintextToken = \"nope\"",
                ),
        );
        assert!(has(&report, "sidecar-protocol"));
        assert!(has(&report, "sidecar-unknown-field"));
        assert!(has(&report, "sidecar-u16-shape"));
    }

    #[test]
    fn missing_required_fields_fail_closed() {
        let report = audit(&OWNER_EXAMPLE.replace("cache = \"runtime-env\"\n", ""));
        assert!(has(&report, "sidecar-runtime-cache"));
    }

    #[test]
    fn runtime_update_path_and_cache_fail_closed() {
        let report = audit(
            &OWNER_EXAMPLE
                .replace("lruConfigPath = \".ores-lru.toml\"", "lruConfigPath = \"../secrets/.ores-lru.toml\"")
                .replace("cache = \"runtime-env\"", "cache = \"redis-url\""),
        );
        assert!(has(&report, "sidecar-runtime-lru-path"));
        assert!(has(&report, "sidecar-runtime-cache"));
    }

    #[test]
    fn sidecar_identity_listener_and_runtime_keys_fail_closed() {
        let report = audit(
            &OWNER_EXAMPLE
                .replace("name = \"worker\"", "name = \"api\"")
                .replace("bindIp = \"127.0.0.1\"", "bindIp = \"0.0.0.0\"")
                .replace("bindPort = 7410", "bindPort = 0")
                .replace("runtimeNamespace = \"example-api\"", "runtimeNamespace = \"bad namespace\"")
                .replace(
                    "runtimeKeys = [\"REQUEST_TIMEOUT_MS\"]",
                    "runtimeKeys = [\"REQUEST_TIMEOUT_MS\", \"REQUEST_TIMEOUT_MS\", \"API_TOKEN\", \"bad-key\"]",
                ),
        );
        assert!(has(&report, "sidecar-duplicate-name"));
        assert!(has(&report, "sidecar-u16-shape"));
        assert!(has(&report, "sidecar-loopback-bind"));
        assert!(has(&report, "sidecar-segment-shape"));
        assert!(has(&report, "sidecar-runtime-key-duplicate"));
        assert!(has(&report, "sidecar-runtime-key-sensitive"));
        assert!(has(&report, "sidecar-runtime-key-shape"));
    }

    #[test]
    fn sidecar_count_is_bounded() {
        let report = audit(
            r#"
protocol = "ores.sidecar-config.v1"
sidecars = []

[runtimeUpdates]
provider = "ores-redis-lru-cache"
lruConfigPath = ".ores-lru.toml"
role = "server"
cache = "runtime-env"
"#,
        );
        assert!(has(&report, "sidecar-count"));
    }
}
