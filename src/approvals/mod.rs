pub mod tui;

use anyhow::Result;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::{
    detection,
    policy::{AccessRequest, PolicyEvaluation},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalScope {
    Once,
    Session,
    Branch,
    Always,
    Deny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalSource {
    LocalTty,
    ManualAllow,
    AgentMediated,
    BrokerApproval,
    Grant,
    PolicyAuto,
    PolicyDeny,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalChannel {
    Dashboard,
    TerminalApprove,
    AgentMediatedCli,
    LocalPrompt,
    ManualAllow,
    PolicyAuto,
    PolicyDeny,
    GrantReuse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalDecision {
    pub approved: bool,
    pub scope: ApprovalScope,
    pub approved_env: Vec<String>,
    pub denied_env: Vec<String>,
    pub source: ApprovalSource,
    pub grant_id: Option<uuid::Uuid>,
}

pub fn prompt_for_approval(
    request: &AccessRequest,
    evaluation: &PolicyEvaluation,
) -> Result<ApprovalDecision> {
    let critical = detection::has_critical_findings(&evaluation.findings);
    let suspicious_action = detection::has_suspicious_action_findings(&evaluation.findings);

    if let Some(scope) = test_approval_scope()? {
        validate_scope_for_findings(scope, &evaluation.findings)?;
        return Ok(decision_for_scope(request, scope));
    }

    let choices = if critical {
        critical_approval_choices()
    } else {
        approval_choices(request.branch.is_some(), !suspicious_action)
    };

    #[cfg(not(any(test, coverage)))]
    let selected = tui::run_approval_tui(request, evaluation, choices)?;
    #[cfg(any(test, coverage))]
    let selected = choices
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("approval prompt has no choices"))?;

    validate_scope_for_findings(selected, &evaluation.findings)?;
    Ok(decision_for_scope(request, selected))
}

pub(crate) fn approval_choices(include_branch: bool, include_always: bool) -> Vec<ApprovalScope> {
    let mut choices = vec![ApprovalScope::Once, ApprovalScope::Session];
    if include_branch {
        choices.push(ApprovalScope::Branch);
    }
    if include_always {
        choices.push(ApprovalScope::Always);
    }
    choices.push(ApprovalScope::Deny);
    choices
}

pub(crate) fn critical_approval_choices() -> Vec<ApprovalScope> {
    vec![ApprovalScope::Deny, ApprovalScope::Once]
}

pub(crate) fn validate_scope_for_critical(scope: ApprovalScope, critical: bool) -> Result<()> {
    if critical && !matches!(scope, ApprovalScope::Deny | ApprovalScope::Once) {
        anyhow::bail!("critical requests can only be approved with --scope once");
    }
    Ok(())
}

pub(crate) fn validate_scope_for_findings(
    scope: ApprovalScope,
    findings: &[detection::Finding],
) -> Result<()> {
    validate_scope_for_critical(scope, detection::has_critical_findings(findings))?;
    if scope == ApprovalScope::Always && detection::has_suspicious_action_findings(findings) {
        anyhow::bail!("suspicious action text cannot be approved with --scope always");
    }
    Ok(())
}

pub(crate) fn test_approval_scope() -> Result<Option<ApprovalScope>> {
    let Ok(value) = std::env::var("WARD_UNSAFE_TEST_APPROVAL") else {
        return Ok(None);
    };
    let scope = match value.trim().to_ascii_lowercase().as_str() {
        "once" => ApprovalScope::Once,
        "session" => ApprovalScope::Session,
        "branch" => ApprovalScope::Branch,
        "always" => ApprovalScope::Always,
        "deny" => ApprovalScope::Deny,
        other => anyhow::bail!("invalid WARD_UNSAFE_TEST_APPROVAL value: {other}"),
    };
    Ok(Some(scope))
}

pub(crate) fn decision_for_scope(
    request: &AccessRequest,
    scope: ApprovalScope,
) -> ApprovalDecision {
    let approved = scope != ApprovalScope::Deny;
    ApprovalDecision {
        approved,
        scope,
        approved_env: if approved {
            request.env.clone()
        } else {
            Vec::new()
        },
        denied_env: if approved {
            Vec::new()
        } else {
            request.env.clone()
        },
        source: ApprovalSource::LocalTty,
        grant_id: None,
    }
}

pub fn auto_approval(evaluation: &PolicyEvaluation) -> ApprovalDecision {
    ApprovalDecision {
        approved: evaluation.denied_env.is_empty(),
        scope: ApprovalScope::Once,
        approved_env: evaluation.approved_env.clone(),
        denied_env: evaluation.denied_env.clone(),
        source: ApprovalSource::PolicyAuto,
        grant_id: None,
    }
}

impl std::fmt::Display for ApprovalScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalScope::Once => write!(formatter, "Allow once"),
            ApprovalScope::Session => write!(formatter, "Allow for session"),
            ApprovalScope::Branch => write!(formatter, "Allow for branch"),
            ApprovalScope::Always => write!(formatter, "Always allow"),
            ApprovalScope::Deny => write!(formatter, "Deny"),
        }
    }
}

impl ApprovalSource {
    pub fn is_persistable_approval(self) -> bool {
        matches!(
            self,
            ApprovalSource::LocalTty | ApprovalSource::ManualAllow | ApprovalSource::BrokerApproval
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        detection::Finding,
        policy::{AccessRequest, ApprovalMode, PolicyEvaluation},
    };

    fn env_lock() -> crate::test_support::TestEnvironment {
        crate::test_support::TestEnvironment::lock()
    }

    fn access() -> AccessRequest {
        AccessRequest {
            project: "demo".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("feature/test".to_string()),
            action: Some("Run dev".to_string()),
            command: "pnpm dev".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        }
    }

    fn evaluation() -> PolicyEvaluation {
        PolicyEvaluation {
            matched_profile: None,
            matched_preset: Some("Next.js Dev Server".to_string()),
            matched_mode: None,
            approval_mode: ApprovalMode::Prompt,
            requested_env: vec!["DATABASE_URL".to_string()],
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            requires_prompt: true,
            findings: vec![Finding {
                severity: crate::detection::Severity::Info,
                code: "test.info".to_string(),
                message: "test finding".to_string(),
            }],
        }
    }

    #[test]
    fn approval_choices_include_branch_when_available() {
        assert_eq!(
            approval_choices(true, true),
            vec![
                ApprovalScope::Once,
                ApprovalScope::Session,
                ApprovalScope::Branch,
                ApprovalScope::Always,
                ApprovalScope::Deny
            ]
        );
        assert_eq!(
            approval_choices(false, true),
            vec![
                ApprovalScope::Once,
                ApprovalScope::Session,
                ApprovalScope::Always,
                ApprovalScope::Deny
            ]
        );
        assert_eq!(
            approval_choices(true, false),
            vec![
                ApprovalScope::Once,
                ApprovalScope::Session,
                ApprovalScope::Branch,
                ApprovalScope::Deny
            ]
        );
        assert_eq!(
            critical_approval_choices(),
            vec![ApprovalScope::Deny, ApprovalScope::Once]
        );
    }

    #[test]
    fn decision_for_scope_handles_allowed_and_denied_scopes() {
        let access = access();
        let allowed = decision_for_scope(&access, ApprovalScope::Always);
        let denied = decision_for_scope(&access, ApprovalScope::Deny);

        assert!(allowed.approved);
        assert_eq!(allowed.approved_env, vec!["DATABASE_URL"]);
        assert!(allowed.denied_env.is_empty());
        assert!(!denied.approved);
        assert!(denied.approved_env.is_empty());
        assert_eq!(denied.denied_env, vec!["DATABASE_URL"]);
    }

    #[test]
    #[serial_test::serial]
    fn parses_all_test_approval_scopes_and_rejects_invalid_values() {
        let _guard = env_lock();

        for (value, expected) in [
            ("once", ApprovalScope::Once),
            ("session", ApprovalScope::Session),
            ("branch", ApprovalScope::Branch),
            ("always", ApprovalScope::Always),
            ("deny", ApprovalScope::Deny),
        ] {
            std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", value);
            assert_eq!(test_approval_scope().unwrap(), Some(expected));
        }

        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "bad");
        assert!(test_approval_scope().is_err());
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        assert_eq!(test_approval_scope().unwrap(), None);
    }

    #[test]
    fn auto_approval_uses_policy_evaluation() {
        let mut evaluation = evaluation();
        evaluation.requires_prompt = false;
        let decision = auto_approval(&evaluation);

        assert!(decision.approved);
        assert_eq!(decision.source, ApprovalSource::PolicyAuto);
        assert_eq!(decision.approved_env, vec!["DATABASE_URL"]);
    }

    #[test]
    fn display_strings_are_user_facing() {
        assert_eq!(ApprovalScope::Once.to_string(), "Allow once");
        assert_eq!(ApprovalScope::Session.to_string(), "Allow for session");
        assert_eq!(ApprovalScope::Branch.to_string(), "Allow for branch");
        assert_eq!(ApprovalScope::Always.to_string(), "Always allow");
        assert_eq!(ApprovalScope::Deny.to_string(), "Deny");
    }

    #[test]
    #[serial_test::serial]
    fn prompt_for_approval_uses_test_scope() {
        let _guard = env_lock();
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "deny");

        let decision = prompt_for_approval(&access(), &evaluation()).unwrap();

        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        assert!(!decision.approved);
        assert_eq!(decision.scope, ApprovalScope::Deny);
    }

    #[test]
    #[serial_test::serial]
    fn prompt_for_approval_restricts_critical_test_scope() {
        let _guard = env_lock();
        let mut evaluation = evaluation();
        evaluation.findings = vec![Finding::critical("critical.test", "critical")];
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "session");

        assert!(prompt_for_approval(&access(), &evaluation).is_err());

        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "once");
        let decision = prompt_for_approval(&access(), &evaluation).unwrap();
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        assert_eq!(decision.scope, ApprovalScope::Once);
        assert!(decision.approved);
        assert!(validate_scope_for_critical(ApprovalScope::Always, true).is_err());
        assert!(validate_scope_for_critical(ApprovalScope::Always, false).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn prompt_for_approval_restricts_suspicious_action_always_scope() {
        let _guard = env_lock();
        let mut evaluation = evaluation();
        evaluation.findings = vec![Finding::warning(
            "action.approval_coercion",
            "coercive action",
        )];
        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "always");

        assert!(prompt_for_approval(&access(), &evaluation).is_err());

        std::env::set_var("WARD_UNSAFE_TEST_APPROVAL", "session");
        let decision = prompt_for_approval(&access(), &evaluation).unwrap();
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        assert_eq!(decision.scope, ApprovalScope::Session);
    }

    #[test]
    fn suspicious_action_findings_reject_always_scope() {
        let findings = vec![Finding::warning(
            "action.prompt_injection",
            "suspicious action",
        )];

        assert!(validate_scope_for_findings(ApprovalScope::Always, &findings).is_err());
        assert!(validate_scope_for_findings(ApprovalScope::Session, &findings).is_ok());
    }

    #[cfg(coverage)]
    #[test]
    #[serial_test::serial]
    fn prompt_for_approval_uses_coverage_terminal_stub_without_test_scope() {
        let _guard = env_lock();
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");

        let decision = prompt_for_approval(&access(), &evaluation()).unwrap();

        assert!(decision.approved);
        assert_eq!(decision.scope, ApprovalScope::Once);
    }

    #[cfg(coverage)]
    #[test]
    #[serial_test::serial]
    fn critical_prompt_uses_coverage_terminal_stub_without_test_scope() {
        let _guard = env_lock();
        std::env::remove_var("WARD_UNSAFE_TEST_APPROVAL");
        let mut evaluation = evaluation();
        evaluation.findings = vec![Finding::critical("critical.test", "critical")];

        let decision = prompt_for_approval(&access(), &evaluation).unwrap();

        assert!(!decision.approved);
        assert_eq!(decision.scope, ApprovalScope::Deny);
    }

    #[cfg(coverage)]
    #[test]
    fn coverage_prompt_rejects_empty_choice_list() {
        assert!(select_approval_scope(Vec::new()).is_err());
    }
}
