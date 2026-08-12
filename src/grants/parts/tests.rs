#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        approvals::{ApprovalDecision, ApprovalSource},
        unlock,
    };

    fn env_lock() -> crate::test_support::TestEnvironment {
        crate::test_support::TestEnvironment::lock()
    }

    fn access() -> AccessRequest {
        AccessRequest {
            project: "ambienta".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("feature/x".to_string()),
            action: Some("Run dev server".to_string()),
            command: "pnpm dev".to_string(),
            env: vec!["DATABASE_URL".to_string()],
        }
    }

    fn setup_signing_home() -> (tempfile::TempDir, PathBuf) {
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");
        unlock::create_run_unlock("ambienta", &vault, "1234", Duration::hours(1)).unwrap();
        (tempdir, vault)
    }

    fn clear_signing_home() {
        std::env::remove_var("WARD_HOME");
        std::env::remove_var("WARD_UNSAFE_TEST_KEYRING");
    }

    fn grant(scope: ApprovalScope, now: DateTime<Utc>, vault: &Path) -> ApprovalGrant {
        let mut grant = ApprovalGrant {
            id: uuid::Uuid::new_v4(),
            created_at: now,
            expires_at: None,
            request_id: None,
            project: "ambienta".to_string(),
            agent: Some("codex".to_string()),
            branch: Some("feature/x".to_string()),
            command: "pnpm dev".to_string(),
            approved_env: vec!["DATABASE_URL".to_string(), "PAYLOAD_SECRET".to_string()],
            scope,
            uses_remaining: (scope == ApprovalScope::Once).then_some(1),
            receipt: None,
        };
        let access = access();
        sign_grant(
            &access,
            vault,
            &mut grant,
            GrantReceiptContext::synthetic(false),
        )
        .unwrap();
        grant
    }

    fn verified_context() -> context::VerifiedContext {
        context::VerifiedContext {
            project: "ambienta".to_string(),
            agent: "codex".to_string(),
            agent_key_id: "agent:key".to_string(),
            worktree: PathBuf::from("/tmp/ambienta-worktree"),
            branch: "feature/x".to_string(),
            git_remote: "https://example.test/ambienta".to_string(),
            commit: "abc123".to_string(),
            git_common_dir: None,
        }
    }

    #[test]
    #[serial_test::serial]
    fn matches_session_branch_and_always_grants() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();

        for scope in [
            ApprovalScope::Session,
            ApprovalScope::Branch,
            ApprovalScope::Always,
        ] {
            let grant = grant(scope, now, &vault);
            assert!(grant_matches_access(&grant, &access, now, false));
        }
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn ignores_once_deny_and_expired_session_grants() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();
        let mut expired = grant(ApprovalScope::Session, now, &vault);
        expired.expires_at = Some(now - Duration::minutes(1));
        let mut spent_once = grant(ApprovalScope::Once, now, &vault);
        spent_once.uses_remaining = Some(0);

        assert!(grant_matches_access(
            &grant(ApprovalScope::Once, now, &vault),
            &access,
            now,
            false
        ));
        assert!(!grant_matches_access(
            &grant(ApprovalScope::Deny, now, &vault),
            &access,
            now,
            false
        ));
        assert!(!grant_matches_access(&spent_once, &access, now, false));
        assert!(!grant_matches_access(&expired, &access, now, false));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn requires_requested_env_subset() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let mut access = access();
        access.env.push("OPENAI_API_KEY".to_string());

        assert!(!grant_matches_access(
            &grant(ApprovalScope::Always, now, &vault),
            &access,
            now,
            false
        ));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn finds_latest_matching_grant_or_once_only_grant() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();
        let always = grant(ApprovalScope::Always, now, &vault);
        let once = grant(ApprovalScope::Once, now, &vault);
        let grants = vec![once.clone(), always.clone()];

        assert_eq!(
            find_matching_grant_in(&grants, &access, now).unwrap().id,
            always.id
        );
        assert_eq!(
            find_matching_once_grant_in(&grants, &access, now, false)
                .unwrap()
                .id,
            once.id
        );
        assert_eq!(
            find_matching_non_always_grant_in(&grants, &access, now)
                .unwrap()
                .id,
            once.id
        );
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn lock_revokes_only_session_grants() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("grants.jsonl");
        let now = Utc::now();

        append_grant_to_path(&path, &grant(ApprovalScope::Session, now, &vault)).unwrap();
        append_grant_to_path(&path, &grant(ApprovalScope::Branch, now, &vault)).unwrap();
        append_grant_to_path(&path, &grant(ApprovalScope::Always, now, &vault)).unwrap();

        let revoked = revoke_session_grants_at_path(&path).unwrap();
        let retained = load_grants_from_path(&path).unwrap();

        assert_eq!(revoked, 1);
        assert_eq!(retained.len(), 2);
        assert!(retained
            .iter()
            .all(|grant| grant.scope != ApprovalScope::Session));
        clear_signing_home();
    }

    #[test]
    fn load_grants_skips_blank_lines_and_reports_invalid_json() {
        let tempdir = tempfile::tempdir().unwrap();
        let blank_path = tempdir.path().join("blank.jsonl");
        let bad_path = tempdir.path().join("bad.jsonl");

        std::fs::write(&blank_path, "\n\n").unwrap();
        std::fs::write(&bad_path, "{not-json}\n").unwrap();

        assert!(load_grants_from_path(&tempdir.path().join("missing.jsonl"))
            .unwrap()
            .is_empty());
        assert!(load_grants_from_path(&blank_path).unwrap().is_empty());
        assert!(load_grants_from_path(&bad_path).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn persist_grant_writes_only_prompt_persisted_approvals() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let access = access();
        let decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Always,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };

        let grant = persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .unwrap();
        let found = find_matching_grant(&access).unwrap().unwrap();
        let default_context_grant = persist_grant(&access, &decision, &vault, None)
            .unwrap()
            .unwrap();
        assert!(default_context_grant.receipt.is_some());

        clear_signing_home();
        assert_eq!(grant.id, found.id);
    }

    #[test]
    #[serial_test::serial]
    fn persist_grant_reports_append_failures() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        let sessions_path = tempdir.path().join("sessions");
        std::fs::write(&sessions_path, "").unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        std::env::set_var("WARD_UNSAFE_TEST_KEYRING", "1");
        let vault = tempdir.path().join(".env.vault");
        assert!(unlock::create_run_unlock("ambienta", &vault, "1234", Duration::hours(1)).is_err());

        let decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Always,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };

        assert!(persist_grant(
            &access(),
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn persist_grant_writes_session_scope() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();

        let decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Session,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };
        let grant = persist_grant(
            &access(),
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .unwrap();

        assert_eq!(grant.scope, ApprovalScope::Session);
        assert!(grant.expires_at.is_some());
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn context_wrapper_lookups_and_default_manual_receipts_are_exercised() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let access = access();
        let context = verified_context();

        let default_grant = persist_manual_grant(
            &access,
            ApprovalScope::Session,
            ApprovalSource::ManualAllow,
            &vault,
            None,
        )
        .unwrap();
        assert!(default_grant.receipt.is_some());

        let receipt_context = GrantReceiptContext {
            request_id: uuid::Uuid::new_v4(),
            pending_request: false,
            critical_confirmation: false,
            verified_context: Some(context.clone()),
        };
        let once_grant = persist_manual_grant(
            &access,
            ApprovalScope::Once,
            ApprovalSource::ManualAllow,
            &vault,
            Some(receipt_context),
        )
        .unwrap();
        assert!(once_grant.receipt.is_some());
        assert!(
            find_matching_non_always_grant_with_context(&access, &context)
                .unwrap()
                .is_some()
        );
        assert!(
            find_matching_once_grant_with_context(&access, false, &context)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            prune_expired_grants_at_path(&grants_path(), Utc::now()).unwrap(),
            0
        );

        clear_signing_home();
    }

    #[test]
    fn append_grant_reports_open_failures() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let tempdir = tempfile::tempdir().unwrap();
        let directory = tempdir.path().join("grants.jsonl");
        std::fs::create_dir(&directory).unwrap();

        assert!(append_grant_to_path(
            &directory,
            &grant(ApprovalScope::Always, Utc::now(), &vault)
        )
        .is_err());
        clear_signing_home();
    }

    #[test]
    fn persist_grant_ignores_once_deny_policy_and_rejects_missing_branch_scope() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let access = AccessRequest {
            branch: None,
            ..access()
        };
        let mut decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Once,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };

        assert!(persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .is_none());
        decision.scope = ApprovalScope::Deny;
        decision.approved = false;
        assert!(persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .is_none());
        decision.scope = ApprovalScope::Always;
        decision.approved = true;
        decision.source = ApprovalSource::PolicyAuto;
        assert!(persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap()
        .is_none());
        decision.scope = ApprovalScope::Branch;
        decision.source = ApprovalSource::LocalTty;
        assert!(persist_grant(
            &access,
            &decision,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());
        clear_signing_home();
    }

    #[test]
    fn grant_from_decision_creates_once_grants_and_rejects_denials() {
        let access = access();
        let mut decision = ApprovalDecision {
            approved: true,
            scope: ApprovalScope::Once,
            approved_env: vec!["DATABASE_URL".to_string()],
            denied_env: Vec::new(),
            source: ApprovalSource::LocalTty,
            grant_id: None,
        };

        let once = grant_from_decision(&access, &decision, Utc::now()).unwrap();
        assert_eq!(once.scope, ApprovalScope::Once);
        assert_eq!(once.uses_remaining, Some(1));
        assert!(once.expires_at.is_some());
        decision.scope = ApprovalScope::Deny;
        assert!(grant_from_decision(&access, &decision, Utc::now()).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn unsigned_and_modified_grants_are_not_reused() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();
        let unsigned = grant_from_decision(
            &access,
            &ApprovalDecision {
                approved: true,
                scope: ApprovalScope::Always,
                approved_env: access.env.clone(),
                denied_env: Vec::new(),
                source: ApprovalSource::LocalTty,
                grant_id: None,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            grant_integrity_status(&unsigned, now),
            GrantIntegrityStatus::LegacyUnsigned
        );
        assert!(!receipt_matches_grant(&unsigned));
        assert!(!grant_matches_access(&unsigned, &access, now, false));

        let mut signed = grant(ApprovalScope::Always, now, &vault);
        assert_eq!(
            grant_integrity_status(&signed, now),
            GrantIntegrityStatus::Valid
        );
        let mut expired = signed.clone();
        expired.expires_at = Some(now - Duration::minutes(1));
        assert_eq!(
            grant_integrity_status(&expired, now),
            GrantIntegrityStatus::Expired
        );
        assert!(!grant_matches_access(&signed, &access, now, true));

        let mut broken_receipt = signed.clone();
        broken_receipt.receipt.as_mut().unwrap().payload_hash = "bad".to_string();
        assert!(!grant_matches_access(&broken_receipt, &access, now, false));

        signed.command = "pnpm build".to_string();
        assert_eq!(
            grant_integrity_status(&signed, now),
            GrantIntegrityStatus::Invalid
        );
        assert!(!grant_matches_access(&signed, &access, now, false));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn persist_manual_grant_reports_unavailable_signing_material() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let key_store_path = crate::logs::ward_home().join("cache").join("keystore.json");
        std::fs::remove_file(key_store_path).unwrap();

        let error = persist_manual_grant(
            &access(),
            ApprovalScope::Always,
            ApprovalSource::ManualAllow,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unlock_material_unavailable"));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn grant_matching_rejects_project_command_agent_and_branch_mismatches() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let grant = grant(ApprovalScope::Branch, now, &vault);

        let mut project_mismatch = access();
        project_mismatch.project = "other".to_string();
        assert!(!grant_matches_access(&grant, &project_mismatch, now, false));

        let mut command_mismatch = access();
        command_mismatch.command = "pnpm build".to_string();
        assert!(!grant_matches_access(&grant, &command_mismatch, now, false));

        let mut agent_mismatch = access();
        agent_mismatch.agent = Some("cursor".to_string());
        assert!(!grant_matches_access(&grant, &agent_mismatch, now, false));

        let mut branch_mismatch = access();
        branch_mismatch.branch = Some("feature/other".to_string());
        assert!(!grant_matches_access(&grant, &branch_mismatch, now, false));
        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn context_bound_grants_require_matching_verified_context() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();
        let now = Utc::now();
        let access = access();
        let verified = verified_context();
        let mut grant = ApprovalGrant {
            id: uuid::Uuid::new_v4(),
            created_at: now,
            expires_at: Some(now + Duration::hours(1)),
            request_id: None,
            project: access.project.clone(),
            agent: access.agent.clone(),
            branch: access.branch.clone(),
            command: access.command.clone(),
            approved_env: access.env.clone(),
            scope: ApprovalScope::Session,
            uses_remaining: None,
            receipt: None,
        };
        sign_grant(
            &access,
            &vault,
            &mut grant,
            GrantReceiptContext {
                request_id: uuid::Uuid::new_v4(),
                pending_request: false,
                critical_confirmation: false,
                verified_context: Some(verified.clone()),
            },
        )
        .unwrap();
        assert!(find_matching_non_always_grant_in_with_context(
            std::slice::from_ref(&grant),
            &access,
            now,
            &verified
        )
        .is_some());
        assert!(!grant_matches_access(&grant, &access, now, false));
        clear_signing_home();
    }

    #[test]
    fn revoke_session_grants_handles_missing_file() {
        let tempdir = tempfile::tempdir().unwrap();
        assert_eq!(
            revoke_session_grants_at_path(&tempdir.path().join("missing.jsonl")).unwrap(),
            0
        );
    }

    #[test]
    #[serial_test::serial]
    fn manual_revoke_prune_and_once_consumption_helpers_cover_edges() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();

        let access = access();
        assert!(persist_manual_grant(
            &access,
            ApprovalScope::Always,
            ApprovalSource::Grant,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());
        assert!(persist_manual_grant(
            &access,
            ApprovalScope::Once,
            ApprovalSource::AgentMediated,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());
        assert!(persist_manual_grant(
            &access,
            ApprovalScope::Deny,
            ApprovalSource::ManualAllow,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .is_err());

        let always = persist_manual_grant(
            &access,
            ApprovalScope::Always,
            ApprovalSource::ManualAllow,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap();
        let once = persist_manual_grant(
            &access,
            ApprovalScope::Once,
            ApprovalSource::BrokerApproval,
            &vault,
            Some(GrantReceiptContext::synthetic(false)),
        )
        .unwrap();
        let session = persist_manual_grant(
            &access,
            ApprovalScope::Session,
            ApprovalSource::ManualAllow,
            &vault,
            None,
        )
        .unwrap();
        assert_eq!(session.scope, ApprovalScope::Session);

        assert!(!consume_once_grant(uuid::Uuid::new_v4()).unwrap());
        assert!(consume_once_grant(once.id).unwrap());
        assert!(!revoke_grant(uuid::Uuid::new_v4()).unwrap());
        assert!(revoke_grant(always.id).unwrap());

        let mut expired = grant(ApprovalScope::Session, Utc::now(), &vault);
        expired.expires_at = Some(Utc::now() - Duration::minutes(1));
        append_grant_to_path(&grants_path(), &expired).unwrap();
        assert_eq!(prune_expired_grants().unwrap(), 1);
        assert_eq!(prune_expired_grants().unwrap(), 0);

        clear_signing_home();
    }

    #[test]
    #[serial_test::serial]
    fn global_grant_helpers_report_invalid_grant_file() {
        let _guard = env_lock();
        let tempdir = tempfile::tempdir().unwrap();
        std::env::set_var("WARD_HOME", tempdir.path());
        let grants_dir = tempdir.path().join("sessions");
        std::fs::create_dir_all(&grants_dir).unwrap();
        std::fs::write(grants_dir.join("grants.jsonl"), "{bad-json}\n").unwrap();

        assert!(find_matching_grant(&access()).is_err());
        assert!(find_matching_once_grant(&access(), false).is_err());
        assert!(find_matching_non_always_grant(&access()).is_err());
        assert!(revoke_session_grants().is_err());

        std::env::remove_var("WARD_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn removes_project_grants_and_keeps_other_projects() {
        let _guard = env_lock();
        let (_home, vault) = setup_signing_home();

        let now = Utc::now();
        append_grant_to_path(&grants_path(), &grant(ApprovalScope::Always, now, &vault)).unwrap();
        let mut other = grant(ApprovalScope::Always, now, &vault);
        other.project = "other".to_string();
        append_grant_to_path(&grants_path(), &other).unwrap();

        assert_eq!(remove_project_grants("missing").unwrap(), 0);
        assert_eq!(remove_project_grants("ambienta").unwrap(), 1);
        let retained = load_grants().unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].project, "other");

        clear_signing_home();
    }
}
