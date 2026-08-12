use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[cfg(not(test))]
use crate::broker;
#[cfg(test)]
use crate::unlock;
use crate::{
    approval_receipts::{self, ApprovalReceipt},
    approvals::{ApprovalDecision, ApprovalScope, ApprovalSource},
    context, fs_util, logs,
    policy::AccessRequest,
};

const SESSION_GRANT_HOURS: i64 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalGrant {
    pub id: uuid::Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<uuid::Uuid>,
    pub project: String,
    pub agent: Option<String>,
    pub branch: Option<String>,
    pub command: String,
    pub approved_env: Vec<String>,
    pub scope: ApprovalScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses_remaining: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ApprovalReceipt>,
}

#[derive(Debug, Clone)]
pub struct GrantReceiptContext {
    pub request_id: uuid::Uuid,
    pub pending_request: bool,
    pub critical_confirmation: bool,
    pub verified_context: Option<context::VerifiedContext>,
}

impl GrantReceiptContext {
    pub fn synthetic(critical_confirmation: bool) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4(),
            pending_request: false,
            critical_confirmation,
            verified_context: None,
        }
    }

    pub fn pending(
        request_id: uuid::Uuid,
        critical_confirmation: bool,
        verified_context: Option<context::VerifiedContext>,
    ) -> Self {
        Self {
            request_id,
            pending_request: true,
            critical_confirmation,
            verified_context,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantIntegrityStatus {
    Valid,
    Expired,
    LegacyUnsigned,
    Invalid,
}

include!("parts/storage.rs");
include!("parts/matching.rs");
include!("parts/tests.rs");
