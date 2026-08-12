fn handle(mut req: tiny_http::Request, token: &str) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = split_url(&url);

    if method == Method::Options {
        respond_empty(req, StatusCode(204));
        return;
    }

    if path.starts_with("/api/") && !authorized(&req, &query, token) {
        respond_json(
            req,
            StatusCode(403),
            &json!({ "error": "unauthorized", "message": "dashboard token required" }),
        );
        return;
    }

    if method == Method::Get && path == "/favicon.png" {
        serve_png(req, WARD_FAVICON_LIGHT_PNG);
        return;
    }

    if method == Method::Get && path == "/favicon.svg" {
        serve_svg(req, WARD_LOGO_DARK_SVG);
        return;
    }

    if method == Method::Get && path == "/assets/ward-logo-dark.png" {
        serve_png(req, WARD_LOGO_DARK_PNG);
        return;
    }

    if method == Method::Get && path == "/assets/ward-logo-transparent.svg" {
        serve_svg(req, WARD_LOGO_TRANSPARENT_SVG);
        return;
    }

    if method == Method::Get && is_dashboard_page_route(&path) {
        serve_html(req);
        return;
    }

    match (method, path.as_str()) {
        (Method::Get, "/api/projects") => respond_json_result(req, dashboard_projects()),
        (Method::Get, "/api/store/projects") => {
            respond_json_result(req, project_store::list_summaries())
        }
        (Method::Get, "/api/events") => {
            let project = query_param(&query, "project");
            respond_json_result(req, Ok(load_all_events(project.as_deref())))
        }
        (Method::Get, "/api/notifications") => {
            respond_json_result(req, notifications::list_notifications())
        }
        (Method::Get, "/api/notifications/stream") => {
            respond_notifications_stream(req);
        }
        (Method::Get, "/api/dashboard/status") => respond_json_result(req, dashboard_status()),
        (Method::Get, _) => respond_not_found(req),
        (Method::Post, "/api/projects/pick-folder") => {
            let result = pick_project_folder(&mut req);
            respond_json_result(req, result);
        }
        (Method::Post, "/api/projects/setup") => {
            let result = setup_project_from_dashboard(&mut req);
            respond_project_setup_result(req, result);
        }
        (Method::Post, "/api/projects/provision") => {
            let result = provision_project_from_dashboard(&mut req);
            respond_project_provision_result(req, result);
        }
        (Method::Post, _) => {
            if let Some((notification_id, action)) = notification_action_route(&path) {
                let result = notification_action(notification_id, &action);
                respond_json_result(req, result);
            } else if path == "/api/sessions/lock-all" {
                let result = lock_all_sessions();
                respond_json_result(req, result);
            } else if let Some((project, action)) = project_action_route(&path) {
                match action.as_str() {
                    "lock" => {
                        let result = lock_project_session(&project);
                        respond_json_result(req, result);
                    }
                    "remove" => {
                        let result = remove_project_from_dashboard(&project, &mut req);
                        respond_broker_project_result(req, result, "project_remove_failed");
                    }
                    _ => respond_not_found(req),
                }
            } else if let Some((request_id, action)) = approval_action_route(&path) {
                let result = approval_action(&mut req, request_id, &action);
                respond_approval_result(req, result);
            } else if let Some((request_id, action)) = worktree_action_route(&path) {
                let result = worktree_action(request_id, &action);
                respond_json_result(req, result);
            } else if let Some(project) = profiles_collection_route(&path) {
                let result = create_profile_policy(&project, &mut req);
                respond_json_result(req, result);
            } else if let Some(project) = store_snapshot_route(&path) {
                let result = snapshot_project_from_dashboard(&project);
                respond_project_snapshot_result(req, result);
            } else if let Some((project, profile)) = profile_env_route(&path) {
                let result = update_profile_env(&project, &profile, &mut req);
                respond_json_result(req, result);
            } else {
                respond_not_found(req);
            }
        }
        (Method::Patch, _) => {
            if let Some((project, profile)) = profile_policy_route(&path) {
                let result = update_profile_policy(&project, &profile, &mut req);
                respond_json_result(req, result);
            } else if let Some((project, profile)) = profile_env_route(&path) {
                let result = update_profile_env(&project, &profile, &mut req);
                respond_json_result(req, result);
            } else {
                respond_not_found(req);
            }
        }
        (Method::Delete, _) => {
            if let Some((project, profile)) = profile_policy_route(&path) {
                let result = delete_profile_policy(&project, &profile);
                respond_json_result(req, result);
            } else {
                respond_not_found(req);
            }
        }
        _ => respond_not_found(req),
    }
}

fn serve_html(req: tiny_http::Request) {
    let html = DASHBOARD_HTML.as_bytes();
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        ],
        Cursor::new(html),
        Some(html.len()),
        None,
    );
    let _ = req.respond(response);
}

fn serve_svg(req: tiny_http::Request, svg: &'static str) {
    let body = svg.as_bytes();
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "image/svg+xml; charset=utf-8").unwrap(),
            Header::from_bytes("Cache-Control", "public, max-age=86400").unwrap(),
        ],
        Cursor::new(body),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn serve_png(req: tiny_http::Request, body: &'static [u8]) {
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "image/png").unwrap(),
            Header::from_bytes("Cache-Control", "public, max-age=86400").unwrap(),
        ],
        Cursor::new(body),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn respond_json_result<T: Serialize>(req: tiny_http::Request, result: Result<T>) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => respond_json(
            req,
            StatusCode(500),
            &json!({ "error": "dashboard_error", "message": error.to_string() }),
        ),
    }
}

fn respond_project_setup_result(
    req: tiny_http::Request,
    result: Result<broker::BrokerProjectSetupStatus>,
) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => {
            if let Some(broker_error) = error.downcast_ref::<broker::BrokerError>() {
                if broker_error.reason() == &broker::BrokerReason::UnlockRequired {
                    respond_json(
                        req,
                        StatusCode(423),
                        &json!({
                            "status": "unlock_required",
                            "unlockRequired": true,
                            "message": broker_error.message(),
                            "fixCommand": "ward unlock --ttl 8h"
                        }),
                    );
                    return;
                }
            }
            respond_json(
                req,
                StatusCode(500),
                &json!({ "error": "project_setup_failed", "message": error.to_string() }),
            );
        }
    }
}

fn respond_approval_result(req: tiny_http::Request, result: Result<Value>) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => {
            let message = error.to_string();
            let status = if message.contains("signing_key_unavailable")
                || message.contains("unlock_required")
                || message.contains("missing broker unlock session")
                || message.contains("expired broker unlock session")
                || message.contains("Ward broker is unavailable")
            {
                StatusCode(423)
            } else {
                StatusCode(500)
            };
            respond_json(
                req,
                status,
                &json!({
                    "error": "approval_failed",
                    "message": message,
                    "unlockRequired": status.0 == 423,
                    "fixCommand": "ward unlock --ttl 8h"
                }),
            );
        }
    }
}

fn respond_project_snapshot_result(
    req: tiny_http::Request,
    result: Result<broker::BrokerProjectSnapshotStatus>,
) {
    respond_broker_project_result(req, result, "project_snapshot_failed")
}

fn respond_project_provision_result(
    req: tiny_http::Request,
    result: Result<broker::BrokerProjectProvisionStatus>,
) {
    respond_broker_project_result(req, result, "project_provision_failed")
}

fn respond_broker_project_result<T: Serialize>(
    req: tiny_http::Request,
    result: Result<T>,
    error_name: &'static str,
) {
    match result {
        Ok(value) => respond_json(req, StatusCode(200), &value),
        Err(error) => {
            if let Some(broker_error) = error.downcast_ref::<broker::BrokerError>() {
                if broker_error.reason() == &broker::BrokerReason::UnlockRequired
                    || broker_error
                        .message()
                        .contains("missing broker unlock session")
                    || broker_error
                        .message()
                        .contains("expired broker unlock session")
                {
                    respond_json(
                        req,
                        StatusCode(423),
                        &json!({
                            "status": "unlock_required",
                            "unlockRequired": true,
                            "message": broker_error.message(),
                            "fixCommand": "ward unlock --ttl 8h"
                        }),
                    );
                    return;
                }
            }
            respond_json(
                req,
                StatusCode(500),
                &json!({ "error": error_name, "message": error.to_string() }),
            );
        }
    }
}

fn respond_json<T: Serialize>(req: tiny_http::Request, status: StatusCode, value: &T) {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    let response = Response::new(
        status,
        vec![
            Header::from_bytes("Content-Type", "application/json").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        ],
        Cursor::new(body.clone()),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn respond_notifications_stream(req: tiny_http::Request) {
    let payload = match notifications::list_notifications() {
        Ok(notifications) => json!({ "notifications": notifications }),
        Err(error) => {
            json!({ "error": "notification_stream_failed", "message": error.to_string() })
        }
    };
    let body = format!("retry: 2000\nevent: notifications\ndata: {payload}\n\n");
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "text/event-stream").unwrap(),
            Header::from_bytes("Cache-Control", "no-cache").unwrap(),
        ],
        Cursor::new(body.clone().into_bytes()),
        Some(body.len()),
        None,
    );
    let _ = req.respond(response);
}

fn respond_empty(req: tiny_http::Request, status: StatusCode) {
    let _ = req.respond(Response::new(
        status,
        Vec::new(),
        Cursor::new(Vec::new()),
        Some(0),
        None,
    ));
}

fn respond_not_found(req: tiny_http::Request) {
    let _ = req.respond(Response::new(
        StatusCode(404),
        Vec::new(),
        Cursor::new(b"not found".to_vec()),
        Some(9),
        None,
    ));
}

fn split_url(url: &str) -> (String, String) {
    match url.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (url.to_string(), String::new()),
    }
}

fn authorized(req: &tiny_http::Request, query: &str, token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    if query_param(query, "token").as_deref() == Some(token) {
        return true;
    }
    req.headers().iter().any(|header| {
        let name = header
            .field
            .to_string()
            .eq_ignore_ascii_case("authorization");
        let value = header.value.as_str();
        (name && value == format!("Bearer {token}"))
            || (header
                .field
                .to_string()
                .eq_ignore_ascii_case("x-ward-dashboard-token")
                && value == token)
    })
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (url_decode(key) == name).then(|| url_decode(value))
    })
}

fn is_dashboard_page_route(path: &str) -> bool {
    path == "/" || path == "/logs" || project_logs_route(path).is_some()
}

fn project_logs_route(path: &str) -> Option<String> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["projects", project, "logs"] => Some(url_decode(project)),
        _ => None,
    }
}

fn store_snapshot_route(path: &str) -> Option<String> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "store", "projects", project, "snapshot"] => Some(url_decode(project)),
        _ => None,
    }
}

fn profiles_collection_route(path: &str) -> Option<String> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, "profiles"] => Some(url_decode(project)),
        _ => None,
    }
}

fn profile_policy_route(path: &str) -> Option<(String, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, "profiles", profile] => {
            Some((url_decode(project), url_decode(profile)))
        }
        _ => None,
    }
}

fn profile_env_route(path: &str) -> Option<(String, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, "profiles", profile, "env"] => {
            Some((url_decode(project), url_decode(profile)))
        }
        _ => None,
    }
}

fn project_action_route(path: &str) -> Option<(String, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "projects", project, action] if *action == "lock" || *action == "remove" => {
            Some((url_decode(project), (*action).to_string()))
        }
        _ => None,
    }
}

fn notification_action_route(path: &str) -> Option<(uuid::Uuid, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "notifications", notification_id, action] if *action == "dismiss" => Some((
            uuid::Uuid::parse_str(notification_id).ok()?,
            (*action).to_string(),
        )),
        _ => None,
    }
}

fn approval_action_route(path: &str) -> Option<(uuid::Uuid, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "approvals", request_id, action] if *action == "approve" || *action == "deny" => {
            Some((
                uuid::Uuid::parse_str(request_id).ok()?,
                (*action).to_string(),
            ))
        }
        _ => None,
    }
}

fn worktree_action_route(path: &str) -> Option<(uuid::Uuid, String)> {
    let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["api", "worktrees", request_id, action] if *action == "approve" || *action == "deny" => {
            Some((
                uuid::Uuid::parse_str(request_id).ok()?,
                (*action).to_string(),
            ))
        }
        _ => None,
    }
}

fn url_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                if let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        out.push(byte);
                        index += 3;
                        continue;
                    }
                }
                out.push(bytes[index]);
                index += 1;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
