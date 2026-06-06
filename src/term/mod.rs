use std::{io::IsTerminal, path::Path, time::Duration};

use indicatif::{ProgressBar, ProgressStyle};

const SPINNER_FRAMES: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
const TICK_MS: u64 = 80;
const PAD: &str = "  ";
const LABEL_WIDTH: usize = 22;
const DEFAULT_OUTPUT_WIDTH: usize = 88;
const MIN_OUTPUT_WIDTH: usize = 40;
const MIN_DETAIL_WIDTH: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderMode {
    Rich,
    NoColor,
    Plain,
}

impl RenderMode {
    pub fn detect() -> Self {
        if std::env::var_os("NO_COLOR").is_some() {
            Self::NoColor
        } else if std::io::stderr().is_terminal() {
            Self::Rich
        } else {
            Self::Plain
        }
    }

    fn symbol(self, level: StatusLevel) -> &'static str {
        match self {
            Self::Plain => match level {
                StatusLevel::Ok => "OK",
                StatusLevel::Warn => "!!",
                StatusLevel::Error => "XX",
                StatusLevel::Info => "--",
            },
            Self::Rich | Self::NoColor => match level {
                StatusLevel::Ok => "✓",
                StatusLevel::Warn => "!",
                StatusLevel::Error => "✕",
                StatusLevel::Info => "·",
            },
        }
    }

    fn arrow(self) -> &'static str {
        match self {
            Self::Plain => "->",
            Self::Rich | Self::NoColor => "→",
        }
    }

    fn brand(self) -> &'static str {
        match self {
            Self::Plain => "*",
            Self::Rich | Self::NoColor => "◆",
        }
    }

    fn accent(self, value: &str) -> String {
        if self == Self::Rich {
            format!("\x1b[38;5;99m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    }

    fn ok(self, value: &str) -> String {
        if self == Self::Rich {
            format!("\x1b[32m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    }

    fn warn(self, value: &str) -> String {
        if self == Self::Rich {
            format!("\x1b[33m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    }

    fn error(self, value: &str) -> String {
        if self == Self::Rich {
            format!("\x1b[31m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    }

    fn dim(self, value: &str) -> String {
        if self == Self::Rich {
            format!("\x1b[2m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLevel {
    Ok,
    Warn,
    Error,
    Info,
}

#[derive(Debug, Clone)]
pub struct Header<'a> {
    pub command: Option<&'a str>,
    pub project: &'a str,
    pub path: Option<&'a Path>,
    pub mode: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct StatusLine<'a> {
    pub level: StatusLevel,
    pub label: &'a str,
    pub detail: Option<&'a str>,
}

impl<'a> StatusLine<'a> {
    pub fn ok(label: &'a str, detail: impl Into<Option<&'a str>>) -> Self {
        Self {
            level: StatusLevel::Ok,
            label,
            detail: detail.into(),
        }
    }

    pub fn warn(label: &'a str, detail: impl Into<Option<&'a str>>) -> Self {
        Self {
            level: StatusLevel::Warn,
            label,
            detail: detail.into(),
        }
    }

    pub fn error(label: &'a str, detail: impl Into<Option<&'a str>>) -> Self {
        Self {
            level: StatusLevel::Error,
            label,
            detail: detail.into(),
        }
    }

    pub fn info(label: &'a str, detail: impl Into<Option<&'a str>>) -> Self {
        Self {
            level: StatusLevel::Info,
            label,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyValue<'a> {
    pub key: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone)]
pub struct Section<'a> {
    pub label: &'a str,
    pub lines: &'a [StatusLine<'a>],
}

#[derive(Debug, Clone)]
pub struct SummaryTable<'a> {
    pub headers: &'a [&'a str],
    pub rows: &'a [&'a [&'a str]],
}

#[derive(Debug, Clone)]
pub struct NextSteps<'a> {
    pub steps: &'a [&'a str],
}

#[derive(Debug, Clone)]
pub struct MessageBlock<'a> {
    pub level: StatusLevel,
    pub title: &'a str,
    pub body: Option<&'a str>,
    pub command: Option<&'a str>,
}

pub fn header(project: &str) {
    emit_header(&Header {
        command: None,
        project,
        path: None,
        mode: None,
    });
}

pub fn header_cmd(cmd: &str, project: &str) {
    emit_header(&Header {
        command: Some(cmd),
        project,
        path: None,
        mode: None,
    });
}

pub fn guided_header(command: &str, project: &str, path: &std::path::Path, body: &str) {
    eprint!("{}", render_guided_header(command, project, path, body));
}

pub fn guided_context_header(
    command: &str,
    label: &str,
    name: &str,
    path: &std::path::Path,
    body: &str,
) {
    eprint!(
        "{}",
        render_guided_context_header(command, label, name, path, body)
    );
}

pub fn render_guided_header(
    command: &str,
    project: &str,
    path: &std::path::Path,
    body: &str,
) -> String {
    render_guided_context_header(command, "Project", project, path, body)
}

pub fn render_guided_context_header(
    command: &str,
    _label: &str,
    name: &str,
    path: &std::path::Path,
    body: &str,
) -> String {
    let mut out = render_header(
        RenderMode::NoColor,
        &Header {
            command: Some(command),
            project: name,
            path: Some(path),
            mode: None,
        },
    );
    out.push_str(&format!("{PAD}{body}\n\n"));
    out
}

pub fn section(label: &str) {
    eprintln!();
    eprint!("{}", render_section(RenderMode::detect(), label));
}

pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    let template = if RenderMode::detect() == RenderMode::Rich {
        format!("{PAD}{{spinner:.cyan}} {{msg}}")
    } else {
        format!("{PAD}{{spinner}} {{msg}}")
    };
    pb.set_style(
        ProgressStyle::with_template(&template)
            .unwrap()
            .tick_chars(SPINNER_FRAMES),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(TICK_MS));
    pb
}

pub fn done(pb: ProgressBar, msg: &str) {
    pb.finish_and_clear();
    emit_status(StatusLine::ok(msg, None));
}

pub fn done_detail(pb: ProgressBar, label: &str, detail: &str) {
    pb.finish_and_clear();
    emit_status(StatusLine::ok(label, Some(detail)));
}

pub fn warn_step(pb: ProgressBar, msg: &str) {
    pb.finish_and_clear();
    emit_status(StatusLine::warn(msg, None));
}

pub fn warn_step_detail(pb: ProgressBar, label: &str, detail: &str) {
    pb.finish_and_clear();
    emit_status(StatusLine::warn(label, Some(detail)));
}

pub fn ok(msg: &str) {
    emit_legacy_status(StatusLevel::Ok, msg);
}

pub fn ok_detail(label: &str, detail: &str) {
    emit_status(StatusLine::ok(label, Some(detail)));
}

pub fn fail(msg: &str) {
    emit_legacy_status(StatusLevel::Error, msg);
}

pub fn fail_detail(label: &str, detail: &str) {
    emit_status(StatusLine::error(label, Some(detail)));
}

pub fn info(msg: &str) {
    emit_legacy_status(StatusLevel::Info, msg);
}

pub fn info_detail(label: &str, detail: &str) {
    emit_status(StatusLine::info(label, Some(detail)));
}

pub fn warn(msg: &str) {
    emit_legacy_status(StatusLevel::Warn, msg);
}

pub fn warn_detail(label: &str, detail: &str) {
    emit_status(StatusLine::warn(label, Some(detail)));
}

fn emit_legacy_status(level: StatusLevel, msg: &str) {
    if let Some((label, detail)) = split_legacy_detail(msg) {
        emit_status(StatusLine {
            level,
            label,
            detail: Some(detail),
        });
    } else {
        emit_status(StatusLine {
            level,
            label: msg,
            detail: None,
        });
    }
}

fn split_legacy_detail(msg: &str) -> Option<(&str, &str)> {
    let idx = msg.find("  ")?;
    let (label, detail) = msg.split_at(idx);
    let detail = detail.trim();
    if label.trim().is_empty() || detail.is_empty() {
        None
    } else {
        Some((label.trim_end(), detail))
    }
}

pub fn blank() {
    eprintln!();
}

pub fn next(msg: &str) {
    eprint!("{}", render_next(RenderMode::detect(), msg));
}

pub fn command_hint(command: &str) {
    eprint!("{}", render_command_hint(RenderMode::detect(), command));
}

pub fn emit_header(header: &Header<'_>) {
    eprint!("{}", render_header(RenderMode::detect(), header));
}

pub fn emit_status(line: StatusLine<'_>) {
    eprint!("{}", render_status_line(RenderMode::detect(), &line));
}

pub fn emit_statuses(lines: &[StatusLine<'_>]) {
    eprint!("{}", render_status_lines(RenderMode::detect(), lines));
}

pub fn emit_key_values(rows: &[KeyValue<'_>]) {
    eprint!("{}", render_key_values(RenderMode::detect(), rows));
}

pub fn emit_section(section: &Section<'_>) {
    eprint!("{}", render_full_section(RenderMode::detect(), section));
}

pub fn emit_summary_table(table: &SummaryTable<'_>) {
    eprint!("{}", render_summary_table(RenderMode::detect(), table));
}

pub fn emit_next_steps(steps: &NextSteps<'_>) {
    eprint!("{}", render_next_steps(RenderMode::detect(), steps));
}

pub fn emit_block(block: &MessageBlock<'_>) {
    eprint!("{}", render_message_block(RenderMode::detect(), block));
}

pub fn render_header(mode: RenderMode, header: &Header<'_>) -> String {
    let mut parts = vec!["ward".to_string()];
    if let Some(command) = header.command {
        parts.push(command.to_string());
    }
    parts.push(header.project.to_string());
    if let Some(mode_name) = header.mode {
        parts.push(mode_name.to_string());
    }

    let mut out = String::new();
    out.push('\n');
    out.push_str(PAD);
    out.push_str(&mode.accent(mode.brand()));
    out.push(' ');
    out.push_str(&parts.join(" · "));
    out.push('\n');
    if let Some(path) = header.path {
        out.push_str(PAD);
        out.push_str("  ");
        out.push_str(&mode.dim("path"));
        out.push_str("  ");
        out.push_str(&short_path(path));
        out.push('\n');
    }
    out.push('\n');
    out
}

pub fn render_section(mode: RenderMode, label: &str) -> String {
    format!("\n{PAD}{}\n", mode.dim(label))
}

pub fn render_status_lines(mode: RenderMode, lines: &[StatusLine<'_>]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(&render_status_line(mode, line));
    }
    out
}

pub fn render_status_line(mode: RenderMode, line: &StatusLine<'_>) -> String {
    render_status_line_at_width(mode, line, output_width())
}

fn render_status_line_at_width(mode: RenderMode, line: &StatusLine<'_>, width: usize) -> String {
    let raw_symbol = mode.symbol(line.level);
    let symbol = match line.level {
        StatusLevel::Ok => mode.ok(raw_symbol),
        StatusLevel::Warn => mode.warn(raw_symbol),
        StatusLevel::Error => mode.error(raw_symbol),
        StatusLevel::Info => mode.dim(raw_symbol),
    };
    let mut out = format!("{PAD}{symbol} {}", line.label);
    if let Some(detail) = line.detail {
        let padding = LABEL_WIDTH
            .saturating_sub(line.label.chars().count())
            .max(2);
        out.push_str(&" ".repeat(padding));
        let indent_width = PAD.chars().count()
            + raw_symbol.chars().count()
            + 1
            + line.label.chars().count()
            + padding;
        let wrap_width = detail_width(width, indent_width);
        let wrapped = wrap_text(detail, wrap_width);
        if let Some((first, rest)) = wrapped.split_first() {
            out.push_str(&mode.dim(first));
            out.push('\n');
            let continuation = " ".repeat(indent_width);
            for line in rest {
                out.push_str(&continuation);
                out.push_str(&mode.dim(line));
                out.push('\n');
            }
            return out;
        }
    }
    out.push('\n');
    out
}

pub fn render_key_values(mode: RenderMode, rows: &[KeyValue<'_>]) -> String {
    render_key_values_at_width(mode, rows, output_width())
}

fn render_key_values_at_width(
    mode: RenderMode,
    rows: &[KeyValue<'_>],
    output_width: usize,
) -> String {
    let mut out = String::new();
    let width = rows
        .iter()
        .map(|row| row.key.chars().count())
        .max()
        .unwrap_or(0)
        .max(8);
    for row in rows {
        out.push_str(PAD);
        out.push_str("  ");
        out.push_str(&mode.dim(row.key));
        let padding = width.saturating_sub(row.key.chars().count()) + 2;
        out.push_str(&" ".repeat(padding));
        let indent_width = PAD.chars().count() + 2 + row.key.chars().count() + padding;
        let wrap_width = detail_width(output_width, indent_width);
        let wrapped = wrap_text(row.value, wrap_width);
        if let Some((first, rest)) = wrapped.split_first() {
            out.push_str(first);
            out.push('\n');
            let continuation = " ".repeat(indent_width);
            for line in rest {
                out.push_str(&continuation);
                out.push_str(line);
                out.push('\n');
            }
        } else {
            out.push('\n');
        }
    }
    out
}

pub fn render_full_section(mode: RenderMode, section: &Section<'_>) -> String {
    let mut out = render_section(mode, section.label);
    out.push_str(&render_status_lines(mode, section.lines));
    out
}

pub fn render_summary_table(mode: RenderMode, table: &SummaryTable<'_>) -> String {
    if table.headers.is_empty() {
        return String::new();
    }
    let column_count = table.headers.len();
    let mut widths = table
        .headers
        .iter()
        .map(|header| header.chars().count())
        .collect::<Vec<_>>();
    for row in table.rows {
        for (idx, cell) in row.iter().take(column_count).enumerate() {
            widths[idx] = widths[idx].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    out.push_str(PAD);
    out.push_str("  ");
    for (idx, header) in table.headers.iter().enumerate() {
        if idx > 0 {
            out.push_str("  ");
        }
        out.push_str(&mode.dim(&format!("{header:<width$}", width = widths[idx])));
    }
    out.push('\n');

    for row in table.rows {
        out.push_str(PAD);
        out.push_str("  ");
        for idx in 0..column_count {
            if idx > 0 {
                out.push_str("  ");
            }
            let cell = row.get(idx).copied().unwrap_or("");
            out.push_str(&format!("{cell:<width$}", width = widths[idx]));
        }
        out.push('\n');
    }
    out
}

pub fn render_next(mode: RenderMode, msg: &str) -> String {
    format!("{PAD}{} next: {msg}\n", mode.arrow())
}

pub fn render_command_hint(_mode: RenderMode, command: &str) -> String {
    format!("{PAD}  {command}\n",)
}

pub fn render_next_steps(mode: RenderMode, steps: &NextSteps<'_>) -> String {
    let mut out = render_section(mode, "next");
    for step in steps.steps {
        out.push_str(&render_next(mode, step));
    }
    out
}

pub fn render_message_block(mode: RenderMode, block: &MessageBlock<'_>) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&render_status_line(
        mode,
        &StatusLine {
            level: block.level,
            label: block.title,
            detail: None,
        },
    ));
    if let Some(body) = block.body {
        let indent = format!("{PAD}  ");
        for line in wrap_text(body, detail_width(output_width(), indent.chars().count())) {
            out.push_str(&indent);
            out.push_str(&line);
            out.push('\n');
        }
    }
    if let Some(command) = block.command {
        out.push_str(&render_next(mode, command));
    }
    out
}

fn output_width() -> usize {
    std::env::var("WARD_TERM_WIDTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .or_else(|| {
            crossterm::terminal::size()
                .ok()
                .map(|(columns, _)| usize::from(columns))
        })
        .unwrap_or(DEFAULT_OUTPUT_WIDTH)
        .clamp(MIN_OUTPUT_WIDTH, 240)
}

fn detail_width(output_width: usize, indent_width: usize) -> usize {
    output_width
        .saturating_sub(indent_width)
        .max(MIN_DETAIL_WIDTH)
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    for raw_line in text.lines() {
        if raw_line.is_empty() {
            lines.push(String::new());
            continue;
        }
        lines.extend(wrap_single_line(raw_line, width));
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn wrap_single_line(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if char_count(word) > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let chunks = split_long_token(word, width);
            let last_idx = chunks.len().saturating_sub(1);
            for (idx, chunk) in chunks.into_iter().enumerate() {
                if idx == last_idx {
                    current = chunk;
                } else {
                    lines.push(chunk);
                }
            }
        } else if current.is_empty() {
            current.push_str(word);
        } else if char_count(&current) + 1 + char_count(word) <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn split_long_token(token: &str, width: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for ch in token.chars() {
        if current.chars().count() >= width {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn char_count(value: &str) -> usize {
    value.chars().count()
}

/// Shorten an absolute path for display — keep last 2 segments.
pub fn short_path(p: &std::path::Path) -> String {
    let parts: Vec<_> = p.components().collect();
    if parts.len() <= 3 {
        return p.display().to_string();
    }
    let tail: std::path::PathBuf = parts[parts.len() - 2..].iter().collect();
    format!("…/{}", tail.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_path_keeps_tail_segments() {
        assert_eq!(
            short_path(std::path::Path::new("/Users/me/project")),
            "…/me/project"
        );
    }

    #[test]
    fn guided_header_includes_command_project_path_and_body() {
        let rendered = render_guided_header(
            "setup",
            "demo",
            std::path::Path::new("/Users/me/demo"),
            "Ward will encrypt your local env, create a vault, and prepare this project for safe human and agent access.",
        );

        assert!(rendered.contains("◆ ward · setup · demo"));
        assert!(rendered.contains("path  …/me/demo"));
        assert!(rendered.contains("encrypt your local env"));
    }

    #[test]
    fn guided_context_header_supports_workspace_label() {
        let rendered = render_guided_context_header(
            "setup",
            "Workspace",
            "cms-core",
            std::path::Path::new("/Users/me/cms-core"),
            "Ward detected a monorepo workspace.",
        );

        assert!(rendered.contains("◆ ward · setup · cms-core"));
        assert!(rendered.contains("path  …/me/cms-core"));
    }

    #[test]
    fn status_lines_align_labels_and_details() {
        let rendered = render_status_lines(
            RenderMode::NoColor,
            &[
                StatusLine::ok("vault encrypted", Some(".env -> .env.vault")),
                StatusLine::warn("session", Some("not started")),
                StatusLine::error("broker", Some("unavailable")),
            ],
        );

        assert!(rendered.contains("✓ vault encrypted"));
        assert!(rendered.contains(".env -> .env.vault"));
        assert!(rendered.contains("! session"));
        assert!(rendered.contains("✕ broker"));
    }

    #[test]
    fn status_detail_wraps_with_detail_column_indent() {
        let rendered = render_status_line_at_width(
            RenderMode::NoColor,
            &StatusLine::ok(
                "ward",
                Some(
                    "kind=app project=cms-core:ward env=Present setup=Configured envNames=11 path=apps/aiward",
                ),
            ),
            64,
        );
        let lines = rendered.lines().collect::<Vec<_>>();

        assert!(lines.len() > 1);
        assert!(lines[0].starts_with("  ✓ ward"));
        let expected_indent = " ".repeat(26);
        for continuation in &lines[1..] {
            assert!(
                continuation.starts_with(&expected_indent),
                "continuation did not preserve detail column: {continuation:?}"
            );
        }
        assert!(rendered.contains("envNames=11"));
    }

    #[test]
    fn key_value_detail_wraps_with_value_column_indent() {
        let rendered = render_key_values_at_width(
            RenderMode::NoColor,
            &[KeyValue {
                key: "config",
                value: "unavailable: failed to read /Users/example/projects/cms-core/.ward.json",
            }],
            52,
        );
        let lines = rendered.lines().collect::<Vec<_>>();

        assert!(lines.len() > 1);
        assert!(lines[0].starts_with("    config"));
        for continuation in &lines[1..] {
            assert!(
                continuation.starts_with("            "),
                "continuation did not preserve value column: {continuation:?}"
            );
        }
    }

    #[test]
    fn rich_mode_adds_color_and_no_color_does_not() {
        let rich = render_status_line(
            RenderMode::Rich,
            &StatusLine::ok("vault encrypted", Some(".env -> .env.vault")),
        );
        let no_color = render_status_line(
            RenderMode::NoColor,
            &StatusLine::ok("vault encrypted", Some(".env -> .env.vault")),
        );

        assert!(rich.contains("\x1b[32m"));
        assert!(!no_color.contains("\x1b["));
    }

    #[test]
    fn plain_mode_uses_ascii_status_symbols() {
        let rendered = render_status_line(
            RenderMode::Plain,
            &StatusLine::ok("vault encrypted", Some(".env -> .env.vault")),
        );

        assert!(rendered.contains("OK vault encrypted"));
        assert!(!rendered.contains('✓'));
    }

    #[test]
    fn message_block_renders_remediation_command() {
        let rendered = render_message_block(
            RenderMode::NoColor,
            &MessageBlock {
                level: StatusLevel::Warn,
                title: "human mode is not active",
                body: Some("project commands are protected"),
                command: Some("ward human"),
            },
        );

        assert!(rendered.contains("! human mode is not active"));
        assert!(rendered.contains("project commands are protected"));
        assert!(rendered.contains("→ next: ward human"));
    }

    #[test]
    fn section_summary_table_and_next_steps_render_cleanly() {
        let section = render_full_section(
            RenderMode::NoColor,
            &Section {
                label: "vault",
                lines: &[StatusLine::ok(
                    "vault encrypted",
                    Some(".env -> .env.vault"),
                )],
            },
        );
        let table = render_summary_table(
            RenderMode::NoColor,
            &SummaryTable {
                headers: &["project", "session"],
                rows: &[&["api", "active"], &["web", "locked"]],
            },
        );
        let next = render_next_steps(
            RenderMode::NoColor,
            &NextSteps {
                steps: &["exec $SHELL && ward human", "ward dashboard start"],
            },
        );

        assert!(section.contains("vault"));
        assert!(section.contains("✓ vault encrypted"));
        assert!(table.contains("project"));
        assert!(table.contains("api"));
        assert!(next.contains("→ next: exec $SHELL && ward human"));
        assert!(next.contains("→ next: ward dashboard start"));
    }

    #[test]
    fn legacy_double_space_messages_split_into_label_and_detail() {
        assert_eq!(
            split_legacy_detail(".ward.json  …/app/.ward.json"),
            Some((".ward.json", "…/app/.ward.json"))
        );
        assert_eq!(split_legacy_detail("all good"), None);
    }

    #[test]
    fn guided_copy_fragments_are_stable() {
        let setup = "Ward will encrypt your local env, create a vault, and prepare this project for safe human and agent access.";
        let human = "This terminal is now protected. Normal commands in this Ward project will receive vault envs through Ward while this session is active.";

        assert!(setup.contains("encrypt your local env"));
        assert!(setup.contains("safe human and agent access"));
        assert!(human.contains("This terminal is now protected"));
        assert!(human.contains("while this session is active"));
    }
}
