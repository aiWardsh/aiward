#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub display: String,
    pub argv: Vec<String>,
}

impl CommandSpec {
    pub fn from_profile_command(command: &str) -> Self {
        Self {
            display: command.to_string(),
            argv: command
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        }
    }

    pub fn from_args(args: Vec<String>) -> Self {
        Self {
            display: args.join(" "),
            argv: args,
        }
    }
}
