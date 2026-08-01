# Ward Local Documentation

This directory is excluded from crates.io packaging because it can contain
internal product notes, implementation maps, scripts, and operational guidance
that should not be published. Most files here are local-only and ignored by git;
this README is a lightweight orientation for anyone who opens the folder.

Keep the public `README.md` accurate for users. It is the canonical source for
Ward's current API-derived vault infrastructure, global off/on behavior,
registry model, monorepo execution behavior, and key API deployment boundary.

Keep these local docs accurate for development, security review,
implementation planning, and future agent handoffs. Because this directory is
local-only, files here may contain internal notes or historical implementation
details. When anything conflicts with the public product flow, use the root
`README.md`.
