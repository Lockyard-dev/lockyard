# Several repositories in one cloud workspace

Use a stable, explicit ID in each project's `.lockyard/config.toml`:

```toml
mode = "cloud"
url = "https://your-server.example"
workspace = "your-team"
repository = "api"
```

IDs contain 1–64 lowercase ASCII letters, digits, dots, underscores or hyphens, starting with a letter
or digit. The ID does not depend on the absolute checkout path or machine. Every agent working on the
same logical repository uses the same ID; another repository uses a different ID. Separate worktrees
with the same ID coordinate the same logical paths.

The workspace keeps common tasks, messages and presence. Zones, dirty paths, wait queues and zone
catalogs are repository-scoped: `src/api` in `api` and `src/api` in `web` are independent. The same
path in two checkouts of `api` conflicts. A repository-wide root claim does not claim other repositories.

Existing configurations without an ID use the legacy namespace. Changing the ID changes the
coordination namespace; release active leases and update collaborating clients together. Configure
all participants consistently rather than mixing explicit IDs with legacy coordination for one checkout.

Repository-scoped calls check server capability before accepting a cache result. An old server or
daemon cannot assert that a namespaced path is free. Hooks deny edits when coordination is unknown
or a zone check fails. Mail and presence failures remain nonblocking. This is cooperative
coordination, not filesystem access control. Token roles and workspace authorization remain separate.

The `.lockyard-repository` top-level path is reserved for protocol addresses and cannot be selected
as an ordinary physical project path. CLI and web views display repository labels and project-relative paths.
