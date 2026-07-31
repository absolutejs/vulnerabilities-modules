# AbsoluteJS Vulnerability Modules

Optional first-party modules for
[`@absolutejs/vulnerabilities`](https://github.com/absolutejs/vulnerabilities).
Each module remains an independently versioned npm package; this repository is
their source monorepo.

## Packages

| Workspace  | Package                               | Role                                                |
| ---------- | ------------------------------------- | --------------------------------------------------- |
| `report/`  | `@absolutejs/vulnerabilities-report`  | Deterministic evidence-backed reporting             |
| `worker/`  | `@absolutejs/vulnerabilities-worker`  | Continuous vulnerability intelligence orchestration |
| `witness/` | `@absolutejs/vulnerabilities-witness` | Independently deployable transparency witness       |

## Development

```sh
bun install
bun run typecheck
bun run test
bun run build
```

The Witness container remains independently deployable. Its package-local lock
file is retained so `witness/Dockerfile` can build from the `witness/` context.
Each workspace retains its own license and changelog.
