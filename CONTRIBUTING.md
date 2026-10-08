# Contributing

Start with [development](docs/development.md) and [architecture](docs/architecture.md).
Use the active mainline as the base and keep one concrete change per pull request.
Discuss new public tools, device writes, dependencies or architecture changes in
an issue before expanding their scope.

Include the problem, resulting behavior and relevant validation in the pull
request. Describe what was tested locally, in a package, in a real AI client and
on a device separately. A cross-compiled binary is not native runtime evidence.

Follow [testing](docs/testing.md). Preserve existing failed-case regressions and
update contracts with behavior changes. Tests should exercise externally useful
behavior, request recovery and failure handling rather than copy implementation
details.

Keep the English and Simplified Chinese entry documents in sync in the same
change: `README.md` / `README.zh-CN.md`, and the `installation`, `getting-started`
and `mcp` pages under `docs/` with their `.zh-CN.md` counterparts. Match their
capabilities, prerequisites, commands and validation limits. Keep executable
examples and interface identifiers identical, use same-language navigation
where a translation exists, and label links to untranslated English guides in
the Chinese pages. Run `python3 scripts/check-docs.py` after documentation changes.

Keep current user and developer instructions in `docs/`. Keep temporary plans,
credentials, device captures, private request files, runtime databases and local
evidence outside the tracked tree. Use issues and pull requests for reviewable
work; do not add a new tracked scratch tracker or candidate diary.

Submit only material you may distribute. Contributions are provided under the
repository's [Apache-2.0 license](LICENSE), subject to any explicit separate
agreement. Preserve third-party notices and identify added dependencies.

Do not include vulnerabilities or credentials in public issues; follow
[SECURITY.md](SECURITY.md).
