# Security

CosmoEdge Connect runs as the current local user and connects to one selected CosmoEdge
device. Its service binds to loopback. The MCP adapter is intended for a trusted
local client launched by that same user. Do not expose the internal HTTP port
through a public listener, reverse proxy or tunnel.

Device credentials belong in the local connection flow and protected state.
Do not put passwords, access tokens, private device addresses, stream URLs or
raw device responses in issues, source files, command arguments or logs. Share
only redacted diagnostics and the candidate version when reporting a problem.

MCP tool approval is permission to call a tool. It does not replace the product's
business confirmation for device changes. A proposal must retain its exact
target and settings; uncertain execution is queried using the same operation,
not repeated with a new request identity.

Protect the installation's token, runtime databases, request state and artifacts
with current-user permissions. A context reference scopes objects within that
local installation; it is not an authentication system for multiple untrusted
users. Multi-user and remote MCP hosting require a separate design.

To report a suspected vulnerability, use the repository's private
[Report a vulnerability](https://github.com/cosmo-wander-ai/cosmoedge-connect/security/advisories/new)
form. Include the affected version, impact and a minimal sanitized reproduction.
Do not post vulnerabilities, device details or credentials in public issues.

During the alpha period, fixes target the latest published alpha and `main`.
Older alpha versions do not receive separate backports. No fixed response-time
or long-term support commitment is announced. Consult the release notes and
compatibility matrix before deploying a particular build.
