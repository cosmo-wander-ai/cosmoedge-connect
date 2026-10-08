# Decision: one service with local MCP and host workflows

Status: accepted for the local integration architecture.

The product keeps one connection owner and one implementation of the three
business operations. A separate stdio MCP adapter maps those operations to tools,
contexts and native content. The WorkBuddy integration uses a paired Python
client for its native Skill and attachment workflow.

This keeps device execution, request recovery, artifacts and confirmation rules
shared across clients. Skill guidance improves name/date interpretation,
follow-ups and explanations but does not own the only enforcement of an
execution rule.

Official service and adapter are matched release artifacts. Third-party clients
use MCP without matching the source commit. The internal HTTP API is not an
additional promised public compatibility surface.

Explicit local business contexts are the initial isolation boundary. They do not
claim trusted host conversation identity. Multiple adapter processes can share
a private journal; separate journal roots are an organizational option. A shared
journal still requires explicit independent business contexts. Remote HTTP,
multi-user identity and phone confirmation remain separate
work requiring a new acceptance matrix.

Keep the constraints and reasoning behind active contracts in decision records
and reproducible diagnostics in the [troubleshooting guide](../troubleshooting.md).
Live schemas, examples and regression fixtures remain where the code consumes
them. Superseded process notes are not part of the public documentation.
