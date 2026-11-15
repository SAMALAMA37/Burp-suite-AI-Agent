# Security and data handling

Use BurpAI only on systems you are authorized to assess. Review scope, automatic request settings, and tool execution settings before use.

## Local and remote data

- Model providers may receive selected requests/responses, source code, prompts, notes, and tool output.
- Provider configuration is stored locally, including the user profile `.burpai_config.json` and service `.state` directories. Never publish these files.
- Connection Hub protects saved credentials with Windows DPAPI on Windows. On other platforms its `local:` encoding is base64, **not encryption**; filesystem permissions are important.
- Logs, captured traffic, session data, and exported documents may contain sensitive information. Review before sharing.
- WSL commands are real commands with network access controlled by the configured execution policy. Review them accordingly.

The repository excludes local state and generated artifacts. Exclusion rules do not replace a review of every staged change before publishing.

## Reporting a vulnerability

Use the repository's private vulnerability reporting feature if enabled. Otherwise request a private contact channel from the owner without posting exploit details, credentials, or target data in a public issue. No response-time guarantee or security audit is claimed.
