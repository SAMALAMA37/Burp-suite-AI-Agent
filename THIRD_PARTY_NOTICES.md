# Third-party components

- The bundled document viewer uses Marked and DOMPurify. Exact versions and integrity metadata are in `document_viewer/dependencies.json`; their license texts are retained in `document_viewer/LICENSES.txt`.
- Jython 2.7.4 is downloaded separately by setup and is not included in source releases. Its distribution contains its own licensing notices.
- The optional 9Router package is pinned to 0.5.112 in `nine_router/package.json` and its lockfile. It is installed separately; its upstream licenses and notices apply. The launcher modifies assets of that specific installed build.
- `tests/viewer` uses jsdom for development checks, installed separately.
- Connection Hub's provider catalog cites `https://github.com/mnfst/awesome-free-llm-apis` as its source. Provider listings are informational snapshots, not guarantees of availability, pricing, or permission to use a service.

Burp Suite, model-provider services, Ollama, and Node.js are external requirements, not bundled project code. Their respective terms and licenses apply. These notices do not assign a license to BurpAI's own code.
