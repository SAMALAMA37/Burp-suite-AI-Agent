# ai burp

A super duper extra extension that makes AI do most things that you can do

it integrates most of the current AI type cybersec capabilities, + more

Its very good at reading and analysing client side code, and can extract a ton of information from it.




everything below is written by ai:

## Features

- Conversation workspace with tool activity, pause/resume, and live guidance.
- Source workbench for website JavaScript collection, text search, and optional semantic search.
- Investigation board and discovery lab with hypotheses, counterevidence, controlled experiments, and retained evidence.
- Markdown documents and mind maps with an embedded sanitized document viewer.
- Local Connection Hub for configurable model providers.
- Optional WSL terminal bridge and experimental 9Router integration.

See the [full user guide](README_BurpAI_v4_5.md) for controls, workflows, limits, and examples.

## Requirements

- Burp Suite with support for Python extensions and a compatible Java runtime.
- Jython standalone **2.7.4**, downloaded by setup when missing.
- Python **3.11 or newer** for setup and local services. The extension itself uses Jython 2.7, not CPython 3.
- A configured model provider. Provider credentials are supplied locally.
- Optional: Ollama with `embeddinggemma` for local semantic search; WSL with Python 3 for the terminal bridge; Node.js 24 for 9Router.

## Install

1. Download and extract the repository or a release source ZIP. Keep the companion modules and subdirectories together.
2. From the extracted directory, run:

   ```sh
   python setup_burpai.py --files-only
   ```

   On Windows, use `py -3` if `python` is unavailable. This prepares files and Jython without starting services or changing provider settings.
3. In Burp's **Extensions** settings, set the Python environment to the downloaded `jython-standalone-2.7.4.jar`.
4. Add a **Python** extension and select `BurpAI_v4_Extension.py`.
5. To configure chat through Connection Hub, run:

   ```sh
   python setup_burpai.py
   ```

   Setup opens the local dashboard and connects the BurpAI profile. Configure a provider and model there, then reload the extension. Add `--with-embeddings` only when you want setup to prepare local semantic search.

Use `python setup_burpai.py --files-only --check` to check the installed files. Model access, quota, and availability depend on your provider.

**Windows shortcuts:** `Restore Connection Hub.cmd` starts Connection Hub. The existing `Launch Hub.cmd` shortcut starts the optional **9Router** integration; complete its [separate setup](docs/9ROUTER.md) first.

## Data and execution

Model requests can contain selected traffic, source code, notes, and tool results. Choose providers appropriate for the data you process. Local services bind to loopback; keep their tokens and state private. Configure Burp scope and request budgets before running experiments against systems you are authorized to test. The WSL terminal can execute commands and access its configured workspace.

See [security and data handling](SECURITY.md). Findings are hypotheses until supported by evidence; model output is not a substitute for verification.

## Development

```sh
python -m unittest discover -s tests -p "test_*.py" -v
```

The test suite uses synthetic fixtures and local services. Manual live checks are separate. See [CONTRIBUTING.md](CONTRIBUTING.md) for Jython and viewer checks, and [publishing instructions](docs/PUBLISHING.md) for repository and release preparation.

## Project layout

| Path | Purpose |
| --- | --- |
| `BurpAI_v4_Extension.py` | Burp entry point and interface |
| `BurpAI_v4_*.py` | Source, evidence, documents, lab, semantic, workspace and WSL modules |
| `provider_hub/` | Python service, provider catalog and dashboard |
| `document_viewer/` | Viewer assets and third-party license notices |
| `nine_router/` | Optional pinned 9Router launcher and priority page |
| `burpai_wsl_runner.py` | WSL command helper |
| `tests/` | Regression and smoke checks |
| `scripts/` | Source release packaging |

## License and third-party software

No project-wide license has been selected. Publication alone does not grant an open-source license; the owner must select one before representing this project as open source. Third-party components retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
