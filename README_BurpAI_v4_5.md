# BurpAI v4.5 — Website Analyse

Download a website's discoverable JavaScript to local files, then search the actual code by meaning. This extends `BurpAI_v4_Extension.py`; the existing agent, JS KB, research engine, and captured-source analysis remain available.

## 9Router chat priority

Open **Provider Priority** at the top of the [9Router dashboard](http://127.0.0.1:20128/dashboard/). Choose the provider you want tried first and click **Save provider priority**. If the provider is new to the combo, choose which model to add. This moves that provider's routes to the front of BurpAI's chat combo while keeping the rest in their existing fallback order. The combo needs to use the **Fallback** strategy.

## The workspace

The interface uses one midnight palette, soft rounded controls, clear keyboard focus, quieter tables, and a grouped navigation rail. **Conversation**, **Testing lab**, **Investigation**, **Source workbench**, and **Notes & maps** sit together at the top. Evidence and diagnostic pages remain directly accessible below them. Source workbench opens the existing Website Analyse tools; internal tab indexes and tool destinations are preserved.

The conversation has a centered reading column, distinct message roles, a spacious composer, and contextual Pause/Resume and Stop controls during a run. Starter buttons append to your draft without sending or overwriting it. Draft editing supports undo and redo. Empty messages are disabled. Incoming messages preserve your reading position; **Jump to latest** shows how many updates arrived while you were reading earlier content. Saving settings displays a quiet, dismissible confirmation instead of a blocking dialog.

| Shortcut | Action |
| --- | --- |
| **Ctrl+K** | Search and switch workspace pages. Type a page name or terms such as `traffic`, `code`, or `experiments`. |
| **Up / Down, Enter, Escape** | Choose, open, or close the quick switcher. |
| **Ctrl+L** | Return to the conversation and focus your draft. |
| **Enter / Shift+Enter** | Send a message / insert a new line. |
| **Ctrl+Z / Ctrl+Y or Ctrl+Shift+Z** | Undo / redo draft edits. |
| **Escape in the lab filter** | Clear the search and show all items. |

The discovery lab has live text filtering, separate lead/experiment filters, readable status labels, and a selected-record view beside the results on wide screens. It stacks the views in smaller windows. Empty and no-match states explain the next action. Selecting a record surfaces its question, falsifier, next step and evidence. Refreshing the same record preserves the detail scroll position. Completed experiments offer explanation and evidence rather than another Run action. Investigation details use the same typographic hierarchy, emphasizing the question and next step.

Reload `BurpAI_v4_Extension.py` to activate the interface. It requires the v4.5 companion modules, including `BurpAI_v4_Lab.py`, `BurpAI_v4_Investigation.py`, and `BurpAI_v4_LocalTools.py`. The isolated Jython smoke test constructs the actual Swing pages and exercises navigation, shortcuts, filtering, draft editing, native card clicks, run states, and rendered wide/compact layouts without making network requests.

## Local Tools

### Direct WSL bridge

**Local Tools > WSL terminal** now runs real Linux commands for both you and the agent. The bridge uses `wsl.exe` to launch Python 3 in your selected distribution and executes commands in a bubblewrap sandbox. There is no listening service or unsandboxed fallback.

1. Keep `BurpAI_v4_WSL.py` and `burpai_wsl_runner.py` beside the extension and its other modules, then reload `BurpAI_v4_Extension.py` in Burp.
2. In your normal Kali/Ubuntu/Debian WSL terminal, install prerequisites if missing: `sudo apt install bubblewrap python3`. Use a non-root WSL user. WSL 2 with working unprivileged user namespaces is required; the connection check reports sandbox setup failures.
3. Open **Local Tools > WSL terminal**, click **Detect**, select your distro, and optionally enter the Linux username. Click **Connect**. Connection verifies the sandbox, a writable workspace, and a read-only system mount. Distro/user preferences persist; execution permission resets when Burp reloads.
4. **Enable network for this connection** is selected by default. The terminal and agent can access the internet through installed tools such as `curl`, `wget` and Python. Leave **Optional in-scope test target URL** blank for general web research or downloads; enter the authorized URL in Burp scope when testing a target. **Ask agent** adds a prompt to your conversation draft that reflects whether you entered a test target.
5. Agent commands inherit the connection's network setting. Omit `target_url` for general web access; supply it for vulnerability testing. Supplied target URLs are checked against Burp scope before network-enabled execution. Use `network=false` for an individual offline agent command. To make the entire connection offline, clear **Enable network for this connection** and reconnect. The supplied `pwd` / tool-location example also works offline.

For a simple internet check, leave the optional test target blank and run `curl -I --max-time 15 https://example.com`. This makes an ordinary HTTPS request and returns response headers to the terminal or agent. Downloads can be saved under `/workspace`; Linux system mounts remain read-only. A successful sandbox connection alone does not verify internet connectivity or DNS.

| Agent tool | What it does |
| --- | --- |
| `wsl_status` | Reads connection, running state, distro, workspace and network permission. |
| `wsl_list_tools` | Finds installed executables and paths, with name filtering and pagination. |
| `wsl_exec` | Runs Bash commands, pipelines, heredocs or saved scripts; returns stdout, stderr, exit code, duration, timeout and cancellation state. |
| `wsl_write_file` | Creates UTF-8 scripts/data under `/workspace`; overwriting requires `overwrite=true`. |
| `wsl_read_file` | Reads bounded pages of result files; byte offsets allow continuation. |
| `wsl_list_files` | Lists workspace files and directories with pagination. |

Commands start in `/workspace` unless a relative `cwd` is supplied. Each run has a fresh noninteractive shell; files persist, shell variables and `cd` do not. The real Linux directory is `~/.burpai-wsl/workspace`, shown after connection. Use `python3 test.py` or `bash test.sh` for saved scripts. File tools reject traversal, symlinks and special files; writes default to creating new files. Tool output enters the configured model's context and normal BurpAI evidence history when the agent invokes tools, so only put data intended for that workflow into the workspace.

The sandbox exposes `/usr`, `/bin`, `/sbin`, Linux libraries and `/opt` read-only, plus selected DNS/TLS/runtime configuration. User tool folders (`~/.local/bin`, `~/.local/lib`, pipx environments and `~/go`) are mounted read-only when present and not redirected through symlinks. Private home files, Windows drives, WSL interop sockets, host process listings and host `/run` are not mounted. `/workspace` persists and `/tmp` is ephemeral. Dependencies that require additional host configuration, root/raw sockets, services or a TTY may not work; for example use Nmap's unprivileged TCP connect mode when appropriate. Python environments can be created in `/workspace`.

**Network permission is connectivity, not an egress allowlist.** General internet commands do not need a declared test target. The adapter checks a supplied target URL against Burp scope, but cannot enforce target destinations inside arbitrary shell commands/scripts or identify testing from command text. The agent is instructed to declare its authorized target for vulnerability testing; this is not a network enforcement boundary. Enabled commands share WSL networking and may reach other hosts or local services. External tools bypass Burp's proxy, per-request scope checks, request budget and pacing; configure each tool's target, concurrency and rate explicitly. For HTTP experiments that need Burp's enforcement and captured sessions, use the existing Testing lab tools.

Only one bridge operation runs at a time. **Stop command**, the agent's **Stop**, **Kill Switch**, disconnect and extension unload cancel the active operation. The open stdin pipe acts as the cancellation channel to the Linux supervisor, which polls it without a background buffered read and terminates the process group and sandbox PID namespace on EOF. This lets successful probes and commands exit cleanly while Burp still holds the pipe open. JSON responses and helper diagnostics use separate pipes, and a helper crash is reported as a failure even if it printed a successful response first. There is no automatic replay after a failure, timeout or cancellation. Default wall time is 60 seconds (maximum 300); command output defaults to 64 KiB (maximum 256 KiB). Output overflow stops the command. Per-process ceilings include 2 GiB address space, 128 processes per user, 512 file descriptors, 64 MiB per file and CPU time. These are not aggregate memory/disk quotas or protection against a kernel exploit; the sandbox shares the WSL kernel.

If **Connect** reports missing bubblewrap or disabled user namespaces, resolve that in your normal WSL session and retry. It never falls back to running commands on your unrestricted host. `E_ACCESSDENIED` means Windows denied WSL access; check `wsl --list --verbose` in your normal Windows session. Do not use `wsl --terminate` to cancel a bridge command: that would stop unrelated distro work.

Implementation validation: bridge behavior tests cover network defaults, explicit offline commands, scope checks, cancellation and connection state on CPython 3 and Jython 2.7.4. `tests/test_wsl_supervisor.py` reproduces the helper shutdown lifecycle with an open parent pipe and checks that no control-reader thread remains. The JVM subprocess test covers framed/large Unicode input, Windows launch quoting, EOF cancellation, stderr separation, helper exit status, malformed responses and output limits. `tests/jython_investigation_smoke.py` constructs the actual Swing terminal and verifies its defaults. Live WSL execution could not be checked in the restricted development session because Windows returned `Wsl/E_ACCESSDENIED`. Run `python3 /mnt/c/kali/BurpAI_4_5/tests/wsl_linux_check.py` from a non-root WSL session for real streamed-probe shutdown, sandbox, file, timeout, child cleanup and network namespace checks. The script uses only the dedicated workspace and no external target.

Reference: [Microsoft WSL command documentation](https://learn.microsoft.com/en-us/windows/wsl/basic-commands) and [bubblewrap options](https://github.com/containers/bubblewrap/blob/main/bwrap.xml).

### Catalog and fixture checks

Open **Local Tools** from the sidebar or search for `wsl` with **Ctrl+K**. In **WSL catalog**, click **Detect distributions**, select a distribution, then click **List tools**. The catalog lists executable names under `/usr/bin` and `/usr/local/bin` without running the listed tools. The agent can query the cached names. Inventory refresh requires Windows WSL access and the distribution's `/usr/bin/find`.

In **Fixture checks**, open a saved UTF-8 JSON file up to 512 KiB. The page reads the selected file into memory and shows its size and root type. Describe your expected behavior with **Draft with AI**, review the request in Conversation, and send it. The request includes the fixture ID, root type, and your description. The selected file's contents stay local. Back in **Fixture checks**, **Use AI draft** loads the proposed assertions for review. You can also write assertions directly in the editor.

For example, with `{"status":200,"body":{"items":[]}}` as your fixture, run:

```json
[
  {"label": "Successful response", "path": "/status", "op": "equals", "expected": 200},
  {"label": "Items are an array", "path": "/body/items", "op": "type_is", "expected": "array"},
  {"label": "No debug field", "path": "/body/debug", "op": "missing"}
]
```

Paths use JSON Pointer syntax. An empty path selects the root. Supported operations are `exists`, `missing`, scalar `equals`, `type_is`, and literal string `contains`. **Run checks** evaluates up to 32 assertions on the selected snapshot. The evaluator has no shell, file, or network operations. **Save report** writes a new JSON report at a path you choose, with the fixture hash, assertions and pass/fail results. **Clear fixture** clears the selection and results.

## Autonomous investigations and live guidance

### Discovery and experiment lab

The **Testing lab** expands what the agent can do: learn an application's behavior from existing traffic, invent evidence-linked hypotheses, test a controlled difference, and look for counterexamples. Reload the extension with both `BurpAI_v4_Lab.py` and `BurpAI_v4_Investigation.py` beside it.

Start with **Discover leads** in chat, or open **Testing lab**, enter the exact website URL and choose **Discover from traffic**. Discovery sends no target requests. It learns method/route groups, query parameters, captured response statuses and bounded JSON structures. The **Application map** view includes routes that did not generate a lead. Discovery can suggest server-error investigations, response-contract drift, object-visibility checks, anonymous/authenticated response equivalence and parameter-boundary checks. These are hypotheses with explicit alternative explanations, not vulnerability findings.

The agent can also create its own hypotheses from source-code and traffic reasoning using `lab_create_hypothesis`. A custom hypothesis must attach to an observed route, cite retained evidence, and explain what would disprove it. It is not limited to the built-in patterns. `lab_challenge` retrieves captured anonymous denials and successful controls, proposes alternative explanations, and identifies missing evidence. `lab_record_assessment` retains the interpretation, supporting and counter-evidence, and the next useful check.

Discovery cards appear in chat and in Testing lab. Their actions refer to the exact selected record:

| Action | What happens |
| --- | --- |
| **Investigate** | Asks the agent to inspect that lead and prepare a discriminating test. |
| **Challenge** | Asks it to find counterevidence and evaluate competing explanations. |
| **Explain** | Asks for a plain-language explanation of observations, interpretations and remaining uncertainty. |
| **Evidence** | Opens the original retained evidence in Memory. |
| **Run this experiment** | Shows the exact target and case count for approval, then instructs the agent to run that prepared experiment. This approval applies only to that experiment. |

Clicking a card preserves an unfinished chat draft. During an active run, card instructions become live guidance. A card remains tied to its mission even when ordinary conversation persistence is disabled. Old links cannot act on a different mission's discoveries. Cards escape model/target text rather than allowing arbitrary HTML or navigation.

`lab_prepare_experiment` builds a request sequence without sending it. `lab_run_experiment` executes it through the existing scope, rate, Stop, pause and per-run request-budget controls. Available recipes are:

| Recipe | Controlled sequence |
| --- | --- |
| **Parameter boundaries** | Fresh baseline; omit one observed query parameter; empty it; duplicate its original value; repeat baseline. Unchanged variants are omitted, so there are at most five requests. Other query parameters retain their original encoding and order. |
| **Session matrix** | Fresh baseline; the same request with anonymous or up to three explicitly selected session profiles; repeat baseline. Profiles are restricted to the exact scheme, host and port. A non-successful baseline stops the matrix before the variants. |

Experiments currently support bodyless GET/HEAD requests. Known action paths are left for manual Repeater review; this is not a general POST workflow engine. Every case uses the same transport normalization: remove hop-by-hop headers, conditional-cache headers and range headers, and request identity encoding. This avoids comparing a fresh body with a cached/partial/unsupported-compression response. HEAD comparisons concern headers and status. Live experiments use captured baseline headers, including that selected request's session headers; they do not silently search history for another session.

To compare sessions, use **Website Analyse > Traffic**, select the desired captured request, then click **Use as session** and name it. Repeat for another account if needed. The agent receives profile IDs and labels, not their credential values. Profiles retain recognized cookie, authorization, API-key and common authentication/CSRF headers in memory only; they disappear on reload, New Chat, loading another mission, or **Forget sessions**. Query-bound authentication and custom unrecognized authentication mechanisms require separate review. A supplied profile label does not prove the account's role. Changing or forgetting profiles invalidates prepared session templates and interrupts an active matrix before its next request.

Each attempted case has its own response evidence ID. The runner compares status, changed header names, exact body hashes, lengths and changed JSON paths. A repeated baseline detects observed drift; an unstable baseline or an unsuccessful control is explicitly labeled. Identical responses do not establish missing authorization, and differences do not automatically confirm a bug. Failed, incomplete and interrupted experiments cannot automatically replay. Reopening a draft after reload requires preparing it again from the same verified captured request.

Automatic sending uses the existing setting. With it disabled, discovery and preparation still work, and the Run action can approve one concrete experiment. The agent cannot grant itself approval through tool arguments. The entire experiment must fit within the remaining run request budget before it starts.

Discovery examines at most 3,000 recent history entries and collects 150 matching exchanges by default (configurable up to 500). It reports interrupted/limited collection, skips unusable requests, retains only bounded structure summaries, and never claims complete application coverage. Application maps, hypotheses and experiment results persist with the mission; credential-bearing request templates do not. Earlier leads not refreshed by a new partial map are marked stale.

Example prompts:

- "Map the captured traffic for this website, then challenge the three strongest bug hypotheses."
- "The source suggests pagination should not affect access. Create a falsifiable hypothesis on the mapped route and prepare a parameter-boundary experiment."
- "Compare this object's visibility using my selected sessions. Explain what changed and whether the baseline was stable."
- "Challenge this result: could it be a login page, public data, caching, or a transient failure?"

New model tools: `lab_map_application`, `lab_status`, `lab_create_hypothesis`, `lab_challenge`, `lab_prepare_experiment`, `lab_run_experiment`, and `lab_record_assessment`. Run `python -m unittest discover -s tests -p 'test_burpai_lab.py'` for deterministic discovery, experiment, session, adapter and chat tests. The Jython smoke test below now also exercises the actual Lab UI, native hyperlink activation, HTML escaping and the experiment runner with mocked transport.

### Investigation board and comparison engine

Open **Investigation** from the chat header or the last tab. The board keeps test priorities, prerequisite tests, target/category coverage, evidence IDs, outcomes, and the next check together. Select a row to inspect the baseline and changed condition. **Focus selected** adds a steering prompt while retaining your draft; press Send to apply it. **Save checkpoint** creates a Markdown note in Notes & maps without calling the model. Activity retains the latest 200 events; the board and checkpoint show the latest 60.

The agent now has four additional tools:

| Tool | Behavior |
| --- | --- |
| `next_test` | Returns ready tests ordered by priority (1 highest), unfinished prerequisites, and coverage of recorded tests. Resumes a testing item before another item of equal priority. |
| `capture_http_evidence` | Reads a complete HTTP response already in Burp history. Requires the index, exact URL and request SHA-256 from `burp_find_traffic`; checks current scope and rejects changed selections, partial responses, unsupported decoding, and bodies over 1 MiB. Sends no request. |
| `compare_evidence` | Compares two captured evidence IDs from this mission: status, changed header names, body hashes/lengths, and up to 60 changed JSON paths. Optional repeated baseline detects observed instability and requires the same request. Does not expose header/body values in the comparison summary or declare a vulnerability. |
| `report_progress` | Records a concise discovery, blocker, or change of direction with the next step in chat and the activity timeline. Communication records cannot substantiate a supported test. |

`update_test_plan` also accepts `target`, `category`, `priority` (1–5), and `depends_on` (test IDs). Unknown, self-referencing, or cyclic dependencies are rejected. A dependent test cannot enter `testing` or `supported` until its prerequisites are `supported` or `not_reproduced`; revise the plan explicitly if a prerequisite is no longer relevant. Counts describe recorded checks, not total application coverage. A `supported` outcome remains a model assessment.

**Pause / Resume** waits at the next operation boundary in a chat investigation without discarding pending tool results. Guidance sent while paused stays queued until Resume. **Summarize now** skips the remaining calls after the current operation and requests a final answer with tools disabled. At idle it displays the saved checkpoint without a model call. Existing in-flight operations may finish. Stop also releases a paused worker. Native and prose tool calls both follow these controls.

The **Next run request cap** on the board defaults to 20; set it to 0 for no live requests or up to 500. It applies to a newly started chat run and is charged immediately before each request attempt through the existing dispatcher, including failed/ambiguous sends. Guidance and pause/resume do not replenish it. Requests blocked before transport do not consume it. The existing scope, approval, rate-limit, and iteration settings still apply. The cap is additional to the iteration budget; it is not a timeout for an already-running request.

Local commands work without a model call:

| Command | Action |
| --- | --- |
| `/pause`, `/resume` | Pause or continue an active chat investigation. |
| `/status`, `/plan` | Show the saved checkpoint and test outcomes. |
| `/summary` | Finish an active investigation using existing evidence, or show the checkpoint at idle. |
| `/help` | Explain these controls. |

The plan, timeline and run checkpoint persist in the mission ledger and chat Save/Load. Reloading or loading a saved active run marks it interrupted; it never starts network work automatically. Send **Continue** to begin a fresh bounded run from the retained plan. Keep the new `BurpAI_v4_Investigation.py` alongside the extension when installing this update. Reload the extension to activate it.

Validation: deterministic orchestration, capture, comparison, dependency, request-budget and interruption tests are in `tests/test_burpai_investigation.py`. `tests/jython_investigation_smoke.py` exercises the actual Swing Agent/Investigation classes and comparison engine on Jython without initializing network adapters. It is a focused check, not a full Burp-session test.

```powershell
python -m unittest discover -s tests -p 'test_burpai_investigation.py'
java '-Djava.awt.headless=true' '-Dpython.cachedir.skip=true' -jar jython-standalone-2.7.4.jar tests/jython_investigation_smoke.py
```

Reload `BurpAI_v4_Extension.py` from this folder after updating. **Discover leads** fills a prompt for an evidence-driven investigation of the selected website. The agent starts from saved source and captured traffic, forms a small prioritized test plan, and describes a baseline and a changed condition before assessing results. Routine next steps no longer require a decision prompt.

- `update_test_plan` creates or updates a test; call it without arguments to read the complete plan. Tests persist with the mission and chat Save/Load. New Chat clears the plan. Outcomes are `planned`, `testing`, `supported`, `not_reproduced`, `inconclusive`, or `blocked`.
- A `supported` assessment requires a baseline, a check, an outcome explanation, and at least two distinct evidence IDs from this mission. This validates provenance, not exploitability: assessments remain model-authored and need review. Queued requests are not executed tests.
- The configured iteration cap bounds work turns. If work consumes that budget, one additional model call is reserved for a summary with tools disabled. This also applies to single-step mode. Repeated unsuccessful turns trigger an earlier summary. If synthesis fails, the chat displays a local recap of completed operations and the saved plan.
- The same proposed/sent request cannot be replayed within a run simply by changing its rationale, confidence, header-name case, or tool name. Failed and ambiguous requests remain subject to manual review. Burp scope, rate limits and request-approval settings continue to apply.
- While the agent runs, **Send guidance** queues your correction. It takes effect after the current operation; remaining tool calls from the old plan are skipped. You can also type guidance instead of choosing a decision button. A request already in transport may finish. If Stop or an error ends the run first, the accepted guidance stays in the conversation; send **Continue** to process it.
- Tool messages show readable outcomes and evidence IDs. Raw arguments/results remain in the separate tool inspector. Reading earlier messages no longer deliberately jumps you to the bottom on every update.
- An unanswered decision times out after five minutes and pauses without selecting an option. The explicit unattended-choice setting still selects its configured first option. Stop shows **Stopping** while the worker is finishing.

The final report should distinguish evidence-supported hypotheses, checks that did not reproduce, blockers, queued requests and untested areas. Reaching a budget never means the target is free of bugs. Model behavior still depends on the selected provider; the runtime enforces request deduplication, tool-free synthesis and interruption handling.

## Markdown notes and visual mind maps

Reload the extension after this update. Ask the Agent to **"Create a Markdown note about ..."** or **"Make a visual mind map of ..."**. The model can create, list, read, revise and open documents with `document_save`, `documents_list`, `document_read` and `document_open`. This works for general topics and for investigation notes.

Open **Notes & maps**, select a document, and choose **Open preview** (or double-click its row). Notes have formatted headings, tables, code blocks, checklists, an outline, light/dark themes, Markdown copy/download and Print / PDF. Maps have colored branches, click-to-fold nodes, drag/pan, zoom, fit, an outline view and SVG export. **Open .md** opens the original in your default editor; **Open folder** shows the saved files. The two Ask buttons fill the chat composer without sending.

Documents persist in `~/.burpai_context_v2/documents` across chats and reloads. Each successful save produces a UTF-8 `.md` file and a standalone `.html` preview; both can be copied elsewhere. Viewing works offline with no running model or server. Updating a document retains its ID and writes a new revision; old revision files are retained. Direct edits to the current `.md` file appear when you reopen its preview from the extension. The library catalog must stay with its files for the extension to find them.

Mind maps use a Markdown bullet outline, optionally preceded by a `# Title`, with two spaces per nesting level. The visual renderer supports up to 250 nodes and 10 levels. Notes accept up to 256 KiB of Markdown. Embedded HTML is sanitized, active content and remote images are blocked, and ordinary web links open only when clicked. Model-written notes remain interpretations; cite evidence and mark uncertainty as needed.

Keep `BurpAI_v4_Documents.py` and the complete `document_viewer` folder beside the extension. The offline viewer bundles Marked 18.1.3 and DOMPurify 3.4.17, with their licenses and pinned download checksums in that folder. The existing website-specific working-note tree is separate and continues to use `website_save_note` and `website_mind_map`.

## Source workbench in v4.5

Website Analyse now has a source explorer beside a code reader, with a dark navy, teal and indigo interface and JavaScript syntax colors. The Connection & limits tab holds setup fields so the workbench stays focused on investigation.

- Search Files returns clickable source locations. Double-click a result or choose Open Selected to read nearby original lines.
- Enter **50** and **150** in the line fields and click **Read Lines** for that inclusive range. Line numbers are the original file's numbers. A huge minified line is capped explicitly; Continue reads the next part of the same requested range.
- **Outline** locates function/class/arrow declarations. **Related Files** follows literal imports and importing files. **Find References** uses the query field as an exact identifier across current scoped files. These are lexical navigation helpers, not a complete JavaScript language server; runtime bindings and computed imports may remain unresolved.
- **Back / Forward** return to previously opened files/ranges. **More Results** pages search inventories, outlines, references or captured traffic when available. Source-file IDs and source hashes keep citations tied to the saved version.
- **Workspace** summarizes the site's saved files, collection gaps, selected source, and recent captured traffic. **Traffic** uses the query field as a URL filter and lists requests from exactly the target origin. Clear the query to see recent traffic.
- Select a traffic row and click **Copy to Repeater** to open the captured request in Burp. Its URL and request hash are checked again first, preventing an old history index from opening a different request. It is copied without being sent.

The Agent has matching tools: `website_read_lines`, `website_outline`, `website_related_files`, `website_find_references`, `burp_workspace_context`, `burp_find_traffic`, and `burp_open_repeater`. Semantic search returns ready-to-use line-reading arguments. Ask, for example: "Find how sessions refresh, read lines 50-150 of the matching file, follow its imports, and correlate the refresh route with captured traffic."

Collection must already have saved the files. The existing scope checks, source-integrity checks and Stop control apply to navigation too. Updates do not require re-downloading existing source files or embeddings.

The Agent receives a fresh local inventory for the selected website at the start of each run, including after a reload or New Chat. For code/security questions about a site with saved files, its instructions prioritize `website_search_js` with a focused natural-language question, followed by exact source reads and captured-traffic correlation. It checks another site's workspace when the question specifies a different target. Collection notices shown in the chat are no longer the only indication that files exist. Search results report the actual embedding mode; the inventory itself does not assert index readiness or complete coverage.

`search_http` searches captured traffic by literal substring unless `regex=true`; alternatives such as `login|auth` require that flag. It is not semantic source search. Client code suggesting an admin route is a lead to verify against server evidence, not proof of an authentication bypass.

## Automatic requests and persistent mind map

**Settings → Agent Behavior → Automatically approve and send new proposed requests** makes `propose_request` send once and return the response to the model. This is independent of the multi-turn autonomous-mode setting. It applies to new proposals; existing queued requests remain for review. Burp scope, the shared request rate, Stop and Kill Switch still apply. Rate-limit waits can be stopped. Failed or ambiguous sends remain queued with approval reset and are not replayed automatically. Turning this setting off immediately revokes automatic approval. The setting defaults off in a fresh installation.

**Website Analyse → Mind map** displays model-authored working notes and their source/related-note links. The model can use `website_save_note` to remember observations, hypotheses, conclusions and next steps, and `website_mind_map` to retrieve them later. Notes persist per website across reloads and New Chat. Source links include file content hashes; links to replaced/removed versions are marked stale. The existing evidence graph retains captured observations separately.

## Semantic search and saved notes

**Settings → Agent Behavior → Use configured local chat model when OpenRouter hits a rate or credit limit** is enabled by default. An explicit OpenRouter HTTP 429 (rate/quota limit) or 402 (credit limit) immediately continues the same conversation with the Local API base URL, Local model and Local API key from Settings. The rest of that run stays local; the next Send tries the selected provider again. The chat shows the switch. Authentication failures, timeouts, and unrelated errors do not trigger this fallback. Stop and Kill Switch remain effective. Configure a working local chat model before relying on fallback.

For cloud embeddings, select **Website Analyse → Connection & limits → Embedding preset → OpenRouter**, then **Save Settings** and **Index Files**. The preset uses `https://openrouter.ai/api/v1/embeddings` with `nvidia/nemotron-3.5-embed-8b:free`. The URL field holds the API base `https://openrouter.ai/api/v1`. A blank embedding key reuses the OpenRouter chat key only for the official HTTPS endpoint; Local/custom never inherits that key automatically. A separate embedding key can be entered if desired.

Cloud indexing sends saved source and queries to OpenRouter/NVIDIA; this free endpoint is intended for non-confidential inputs. Changing embedding providers creates a separate model/endpoint-specific cache. Embeddings do not automatically switch to another model on a limit: vector spaces cannot be mixed. Existing embedding selections are preserved, including when setup is rerun.

Semantic search searches all scoped saved JavaScript by default. The main model can choose an explicit `file_ids` subset after inspecting source or saved notes. No auxiliary JS model or generated functionality labels are used. Legacy file-map caches are ignored. Mind map contains only notes and source relationships explicitly saved by the main agent.

Search matches include roughly 30 lines of original context on each side, with continuation for large/minified lines. Keyword and identifier search works without an embedding model. Local semantic search can use embeddinggemma through Ollama.

## Automatic setup

Keep `setup_burpai.py` beside the extracted files (or beside the bundle ZIP), then run:

```powershell
python3 setup_burpai.py
```

On Windows, `py -3 setup_burpai.py` also works. The script checks the required modules and viewer files, downloads Jython if missing, and starts Connection Hub as BurpAI's chat provider. Use `--no-hub` to keep your current provider or `--files-only` to prepare the extension and Jython without starting services or changing settings. Add `--with-embeddings` only if you want setup to prepare Ollama and embeddinggemma for local semantic search. The default setup leaves your embedding settings in place. Add `--check` to verify the selected setup without making changes. The check exits with status 1 if a required file, service, or model is unavailable. Follow the printed steps to load or reload BurpAI in Burp.

When launched from WSL, setup uses Windows Python for Connection Hub or optional Ollama setup so it uses the Windows Burp profile and saved Hub credentials. If Windows Python cannot be launched from WSL, run setup from Windows PowerShell under the same Windows account as Burp. `--files-only` and `--no-hub` without `--with-embeddings` can run directly in WSL.

## Install or update

1. Keep these files and the viewer folder together in the same folder:
   - `BurpAI_v4_Extension.py`
   - `BurpAI_v4_Website.py`
   - `BurpAI_v4_Semantic.py`
   - `BurpAI_v4_Workspace.py`
   - `BurpAI_v4_Documents.py`
   - `document_viewer/` (all bundled files)
2. In Burp's Extensions settings, use Jython 2.7.4 and load/reload `BurpAI_v4_Extension.py` as the Python extension.
3. Open **AI Agent → Website Analyse**.

The ZIP includes these modules, this guide, and the unchanged optional `BurpAI_v4_ResearchEngine.py`. The research sidecar is not required for website collection or semantic search. The previous extension is backed up separately as `backups/BurpAI_v4_Extension.before-website-analyse.py`.

## Collection speed

Website Analyse spaces requests evenly using the shared HTTP rate setting. The default is 30 requests/minute (one every two seconds). Open **Website Analyse > Connection & limits > HTTP requests / minute (shared)** to change it; 120 means approximately two requests/second. This setting stays synchronized with Settings. When the shared minute budget is exhausted, the status displays the used allowance and a countdown. Stop interrupts these waits. This is a local HTTP pacing limit, separate from model-provider rate limits.

## Collect and search

1. Add the website and any authorized script/CDN hosts to Burp's **Target scope**.
2. Enter the site's final URL, for example `https://example.test/`, and choose **Save files in**. The default is `~/.burpai_website`.
3. Click **Collect JS + Index**. It gathers complete captured scripts, crawls same-origin pages, saves inline JavaScript, and follows script tags, module preloads, literal imports, and literal JavaScript chunk references. It then builds the search index automatically.
4. Search with a question such as **“Where is the sign-in state stored and refreshed?”** or **“Which code builds requests to the billing API?”**.
5. Results include the local path, original URL, file ID, line range, character offset, and exact excerpt. Paste a file ID and offset into **Read Source** to inspect surrounding code.

**List Files** displays the inventory and storage folder. If another inventory page is available, enter its next offset and click List Files again. **Index Files** resumes missing embeddings without downloading the site again. **Stop** halts discovery/indexing between operations and retains completed work. A website request already in Burp's transport may finish before Stop takes effect.

The Agent can use the same files through `website_collect_js`, `website_search_js`, `website_index_js`, `website_list_js`, and `website_read_js`. Ask it to collect a URL or search its downloaded JavaScript, then request analysis with source citations. Search results are evidence; downloaded code is never executed.

## Enable semantic search

Semantic search needs an **embedding model**, separate from the chat model. The default configuration keeps embedding requests on this computer:

- Embedding URL: `http://127.0.0.1:11434`
- Model: `embeddinggemma`
- Key: empty

With [Ollama](https://ollama.com/library/embeddinggemma) installed, start Ollama and download the model once:

```powershell
ollama pull embeddinggemma
```

If Ollama is not already running, start it with `ollama serve`. Then click **Index Files**. The extension does not install or download a model automatically.

An OpenAI-compatible embedding server also works. For example, use your local server's `/v1` base URL and the exact ID of a loaded embedding model. A chat-only model/server cannot produce embeddings. Full `/v1/embeddings` and Ollama `/api/embed` URLs are also accepted. If you choose a remote embedding endpoint, code chunks and search queries are sent to that endpoint; the default endpoint is local. These settings are independent of the existing chat-model settings.

Search modes are explicit:

- `semantic_hybrid`: all searchable chunks have embeddings; results combine vector similarity and identifier matching.
- `semantic_partial`: some chunks have embeddings; unfinished chunks remain searchable by text. Click Index Files to resume.
- `lexical`: keyword/identifier matching only. Check the displayed embedding error, server URL, and model, then index again.

Behavior tests run on Python and Jython 2.7.4. They use a deterministic embedding provider and local HTTP fixtures to verify ranking, persistence, navigation and both API protocols. An additional live smoke test with local embeddinggemma ranked session-renewal code first for a natural-language login-renewal question. This is a functional smoke test, not a broad retrieval-quality benchmark. Actual Swing construction, control wiring and syntax colors were checked, and rendered at 1500x960 and 1300x900. The included interface preview uses demonstration data.

## Files, coverage, and limits

Sources are saved as UTF-8 `.js`/`.mjs`/`.cjs` files in a per-origin folder under `sites/`. A `manifest.json` records URLs, hashes, file IDs, and collection outcomes. Query-string variants and source revisions have distinct filenames. The manifest represents the latest collection; older source files remain on disk but are excluded from current search results. Changing the website path on the same origin uses the same library.

Source chunks retain original line and character positions, including minified code. Embeddings are cached by file content, model, and endpoint. Unchanged files reuse cached work. Changed or corrupted source files are rejected until collected again, so citations cannot silently point at different bytes. A changed model name or endpoint requires fresh embeddings. If you replace a model's weights while keeping its name, use a different model alias or a new output folder to avoid reusing the old vectors.

Default collection limits are **30 page requests**, **500 scripts**, and **100 MiB of saved JavaScript**. The UI allows changing page/file limits; each response/source is limited to **32 MiB**. Redirects and unsuccessful page requests count toward the page limit. Requests respect the extension's existing request rate and Burp scope; redirect destinations are checked individually. Stop and Kill Switch remain active. Scope is also rechecked when reading/searching saved files.

Collection follows static references and Burp-captured traffic. It does not execute a browser, submit forms, guess hidden routes, or resolve computed runtime chunk names. Lazy-loaded or authenticated routes may contain additional scripts: browse those routes through Burp and collect again. Live collection does not automatically copy cookies or authorization headers from history. Add referenced CDN hosts to scope if their scripts should be fetched. Start with the final HTTPS URL when a site's HTTP entry point redirects to another origin.

Incomplete, undecodable, oversized, and HTML-at-script responses are reported rather than indexed as complete JavaScript. Brotli-only responses are reported as unsupported; live collection requests identity encoding. The result shows failed/skipped URLs, limit hits, and a static-discovery caveat. Collection and search do not assert that every runtime script was found or that a vulnerability has been confirmed.

## Verification

Run the behavior tests with Python 3:

```powershell
py -3 -m unittest discover -s tests -p "test_burpai_*.py" -v
```

Run them with the actual Burp-compatible runtime:

```powershell
java '-Dpython.cachedir.skip=true' -jar jython-standalone-2.7.4.jar -m unittest discover -s tests -p 'test_burpai_*.py' -v
java '-Djava.awt.headless=true' '-Dpython.cachedir.skip=true' -jar jython-standalone-2.7.4.jar tests/jython_website_smoke.py
```

Tests cover discovery, scope/redirect checks, complete response decoding, limits, cancellation, source integrity, semantic ranking, model/cache invalidation, API response validation, and collection → search → source reading. The Jython smoke test constructs the actual Swing interface and verifies button/Enter wiring with mocked Burp callbacks. Tests contact local fixtures only. Loading and exercising the extension inside an actual Burp session remains a manual check.
