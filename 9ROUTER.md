# Optional 9Router setup

Connection Hub is the default setup path. The experimental 9Router integration requires Node.js 24 and the exact pinned 9Router version because its launcher patches prebuilt assets.

```sh
cd nine_router
npm install
cd ..
python nine_router/launch_9router.py --no-connect
```

The dashboard opens on `http://127.0.0.1:20128/dashboard`. Configure your providers, create a combo with the Fallback strategy, and create a local API key using the dashboard.

Create `nine_router/.state/burp-connection.json` locally with your combo name and key:

```json
{
  "model": "YOUR_COMBO_NAME",
  "key": "YOUR_LOCAL_ROUTER_API_KEY"
}
```

Then run `python nine_router/launch_9router.py` and reload BurpAI. Use `--top-priority` to open provider ordering. This connection file is deliberately ignored by Git. An optional `embedding_model` entry configures the embedding route too.

Node is found on PATH by default. If necessary, copy `runtime.example.json` to `runtime.json` inside `nine_router` and set an absolute Node executable path. Never commit this local override.

The launcher refuses incompatible completion-patch layouts. Do not upgrade 9Router without reviewing its patches and regression tests. Existing launch shortcuts select this router; `Restore Connection Hub.cmd` switches back to Connection Hub.
