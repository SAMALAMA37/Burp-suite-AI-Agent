# Contributing

Keep Burp-loaded modules compatible with Jython 2.7. Local services and setup target Python 3.11+. Do not commit tokens, captured traffic, saved missions, provider state, logs, or machine-specific paths.

Run the deterministic Python suite:

```sh
python -m unittest discover -s tests -p "test_*.py" -v
```

After setup downloads Jython, check the Burp-compatible runtime:

```sh
java -Dpython.cachedir.skip=true -jar jython-standalone-2.7.4.jar -m unittest discover -s tests -p "test_burpai_*.py" -v
java -Djava.awt.headless=true -Dpython.cachedir.skip=true -jar jython-standalone-2.7.4.jar tests/jython_website_smoke.py
java -Djava.awt.headless=true -Dpython.cachedir.skip=true -jar jython-standalone-2.7.4.jar tests/jython_investigation_smoke.py
```

Viewer checks require Node.js 24 and dependencies in `tests/viewer`:

```sh
cd tests/viewer
npm install
node test_viewer.cjs
node test_connections.cjs
```

The `live_*.py`, `wsl_linux_check.py`, and Jython transport scripts are opt-in environment checks. Read each before running; they require local services or WSL. Loading the extension in a real Burp session remains a manual integration check.

Pull requests should explain the user-visible change, tests run, and any limitations. Report security issues privately as described in SECURITY.md. Licensing must be resolved with the repository owner before accepting contributions under a shared license.
