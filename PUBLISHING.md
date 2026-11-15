# Publishing BurpAI

## First upload

1. Select the GitHub owner and repository visibility. The commands below default to private; choose public only when intended.
2. Install GitHub CLI and sign in with `gh auth login`. Use its interactive browser flow; do not paste access tokens into chat or source files.
3. Set your Git author name and email locally if needed (`git config user.name` and `git config user.email`).
4. Review staged files, run tests, and commit:

   ```sh
   git add .
   git diff --cached --stat
   git diff --cached
   git commit -m "Prepare BurpAI 4.5 source distribution"
   gh repo create BurpAI_4_5 --private --source=. --remote=origin --push
   ```

If the repository already exists, set its exact URL with `git remote add origin URL`, then `git push -u origin main`. Do not overwrite an existing remote or force-push unrelated history.

## Release

Resolve project licensing with the owner, run the checks in CONTRIBUTING.md, and perform a manual load in Burp. Confirm that the CI run is green before publishing a release.

```sh
python scripts/build_release.py
git tag v4.5.0
git push origin v4.5.0
gh release create v4.5.0 release/BurpAI-4.5-source.zip release/SHA256SUMS.txt --title "BurpAI 4.5" --notes-file CHANGELOG.md
```

The packager includes only files tracked in Git and rejects known private/runtime paths. It does not bundle Jython, node_modules, credentials, traffic, backups, or logs. Setup downloads Jython for the recipient. Review source content for secrets even when paths look safe.

Before the first commit, `python scripts/build_release.py --include-untracked` can package reviewed, non-ignored source files as well. Inspect `git ls-files --others --exclude-standard` before using this option.

Enable private vulnerability reporting and branch protection in GitHub settings if available for the chosen repository. The included CI runs Python regression tests on Windows and Linux and document-viewer checks on Linux. It does not certify live provider access or an actual Burp session.
