# Release validation tools

These validators ship with the source tree. Deployment and signing tools do not
require the maintainer's private `.agents/` directory or an installed Codex
skill. The validation rules are copied from the project's governance helpers;
keep their contracts and deterministic self-tests aligned when updating them.

Run on the remote build host:

```bash
python3 scripts/governance/self_test.py
python3 -m unittest discover -s tests -p 'test_ds*.py'
```

Each validator provides `--help`. Synthetic self-test results verify the tools'
contracts; they do not constitute measured detection-quality evidence or
authorize deployment, signing, or model activation.
