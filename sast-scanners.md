### Free, open-source Python SAST scanners

- **[Bandit](https://bandit.readthedocs.io/)** – AST-based scans for common Python security issues.  
  *Quick start:* `pip install bandit` → `bandit -r <path>`

- **[Semgrep CE](https://semgrep.dev/docs/)** – pattern-matching engine with a large community ruleset; fast and CI-friendly.  
  *Quick start:* `pipx install semgrep` → `semgrep --config=p/python <path>`

- **[Pysa (Pyre)](https://pyre-check.org/docs/pysa-basics/)** – deep taint-flow analysis that tracks data from untrusted sources to dangerous sinks.  
  *Quick start:* `pip install pyre-check` → `pyre init && pyre analyze`

- **[CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli)** – semantic query engine (the same one GitHub uses for GitHub Code Scanning).  
  *Quick start:* download the CLI → `codeql database create db --language=python` → `codeql database analyze db`

- **[PyT](https://pyt.readthedocs.io/)** – static taint analysis for Python web apps (SQLi, SSRF, XSS, etc.).  
  *Quick start:* `pip install pyt` → `pyt --path <path>`
