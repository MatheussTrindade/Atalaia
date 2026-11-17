# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e [SemVer](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Added — Fase 1 (MVP)
- Coletores CISA KEV e NVD CVE 2.0 (janela incremental, paginação, rate limit) e
  enriquecimento EPSS em lote.
- Filtro de ambiente: perfis (`azure`, `microsoft365`, `windows`, `aws`, `gcp`,
  `google_workspace`, `linux`, `kubernetes`), vendors/produtos com curinga e `exclude`
  (perfis, vendors, produtos, palavras-chave) que vence inclusive o KEV.
- Categorização por tipo de falha (CWE + palavras-chave) e catálogo em SQLite.
- Priorização KEV · CVSS · EPSS com limiares configuráveis (`scoring`, `thresholds`).
- Notifier Telegram (HTML escapado, throttling, `retry_after`, confirmação `ok: true`),
  deduplicação com realerta em escalada de severidade e resumo quando passa do limite.
- CLI: `--once` e `--dry-run`. HTTP seguro (TLS, timeout, retry) e logger com redação.
- Testes unitários e de integração com fixtures de API.

### Added — Fase 0
- Estrutura modular: `collectors`, `enrichers`, `core`, `models`, `notifiers`, `storage`, `utils`.
- Pipeline de CI com gitleaks, ruff, bandit, pip-audit e pytest.
- Dependabot, pre-commit, `SECURITY.md`, threat model e Dockerfile sem root.
- Documentação: arquitetura, fontes de dados e ADRs
  ([priorização por risco](docs/adr/0001-priorizacao-por-risco.md),
  [estado em SQLite](docs/adr/0002-estado-em-sqlite.md)).
