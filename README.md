# Sentinel Ops Toolkit

![CI](https://github.com/jonhsoares2104-commits/sentinel-ops-toolkit/actions/workflows/ci.yml/badge.svg)

Coleção de ferramentas de automação e segurança para ambientes Windows,
construídas em Python (com PowerShell para coleta de dados nativa do
sistema). Cada pasta é um projeto independente, com seu próprio README
explicando decisões de design, uso e limitações conhecidas.

## Projetos

| Projeto | Categoria | O que faz |
|---|---|---|
| [`claude_ti_pipeline`](./claude_ti_pipeline) | Automação | Coleta saúde do sistema via PowerShell, analisa com a API do Claude e gera relatório em PDF — com envio por email e auto-agendamento. |
| [`config_drift_detector`](./config_drift_detector) | Automação | Detecta mudanças de configuração (serviços, registro, firewall) fora do processo formal de change management. |
| [`password_spray_detector`](./password_spray_detector) | Segurança | Detecta padrão de password spray (e brute force clássico) em logs de logon falho do Windows (Event ID 4625). |
| [`file_integrity_monitor`](./file_integrity_monitor) | Segurança | Monitora integridade de arquivos críticos via hash SHA-256 — alterado, removido ou novo. |
| [`mini_soc_dashboard`](./mini_soc_dashboard) | Segurança / Dashboard | Unifica os relatórios dos detectores acima num painel HTML único, estilo NOC. |

## Como os projetos se conectam

```
config_drift_detector.py  ─┐
password_spray_detector.py ─┼──> reports/*.json ──> mini_soc_dashboard.py ──> dashboard.html
file_integrity_monitor.py ─┘
```

Os três detectores de segurança/config exportam relatórios num schema JSON
padronizado (`fonte`, `gerado_em`, `achados: [{categoria, item, severidade,
detalhe}]`). O Mini-SOC Dashboard lê qualquer JSON nesse formato — incluindo
detectores futuros que venham a seguir o mesmo padrão.

## Testando rapidamente (sem Windows)

Todo projeto tem um modo `--demo`, com dados simulados, para rodar e revisar
sem precisar de um servidor Windows real ou credenciais de API:

```bash
python claude_ti_pipeline/claude_ti_pipeline.py --demo
python config_drift_detector/config_drift_detector.py --demo
python password_spray_detector/password_spray_detector.py --demo
python file_integrity_monitor/file_integrity_monitor.py --demo --criar-baseline
python file_integrity_monitor/file_integrity_monitor.py --demo
python mini_soc_dashboard/mini_soc_dashboard.py --demo --abrir
```

## Requisitos

- Python 3.10+
- `reportlab` e `requests` (apenas para `claude_ti_pipeline`):
  `pip install -r requirements.txt`
- Os demais projetos usam apenas biblioteca padrão do Python.
- PowerShell (para coleta de dados real em ambiente Windows — os modos
  `--demo` não precisam disso).

## Integração Contínua

Todo push/PR roda automaticamente o modo `--demo` de cada um dos 5 projetos
via GitHub Actions (`.github/workflows/ci.yml`) — um smoke test rápido que
garante que nenhum projeto quebrou de forma óbvia antes de chegar na branch
principal.

## Licença

MIT — ver [LICENSE](./LICENSE).
