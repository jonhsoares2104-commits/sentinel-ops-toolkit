"""
mini_soc_dashboard.py
=======================
Unifica os relatórios JSON dos detectores (Config Drift Detector, Password
Spray Detector, File Integrity Monitor) numa única página HTML — um painel
de SOC em miniatura, sem precisar de servidor, banco de dados, ou dependência
externa (só biblioteca padrão do Python).

COMO OS DETECTORES SE CONECTAM AQUI:
Cada detector, quando rodado com --saida-json, gera um arquivo no formato:
{
  "fonte": "config_drift" | "password_spray" | "file_integrity",
  "gerado_em": "2026-07-16T10:00:00",
  "total_achados": N,
  "achados": [
    {"categoria": "...", "item": "...", "severidade": "CRITICO"|"ATENCAO"|"OK", "detalhe": "..."}
  ]
}
Esse script varre uma pasta de relatórios, lê todos os JSONs que encontrar
nesse formato, e monta um dashboard único agregando tudo.

Uso:
    # Rodar os detectores reais salvando na pasta de relatórios:
    python config_drift_detector.py --saida-json reports/config_drift.json
    python password_spray_detector.py --csv eventos.csv --saida-json reports/password_spray.json
    python file_integrity_monitor.py --caminhos C:\\Scripts --saida-json reports/file_integrity.json

    # Depois, gerar o dashboard:
    python mini_soc_dashboard.py --pasta-relatorios reports/

    # Ou testar tudo de uma vez, sem precisar rodar os outros scripts:
    python mini_soc_dashboard.py --demo
"""

import os
import sys
import json
import glob
import argparse
import webbrowser
from datetime import datetime

PASTA_RELATORIOS_PADRAO = os.path.join(os.path.dirname(__file__), "reports")
ARQUIVO_SAIDA = os.path.join(os.path.dirname(__file__), "mini_soc_dashboard.html")

NOMES_AMIGAVEIS_FONTE = {
    "config_drift": "Config Drift Detector",
    "password_spray": "Password Spray Detector",
    "file_integrity": "File Integrity Monitor",
}

CORES_SEVERIDADE = {
    "CRITICO": "#ff5252",
    "ATENCAO": "#ffab40",
    "OK": "#69f0ae",
}


# ----------------------------------------------------------------------------
# LEITURA DOS RELATÓRIOS
# ----------------------------------------------------------------------------
def carregar_relatorios(pasta: str) -> list[dict]:
    relatorios = []
    for caminho in sorted(glob.glob(os.path.join(pasta, "*.json"))):
        try:
            with open(caminho, "r", encoding="utf-8") as f:
                dado = json.load(f)
            if "achados" not in dado:
                continue  # ignora JSON que não segue o schema esperado
            dado["_arquivo_origem"] = os.path.basename(caminho)
            relatorios.append(dado)
        except (json.JSONDecodeError, OSError) as erro:
            print(f"AVISO: não foi possível ler {caminho}: {erro}")
    return relatorios


# ----------------------------------------------------------------------------
# DADOS DEMO (gera os 3 relatórios simulados, um de cada detector)
# ----------------------------------------------------------------------------
def gerar_relatorios_demo(pasta: str) -> None:
    os.makedirs(pasta, exist_ok=True)
    agora = datetime.now().isoformat(timespec="seconds")

    demo_config_drift = {
        "fonte": "config_drift", "gerado_em": agora, "total_achados": 3,
        "achados": [
            {"categoria": "servico", "item": "wuauserv", "severidade": "CRITICO",
             "detalhe": "Status: Running -> Stopped | StartType: Automatic -> Disabled"},
            {"categoria": "registro", "item": "EnableLUA", "severidade": "CRITICO",
             "detalhe": "Valor: 1 -> 0 (UAC desabilitado)"},
            {"categoria": "firewall", "item": "Regra Temporaria Suporte", "severidade": "ATENCAO",
             "detalhe": "Nova regra de firewall ativa, não presente no baseline."},
        ],
    }

    demo_password_spray = {
        "fonte": "password_spray", "gerado_em": agora, "total_achados": 2,
        "achados": [
            {"categoria": "password_spray", "item": "203.0.113.55", "severidade": "CRITICO",
             "detalhe": "8 contas distintas em 8 tentativas em 10 minutos: jsilva, administrator, vpnuser..."},
            {"categoria": "brute_force", "item": "jsilva", "severidade": "ATENCAO",
             "detalhe": "7 tentativas vindas de: 198.51.100.20, 203.0.113.55"},
        ],
    }

    demo_file_integrity = {
        "fonte": "file_integrity", "gerado_em": agora, "total_achados": 3,
        "achados": [
            {"categoria": "arquivo_alterado", "item": r"C:\Windows\System32\drivers\etc\hosts", "severidade": "CRITICO",
             "detalhe": "Hash mudou. Entrada suspeita adicionada redirecionando login.microsoft.com."},
            {"categoria": "arquivo_removido", "item": r"C:\Scripts\startup_script.ps1", "severidade": "CRITICO",
             "detalhe": "Arquivo presente no baseline não foi encontrado."},
            {"categoria": "arquivo_novo", "item": r"C:\Scripts\svchost_updater.ps1", "severidade": "ATENCAO",
             "detalhe": "Arquivo não presente no baseline, apareceu na pasta monitorada."},
        ],
    }

    for nome, conteudo in [
        ("config_drift.json", demo_config_drift),
        ("password_spray.json", demo_password_spray),
        ("file_integrity.json", demo_file_integrity),
    ]:
        with open(os.path.join(pasta, nome), "w", encoding="utf-8") as f:
            json.dump(conteudo, f, ensure_ascii=False, indent=2)

    print(f"Relatórios demo gerados em: {pasta}")


# ----------------------------------------------------------------------------
# GERAÇÃO DO HTML
# ----------------------------------------------------------------------------
def escapar(texto: str) -> str:
    return (str(texto).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def gerar_html(relatorios: list[dict]) -> str:
    todos_achados = []
    for r in relatorios:
        fonte = r.get("fonte", r.get("_arquivo_origem", "desconhecido"))
        for a in r["achados"]:
            achado = dict(a)
            achado["_fonte"] = fonte
            achado["_gerado_em"] = r.get("gerado_em", "")
            todos_achados.append(achado)

    total_criticos = sum(1 for a in todos_achados if a["severidade"] == "CRITICO")
    total_atencao = sum(1 for a in todos_achados if a["severidade"] == "ATENCAO")
    total_geral = len(todos_achados)

    if total_criticos > 0:
        status_geral, cor_status = "CRÍTICO", CORES_SEVERIDADE["CRITICO"]
    elif total_atencao > 0:
        status_geral, cor_status = "ATENÇÃO", CORES_SEVERIDADE["ATENCAO"]
    else:
        status_geral, cor_status = "OK", CORES_SEVERIDADE["OK"]

    # Ordena: críticos primeiro, depois atenção, mais recentes primeiro dentro do grupo
    ordem_severidade = {"CRITICO": 0, "ATENCAO": 1, "OK": 2}
    todos_achados.sort(key=lambda a: ordem_severidade.get(a["severidade"], 9))

    # --- cards por fonte ---
    cards_fontes = ""
    for r in relatorios:
        fonte = r.get("fonte", "desconhecido")
        nome_amigavel = NOMES_AMIGAVEIS_FONTE.get(fonte, fonte)
        n_criticos = sum(1 for a in r["achados"] if a["severidade"] == "CRITICO")
        n_atencao = sum(1 for a in r["achados"] if a["severidade"] == "ATENCAO")
        cor = CORES_SEVERIDADE["CRITICO"] if n_criticos else (CORES_SEVERIDADE["ATENCAO"] if n_atencao else CORES_SEVERIDADE["OK"])
        cards_fontes += f"""
        <div class="card-fonte" style="border-left-color: {cor};">
          <div class="card-fonte-titulo">{escapar(nome_amigavel)}</div>
          <div class="card-fonte-contagem">{n_criticos} crítico(s) · {n_atencao} atenção</div>
          <div class="card-fonte-meta">Última execução: {escapar(r.get('gerado_em', 'N/D'))}</div>
        </div>"""

    if not relatorios:
        cards_fontes = '<div class="sem-dados">Nenhum relatório encontrado na pasta informada.</div>'

    # --- linhas da tabela ---
    linhas_tabela = ""
    for a in todos_achados:
        cor = CORES_SEVERIDADE.get(a["severidade"], "#999")
        nome_fonte = NOMES_AMIGAVEIS_FONTE.get(a["_fonte"], a["_fonte"])
        linhas_tabela += f"""
        <tr>
          <td><span class="badge" style="background:{cor}22; color:{cor}; border-color:{cor};">{a['severidade']}</span></td>
          <td>{escapar(nome_fonte)}</td>
          <td>{escapar(a.get('categoria', ''))}</td>
          <td class="item-cell">{escapar(a.get('item', ''))}</td>
          <td class="detalhe-cell">{escapar(a.get('detalhe', ''))}</td>
        </tr>"""

    if not todos_achados:
        linhas_tabela = '<tr><td colspan="5" class="sem-dados">Nenhum achado — todos os detectores reportaram ambiente limpo.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Mini-SOC Dashboard</title>
<style>
  :root {{
    --bg: #0d1117;
    --bg-card: #161b22;
    --borda: #30363d;
    --texto: #c9d1d9;
    --texto-fraco: #8b949e;
    --acento: #58a6ff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--texto);
    font-family: 'Consolas', 'SF Mono', 'Courier New', monospace;
    margin: 0; padding: 32px;
  }}
  .topo {{
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 28px; flex-wrap: wrap; gap: 16px;
  }}
  h1 {{ margin: 0; font-size: 22px; letter-spacing: 0.5px; }}
  h1 .prefixo {{ color: var(--acento); }}
  .status-geral {{
    display: flex; align-items: center; gap: 10px;
    background: var(--bg-card); border: 1px solid var(--borda);
    padding: 10px 18px; border-radius: 6px;
  }}
  .status-dot {{ width: 12px; height: 12px; border-radius: 50%; box-shadow: 0 0 8px currentColor; }}
  .cards-fontes {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 14px; margin-bottom: 28px;
  }}
  .card-fonte {{
    background: var(--bg-card); border: 1px solid var(--borda);
    border-left: 4px solid; border-radius: 6px; padding: 14px 16px;
  }}
  .card-fonte-titulo {{ font-size: 14px; font-weight: bold; margin-bottom: 6px; }}
  .card-fonte-contagem {{ font-size: 13px; color: var(--texto); margin-bottom: 4px; }}
  .card-fonte-meta {{ font-size: 11px; color: var(--texto-fraco); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--bg-card); border: 1px solid var(--borda); border-radius: 6px; overflow: hidden; }}
  thead th {{
    text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--texto-fraco); padding: 10px 14px; border-bottom: 1px solid var(--borda);
  }}
  tbody td {{ padding: 10px 14px; border-bottom: 1px solid var(--borda); font-size: 13px; vertical-align: top; }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #1c2129; }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    border: 1px solid; font-size: 11px; font-weight: bold;
  }}
  .item-cell {{ color: var(--acento); }}
  .detalhe-cell {{ color: var(--texto-fraco); max-width: 420px; }}
  .sem-dados {{ color: var(--texto-fraco); text-align: center; padding: 24px; }}
  .rodape {{ margin-top: 24px; font-size: 11px; color: var(--texto-fraco); }}
</style>
</head>
<body>
  <div class="topo">
    <h1><span class="prefixo">&gt;_</span> Mini-SOC Dashboard</h1>
    <div class="status-geral">
      <span class="status-dot" style="background:{cor_status}; color:{cor_status};"></span>
      <span>Status geral: <strong style="color:{cor_status};">{status_geral}</strong></span>
      <span style="color:var(--texto-fraco);">| {total_geral} achado(s) — {total_criticos} crítico(s), {total_atencao} atenção</span>
    </div>
  </div>

  <div class="cards-fontes">{cards_fontes}
  </div>

  <table>
    <thead>
      <tr><th>Severidade</th><th>Detector</th><th>Categoria</th><th>Item</th><th>Detalhe</th></tr>
    </thead>
    <tbody>{linhas_tabela}
    </tbody>
  </table>

  <div class="rodape">Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} · mini_soc_dashboard.py</div>
</body>
</html>"""


# ----------------------------------------------------------------------------
# ORQUESTRAÇÃO
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Gera um dashboard HTML unificado a partir dos relatórios JSON dos detectores.")
    parser.add_argument("--pasta-relatorios", default=PASTA_RELATORIOS_PADRAO, help="Pasta onde estão os JSONs exportados pelos detectores.")
    parser.add_argument("--demo", action="store_true", help="Gera relatórios demo dos 3 detectores automaticamente antes de montar o dashboard.")
    parser.add_argument("--abrir", action="store_true", help="Abre o dashboard no navegador padrão após gerar.")
    args = parser.parse_args()

    pasta = args.pasta_relatorios
    if args.demo:
        gerar_relatorios_demo(pasta)

    if not os.path.isdir(pasta):
        sys.exit(f"ERRO: pasta de relatórios não encontrada: {pasta}")

    relatorios = carregar_relatorios(pasta)
    print(f"{len(relatorios)} relatório(s) carregado(s) de: {pasta}")

    html = gerar_html(relatorios)
    with open(ARQUIVO_SAIDA, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Dashboard gerado em: {ARQUIVO_SAIDA}")

    if args.abrir:
        webbrowser.open(f"file://{os.path.abspath(ARQUIVO_SAIDA)}")


if __name__ == "__main__":
    main()
