"""
config_drift_detector.py
=========================
Detecta "drift" de configuração em servidores Windows: compara o estado atual
contra um baseline aprovado e aponta o que mudou fora do processo formal de
change management.

Por que isso importa: a causa de muito incidente em produção não é "quebrou
sozinho", é uma mudança manual que ninguém documentou (alguém mexeu num
serviço, abriu uma porta no firewall, mudou uma chave de registro "só para
testar" e esqueceu de reverter). Esse script não impede a mudança, mas garante
que ela não passe despercebida.

FLUXO:
  1. capturar_baseline()  -> roda uma vez, salva o "estado aprovado" em JSON
  2. capturar_atual()     -> roda periodicamente, coleta o estado agora
  3. comparar()           -> diff estruturado entre baseline e atual
  4. relatorio()          -> imprime/exporta o que mudou, com severidade

Uso:
    python config_drift_detector.py --criar-baseline        # primeira vez
    python config_drift_detector.py                          # checagens seguintes
    python config_drift_detector.py --demo                    # roda com dados simulados
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime

BASELINE_FILE = os.path.join(os.path.dirname(__file__), "baseline.json")

# Serviços que consideramos sensíveis o suficiente para monitorar de perto.
# Mudança de StartType ou Status nesses serviços é sempre reportada.
SERVICOS_MONITORADOS = [
    "WinDefend",     # Windows Defender
    "wuauserv",      # Windows Update
    "EventLog",      # Log de eventos do Windows
    "RemoteRegistry",
    "TermService",   # Remote Desktop
]

# Chaves de registro sensíveis (ex: coisas que afetam segurança/RDP/UAC).
# Formato: (hive, path, nome_do_valor)
CHAVES_REGISTRO_MONITORADAS = [
    (r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"),
    (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
    (r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"),
]


# ----------------------------------------------------------------------------
# COLETA (PowerShell)
# ----------------------------------------------------------------------------
def rodar_powershell(comando: str) -> str:
    resultado = subprocess.run(
        ["powershell", "-NoProfile", "-Command", comando],
        capture_output=True, text=True, timeout=60
    )
    if resultado.returncode != 0:
        raise RuntimeError(f"PowerShell falhou: {resultado.stderr.strip()}")
    return resultado.stdout.strip()


def coletar_estado_atual() -> dict:
    """Coleta serviços monitorados, valores de registro e regras de firewall ativas."""
    servicos = {}
    for nome in SERVICOS_MONITORADOS:
        saida = rodar_powershell(
            f"Get-Service -Name {nome} -ErrorAction SilentlyContinue | "
            f"Select-Object Name, Status, StartType | ConvertTo-Json"
        )
        if saida:
            servicos[nome] = json.loads(saida)

    registro = {}
    for hive_path, valor in CHAVES_REGISTRO_MONITORADAS:
        chave = f"{hive_path}\\{valor}"
        saida = rodar_powershell(
            f"(Get-ItemProperty -Path '{hive_path.replace(':', '')}' -Name '{valor}' "
            f"-ErrorAction SilentlyContinue).{valor}"
        )
        registro[chave] = saida if saida else None

    firewall_json = rodar_powershell(
        "Get-NetFirewallRule -Enabled True -Direction Inbound | "
        "Select-Object DisplayName, Action | ConvertTo-Json"
    )
    firewall = json.loads(firewall_json) if firewall_json else []

    return {
        "coletado_em": datetime.now().isoformat(timespec="seconds"),
        "servicos": servicos,
        "registro": registro,
        "firewall_regras_ativas": sorted([r["DisplayName"] for r in firewall]) if firewall else [],
    }


# ----------------------------------------------------------------------------
# DADOS DEMO (simula um baseline "aprovado" e um estado atual com drift)
# ----------------------------------------------------------------------------
def baseline_demo() -> dict:
    return {
        "coletado_em": "2026-06-01T09:00:00",
        "servicos": {
            "WinDefend": {"Name": "WinDefend", "Status": "Running", "StartType": "Automatic"},
            "wuauserv": {"Name": "wuauserv", "Status": "Running", "StartType": "Automatic"},
            "EventLog": {"Name": "EventLog", "Status": "Running", "StartType": "Automatic"},
            "RemoteRegistry": {"Name": "RemoteRegistry", "Status": "Stopped", "StartType": "Disabled"},
            "TermService": {"Name": "TermService", "Status": "Running", "StartType": "Automatic"},
        },
        "registro": {
            r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections": "0",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA": "1",
            r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1": "0",
        },
        "firewall_regras_ativas": ["Core Networking - DNS", "Remote Desktop", "File and Printer Sharing"],
    }


def atual_demo() -> dict:
    return {
        "coletado_em": datetime.now().isoformat(timespec="seconds"),
        "servicos": {
            "WinDefend": {"Name": "WinDefend", "Status": "Running", "StartType": "Automatic"},
            "wuauserv": {"Name": "wuauserv", "Status": "Stopped", "StartType": "Disabled"},  # <- drift
            "EventLog": {"Name": "EventLog", "Status": "Running", "StartType": "Automatic"},
            "RemoteRegistry": {"Name": "RemoteRegistry", "Status": "Running", "StartType": "Automatic"},  # <- drift
            "TermService": {"Name": "TermService", "Status": "Running", "StartType": "Automatic"},
        },
        "registro": {
            r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections": "0",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA": "0",  # <- drift (UAC desligado!)
            r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1": "0",
        },
        "firewall_regras_ativas": [
            "Core Networking - DNS", "Remote Desktop", "File and Printer Sharing",
            "Regra Temporaria Suporte",  # <- drift (nova regra não documentada)
        ],
    }


# ----------------------------------------------------------------------------
# COMPARAÇÃO / DIFF
# ----------------------------------------------------------------------------
def classificar_severidade_servico(nome: str, antes: dict, agora: dict) -> str:
    if antes["Status"] == agora["Status"] and antes["StartType"] == agora["StartType"]:
        return None
    # Serviço de segurança que parou ou virou manual/desabilitado = crítico
    if nome in ("WinDefend", "wuauserv", "EventLog") and (
        agora["Status"] != "Running" or agora["StartType"] in ("Disabled", "Manual")
    ):
        return "CRITICO"
    # RemoteRegistry ligado é sempre suspeito (normalmente deve ficar desligado)
    if nome == "RemoteRegistry" and agora["Status"] == "Running":
        return "CRITICO"
    return "ATENCAO"


def comparar(baseline: dict, atual: dict) -> list[dict]:
    """Retorna uma lista de itens com drift detectado, cada um com severidade e detalhe."""
    achados = []

    # --- Serviços ---
    for nome, estado_atual in atual["servicos"].items():
        estado_base = baseline["servicos"].get(nome)
        if not estado_base:
            continue
        sev = classificar_severidade_servico(nome, estado_base, estado_atual)
        if sev:
            achados.append({
                "categoria": "servico",
                "item": nome,
                "severidade": sev,
                "detalhe": (
                    f"Status: {estado_base['Status']} -> {estado_atual['Status']} | "
                    f"StartType: {estado_base['StartType']} -> {estado_atual['StartType']}"
                ),
            })

    # --- Registro ---
    for chave, valor_base in baseline["registro"].items():
        valor_atual = atual["registro"].get(chave)
        if valor_atual != valor_base:
            sev = "CRITICO" if "EnableLUA" in chave or "SMB1" in chave else "ATENCAO"
            achados.append({
                "categoria": "registro",
                "item": chave,
                "severidade": sev,
                "detalhe": f"Valor: {valor_base} -> {valor_atual}",
            })

    # --- Firewall ---
    regras_base = set(baseline["firewall_regras_ativas"])
    regras_atual = set(atual["firewall_regras_ativas"])
    for nova_regra in regras_atual - regras_base:
        achados.append({
            "categoria": "firewall",
            "item": nova_regra,
            "severidade": "ATENCAO",
            "detalhe": "Nova regra de firewall ativa, não presente no baseline.",
        })
    for regra_removida in regras_base - regras_atual:
        achados.append({
            "categoria": "firewall",
            "item": regra_removida,
            "severidade": "ATENCAO",
            "detalhe": "Regra do baseline não está mais ativa (foi removida ou desabilitada).",
        })

    return achados


# ----------------------------------------------------------------------------
# RELATÓRIO (console)
# ----------------------------------------------------------------------------
def imprimir_relatorio(achados: list[dict]) -> None:
    if not achados:
        print("Nenhum drift detectado. Configuração bate com o baseline. ✅")
        return

    criticos = [a for a in achados if a["severidade"] == "CRITICO"]
    atencao = [a for a in achados if a["severidade"] == "ATENCAO"]

    print(f"\n{'=' * 60}")
    print(f"DRIFT DETECTADO — {len(achados)} item(ns) fora do baseline")
    print(f"  {len(criticos)} crítico(s) | {len(atencao)} atenção")
    print(f"{'=' * 60}\n")

    for grupo, titulo in [(criticos, "CRÍTICO"), (atencao, "ATENÇÃO")]:
        if not grupo:
            continue
        print(f"--- {titulo} ---")
        for a in grupo:
            print(f"  [{a['categoria'].upper()}] {a['item']}")
            print(f"      {a['detalhe']}")
        print()


def salvar_relatorio_json(achados: list[dict], caminho: str) -> None:
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump({
            "fonte": "config_drift",
            "gerado_em": datetime.now().isoformat(timespec="seconds"),
            "total_achados": len(achados),
            "achados": achados,
        }, f, ensure_ascii=False, indent=2)


# ----------------------------------------------------------------------------
# ORQUESTRAÇÃO
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Detecta drift de configuração contra um baseline aprovado.")
    parser.add_argument("--criar-baseline", action="store_true", help="Captura o estado atual como novo baseline aprovado.")
    parser.add_argument("--demo", action="store_true", help="Roda com dados simulados (baseline e estado atual fictícios).")
    parser.add_argument("--saida-json", default=None, help="Caminho para salvar o relatório em JSON (opcional).")
    args = parser.parse_args()

    if args.criar_baseline:
        print("Capturando estado atual como novo baseline...")
        estado = baseline_demo() if args.demo else coletar_estado_atual()
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(estado, f, ensure_ascii=False, indent=2)
        print(f"Baseline salvo em: {BASELINE_FILE}")
        return

    if args.demo:
        baseline = baseline_demo()
        atual = atual_demo()
    else:
        if not os.path.exists(BASELINE_FILE):
            sys.exit("ERRO: nenhum baseline encontrado. Rode primeiro com --criar-baseline.")
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        atual = coletar_estado_atual()

    achados = comparar(baseline, atual)
    imprimir_relatorio(achados)

    if args.saida_json:
        salvar_relatorio_json(achados, args.saida_json)
        print(f"Relatório salvo em: {args.saida_json}")


if __name__ == "__main__":
    main()
