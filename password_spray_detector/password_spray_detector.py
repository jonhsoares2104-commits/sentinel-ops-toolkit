"""
password_spray_detector.py
============================
Detecta padrão de "password spray" em logs de autenticação falha do Windows
(Event ID 4625).

DIFERENÇA IMPORTANTE entre os dois ataques:
  - Brute force clássico : MUITAS tentativas contra POUCAS contas.
    Fácil de detectar (a conta bloqueia, alarme dispara rápido).
  - Password spray       : POUCAS tentativas (1-3 senhas comuns) contra
    MUITAS contas diferentes, geralmente vindas da mesma origem (IP) num
    intervalo curto de tempo. Passa despercebido por regras de bloqueio de
    conta tradicionais, porque nenhuma conta individual recebe tentativas
    suficientes pra travar.

Esse script foca especificamente no segundo padrão: agrupa falhas de logon
por IP de origem dentro de uma janela de tempo, e sinaliza quando o número de
CONTAS DISTINTAS atingidas por aquele IP passa de um limite configurável.

FONTE DE DADOS:
No Windows real, os eventos 4625 podem ser exportados assim (rode como admin,
com auditoria de logon habilitada via GPO):

    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
      Select-Object TimeCreated,
        @{N='Usuario';E={$_.Properties[5].Value}},
        @{N='IPOrigem';E={$_.Properties[19].Value}} |
      Export-Csv eventos_4625.csv -NoTypeInformation -Encoding UTF8

Uso:
    python password_spray_detector.py --csv eventos_4625.csv
    python password_spray_detector.py --demo     # dados simulados, sem CSV
"""

import argparse
import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta
import json

# ----------------------------------------------------------------------------
# CONFIGURAÇÃO (limites ajustáveis por linha de comando)
# ----------------------------------------------------------------------------
JANELA_PADRAO_MINUTOS = 30
MIN_CONTAS_DISTINTAS_PADRAO = 5   # a partir de quantas contas diferentes já é suspeito
IPS_CONFIAVEIS = {"10.0.0.1"}     # ex: gateway VPN interno, jump host, etc — ajuste conforme seu ambiente


# ----------------------------------------------------------------------------
# LEITURA DO CSV (exportado do Get-WinEvent)
# ----------------------------------------------------------------------------
def ler_eventos_csv(caminho: str) -> list[dict]:
    eventos = []
    with open(caminho, "r", encoding="utf-8-sig") as f:
        leitor = csv.DictReader(f)
        for linha in leitor:
            eventos.append({
                "timestamp": datetime.fromisoformat(linha["TimeCreated"]),
                "usuario": linha["Usuario"],
                "ip_origem": linha["IPOrigem"],
            })
    return eventos


def eventos_demo() -> list[dict]:
    """
    Simula um trecho de log com 3 situações diferentes:
    1. Um IP fazendo spray real (várias contas, poucas tentativas cada)
    2. Um IP fazendo brute force numa conta só (não deveria disparar spray)
    3. Ruído normal (falhas isoladas de usuário digitando senha errada)
    """
    base = datetime(2026, 7, 9, 14, 0, 0)
    eventos = []

    # 1. Password spray: IP 203.0.113.55 tentando 8 contas diferentes em 12 minutos
    contas_alvo = ["jsilva", "mferreira", "acosta", "rlima", "pcardoso", "tsouza", "administrator", "vpnuser"]
    for i, conta in enumerate(contas_alvo):
        eventos.append({"timestamp": base + timedelta(minutes=i * 1.5), "usuario": conta, "ip_origem": "203.0.113.55"})

    # 2. Brute force: mesma conta "jsilva" apanhando de outro IP, tentativa após tentativa
    for i in range(6):
        eventos.append({"timestamp": base + timedelta(minutes=i * 0.5), "usuario": "jsilva", "ip_origem": "198.51.100.20"})

    # 3. Ruído normal: usuários errando a própria senha, IPs internos variados
    eventos.append({"timestamp": base + timedelta(minutes=5), "usuario": "mferreira", "ip_origem": "10.20.30.40"})
    eventos.append({"timestamp": base + timedelta(minutes=40), "usuario": "rlima", "ip_origem": "10.20.30.41"})

    return sorted(eventos, key=lambda e: e["timestamp"])


# ----------------------------------------------------------------------------
# DETECÇÃO
# ----------------------------------------------------------------------------
def detectar_spray(eventos: list[dict], janela_minutos: int, min_contas: int) -> list[dict]:
    """
    Agrupa eventos por IP de origem. Para cada IP, desliza uma janela de tempo
    e verifica se o número de CONTAS DISTINTAS atingidas dentro da janela
    ultrapassa o limite configurado.
    """
    por_ip = defaultdict(list)
    for e in eventos:
        por_ip[e["ip_origem"]].append(e)

    achados = []
    for ip, lista in por_ip.items():
        if ip in IPS_CONFIAVEIS:
            continue
        lista.sort(key=lambda e: e["timestamp"])

        # Janela deslizante simples: para cada evento, olha pra frente até o limite da janela
        for i, evento_inicio in enumerate(lista):
            fim_janela = evento_inicio["timestamp"] + timedelta(minutes=janela_minutos)
            na_janela = [e for e in lista[i:] if e["timestamp"] <= fim_janela]
            contas_distintas = {e["usuario"] for e in na_janela}

            if len(contas_distintas) >= min_contas:
                achados.append({
                    "ip_origem": ip,
                    "inicio_janela": evento_inicio["timestamp"],
                    "fim_janela": na_janela[-1]["timestamp"],
                    "qtd_contas_distintas": len(contas_distintas),
                    "qtd_tentativas": len(na_janela),
                    "contas_alvo": sorted(contas_distintas),
                })
                break  # já reportou esse IP, não precisa continuar deslizando

    return achados


def detectar_brute_force_classico(eventos: list[dict], min_tentativas: int = 5) -> list[dict]:
    """Detecção complementar: mesma conta, muitas tentativas, de um ou poucos IPs — útil para contraste."""
    por_conta = defaultdict(list)
    for e in eventos:
        por_conta[e["usuario"]].append(e)

    achados = []
    for conta, lista in por_conta.items():
        if len(lista) >= min_tentativas:
            ips_origem = sorted({e["ip_origem"] for e in lista})
            achados.append({
                "usuario": conta,
                "qtd_tentativas": len(lista),
                "ips_origem": ips_origem,
            })
    return achados


# ----------------------------------------------------------------------------
# RELATÓRIO
# ----------------------------------------------------------------------------
def imprimir_relatorio(spray: list[dict], brute_force: list[dict]) -> None:
    print(f"\n{'=' * 65}")
    print("RELATÓRIO DE DETECÇÃO — TENTATIVAS DE AUTENTICAÇÃO SUSPEITAS")
    print(f"{'=' * 65}\n")

    if spray:
        print(f"🚨 PASSWORD SPRAY detectado — {len(spray)} origem(ns) suspeita(s):\n")
        for s in spray:
            print(f"  IP de origem : {s['ip_origem']}")
            print(f"  Janela       : {s['inicio_janela']} até {s['fim_janela']}")
            print(f"  Contas alvo  : {s['qtd_contas_distintas']} distintas em {s['qtd_tentativas']} tentativas")
            print(f"                 {', '.join(s['contas_alvo'])}")
            print(f"  Recomendação : bloquear IP no firewall, forçar MFA/reset nas contas listadas.\n")
    else:
        print("Nenhum padrão de password spray detectado nos dados analisados.\n")

    if brute_force:
        print(f"⚠️  BRUTE FORCE clássico detectado — {len(brute_force)} conta(s) alvo:\n")
        for b in brute_force:
            print(f"  Conta        : {b['usuario']}")
            print(f"  Tentativas   : {b['qtd_tentativas']}")
            print(f"  IPs origem   : {', '.join(b['ips_origem'])}")
            print(f"  Recomendação : verificar bloqueio de conta, revisar política de lockout.\n")
    else:
        print("Nenhum padrão de brute force clássico detectado.\n")


def salvar_relatorio_json(spray: list[dict], brute_force: list[dict], caminho: str) -> None:
    """Exporta achados no mesmo schema padronizado (categoria/item/severidade/detalhe)
    usado pelos outros detectores, para consumo pelo Mini-SOC Dashboard."""
    achados = []
    for s in spray:
        achados.append({
            "categoria": "password_spray",
            "item": s["ip_origem"],
            "severidade": "CRITICO",
            "detalhe": (
                f"{s['qtd_contas_distintas']} contas distintas em {s['qtd_tentativas']} "
                f"tentativas entre {s['inicio_janela']} e {s['fim_janela']}: "
                f"{', '.join(s['contas_alvo'])}"
            ),
        })
    for b in brute_force:
        achados.append({
            "categoria": "brute_force",
            "item": b["usuario"],
            "severidade": "ATENCAO",
            "detalhe": f"{b['qtd_tentativas']} tentativas vindas de: {', '.join(b['ips_origem'])}",
        })

    with open(caminho, "w", encoding="utf-8") as f:
        json.dump({
            "fonte": "password_spray",
            "gerado_em": datetime.now().isoformat(timespec="seconds"),
            "total_achados": len(achados),
            "achados": achados,
        }, f, ensure_ascii=False, indent=2)


# ----------------------------------------------------------------------------
# ORQUESTRAÇÃO
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Detecta password spray e brute force em logs de logon falho do Windows (Event ID 4625).")
    parser.add_argument("--csv", help="Caminho do CSV exportado via Get-WinEvent (colunas: TimeCreated, Usuario, IPOrigem).")
    parser.add_argument("--demo", action="store_true", help="Roda com dados simulados, sem precisar de CSV.")
    parser.add_argument("--janela-minutos", type=int, default=JANELA_PADRAO_MINUTOS, help=f"Janela de tempo em minutos (padrão: {JANELA_PADRAO_MINUTOS}).")
    parser.add_argument("--min-contas", type=int, default=MIN_CONTAS_DISTINTAS_PADRAO, help=f"Mínimo de contas distintas para considerar spray (padrão: {MIN_CONTAS_DISTINTAS_PADRAO}).")
    parser.add_argument("--saida-json", default=None, help="Caminho para salvar o relatório em JSON (opcional, formato padronizado para o Mini-SOC Dashboard).")
    args = parser.parse_args()

    if args.demo:
        print("Rodando com dados simulados...")
        eventos = eventos_demo()
    elif args.csv:
        eventos = ler_eventos_csv(args.csv)
    else:
        parser.error("Informe --csv <arquivo> ou use --demo para testar com dados simulados.")

    spray = detectar_spray(eventos, args.janela_minutos, args.min_contas)
    brute_force = detectar_brute_force_classico(eventos)
    imprimir_relatorio(spray, brute_force)

    if args.saida_json:
        salvar_relatorio_json(spray, brute_force, args.saida_json)
        print(f"Relatório salvo em: {args.saida_json}")


if __name__ == "__main__":
    main()
