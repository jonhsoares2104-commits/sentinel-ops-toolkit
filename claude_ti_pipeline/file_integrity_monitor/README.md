# File Integrity Monitor (FIM)

Monitora integridade de arquivos críticos via hash SHA-256: detecta arquivo
alterado, removido, ou novo arquivo não esperado numa pasta monitorada.

## Por que esse projeto existe

Config Drift Detector olha serviços/registro/firewall. Password Spray
Detector olha tentativas de logon. Nenhum dos dois olha **arquivo**. E
arquivo é onde a maioria dos comprometimentos deixa rastro: um binário
substituído, uma DLL nova numa pasta de sistema, um script de inicialização
alterado para baixar payload. File Integrity Monitoring é item obrigatório
em praticamente todo framework de compliance sério (PCI-DSS Requirement 11.5,
CIS Control 3) exatamente por isso.

## Como funciona

1. **Baseline**: `--criar-baseline` calcula o hash SHA-256 de cada arquivo
   nos caminhos informados (arquivos individuais ou pastas inteiras) e salva.
2. **Checagem**: sem essa flag, recalcula os hashes agora e compara.
3. Três tipos de achado, todos reportados:
   - **Alterado**: hash mudou (conteúdo diferente do baseline)
   - **Removido**: estava no baseline, não existe mais
   - **Novo**: existe agora, não estava no baseline

## Decisões de design (e por quê)

- **Hash SHA-256, não data de modificação.** Data de modificação é
  trivialmente forjável (`Set-ItemProperty` muda o timestamp sem alterar
  conteúdo). Hash criptográfico garante que qualquer mudança de conteúdo,
  por menor que seja, é detectada.
- **Leitura em blocos (64KB), não arquivo inteiro na memória.** Para
  monitorar pastas com arquivos grandes sem estourar memória — decisão
  simples, mas que evita um problema real em produção.
- **Extensões ignoradas configuráveis (`.log`, `.tmp`, `.bak`).** Sem isso,
  monitorar uma pasta de aplicação geraria alerta constante por arquivos que
  mudam por natureza (logs rotacionando, por exemplo), degradando a confiança
  no alerta ao longo do tempo.
- **Severidade por tipo de arquivo, não por tipo de mudança.** Um `.ps1` ou
  o arquivo `hosts` alterado é sempre crítico, não importa se foi
  "alterado" ou "novo" — o que importa é o que aquele arquivo específico
  pode fazer no sistema.

## Uso

```bash
# Primeira vez: aprovar o estado atual como baseline
python file_integrity_monitor.py --criar-baseline --caminhos "C:\Windows\System32\drivers\etc\hosts,C:\Scripts"

# Checagens seguintes
python file_integrity_monitor.py --caminhos "C:\Windows\System32\drivers\etc\hosts,C:\Scripts"

# Exportando para o Mini-SOC Dashboard
python file_integrity_monitor.py --caminhos "C:\Scripts" --saida-json relatorio_fim.json

# Testar sem precisar apontar caminhos reais (cria um ambiente demo sozinho)
python file_integrity_monitor.py --demo --criar-baseline
python file_integrity_monitor.py --demo   # simula edição, remoção e arquivo novo suspeito
```

## Limitações conhecidas (transparência > empolgação)

- Não detecta mudança *durante* o processo de escrita (não é um monitor em
  tempo real via `FileSystemWatcher`) — é um comparador ponto-a-ponto,
  pensado para rodar periodicamente (ex: a cada hora via Scheduled Task).
- Calcular hash de pastas muito grandes tem custo de I/O; para volumes
  grandes, o ideal é apontar para pastas/arquivos específicos e sensíveis,
  não a árvore inteira do sistema.
- Não distingue "mudança legítima de patch" de "mudança maliciosa" — ele
  sinaliza o que mudou, quem decide se é esperado é o analista. Uma extensão
  natural seria integrar com uma janela de manutenção conhecida (ex: ignorar
  mudanças durante Patch Tuesday).
