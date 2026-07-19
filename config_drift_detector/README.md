# Config Drift Detector

Detecta mudanças de configuração em servidores Windows que aconteceram fora do
processo formal de change management — serviços que mudaram de status/tipo de
inicialização, chaves de registro sensíveis alteradas, e regras de firewall
novas ou removidas.

## Por que esse projeto existe

Na prática, boa parte dos incidentes de produção não é "quebrou sozinho" — é
uma mudança manual que alguém fez ("só pra testar", "resolvendo um chamado
rápido") e esqueceu de documentar ou reverter. Ferramentas de gestão de
configuração enterprise (Puppet, Ansible, SCCM) resolvem isso em escala, mas
custam tempo de implantação e licenciamento. Esse script cobre o caso de uso
mais comum — poucos servidores críticos, sem orçamento pra suite enterprise —
com uma abordagem simples de "tirar uma foto aprovada e comparar depois".

## Como funciona

1. **Baseline**: você roda `--criar-baseline` uma vez, num estado que você
   confirma que está correto. Isso vira o "estado aprovado".
2. **Checagem periódica**: rodando sem flags, o script coleta o estado atual
   e compara contra o baseline salvo.
3. **Classificação por severidade**: nem todo drift é igual. Um serviço de
   antivírus parado é `CRITICO`. Uma regra de firewall nova é `ATENCAO` —
   pode ser legítima, mas precisa ser confirmada.

## Decisões de design (e por quê)

- **Lista de itens monitorados é explícita, não "monitorar tudo".**
  Monitorar toda chave de registro do Windows geraria ruído absurdo e
  ninguém prestaria atenção nos alertas depois de uma semana. A lista em
  `SERVICOS_MONITORADOS` e `CHAVES_REGISTRO_MONITORADAS` é curada
  propositalmente — o valor está em focar no que realmente importa pra
  segurança e disponibilidade.
- **Severidade é regra de negócio, não always-CRITICO.** Um `RemoteRegistry`
  que liga sozinho é crítico (normalmente indica acesso remoto ao registro
  habilitado sem necessidade). Uma regra de firewall nova é só atenção,
  porque pode ter sido um chamado legítimo de suporte.
- **Baseline em JSON versionável.** O arquivo `baseline.json` pode (e
  deveria) ser commitado num repositório Git — assim toda mudança no
  "estado aprovado" fica auditável também.

## Uso

```bash
# Primeira vez: aprovar o estado atual como baseline
python config_drift_detector.py --criar-baseline

# Checagens seguintes (rodar via Scheduled Task, por exemplo)
python config_drift_detector.py

# Salvando o relatório em JSON, pra integrar com outro sistema
python config_drift_detector.py --saida-json relatorio_drift.json

# Testar sem depender de Windows/PowerShell (dados simulados)
python config_drift_detector.py --demo
```

## Limitações conhecidas (transparência > empolgação)

- Precisa rodar com permissão de leitura de registro e serviços (idealmente
  como administrador).
- Comparação é ponto-a-ponto: não guarda histórico de todas as mudanças,
  só o baseline atual vs. o estado agora. Uma extensão natural seria salvar
  cada checagem com timestamp pra ter uma linha do tempo completa de drift.
- Lista de itens monitorados é fixa no código — numa v2, faria sentido
  externalizar isso pra um YAML de configuração.
