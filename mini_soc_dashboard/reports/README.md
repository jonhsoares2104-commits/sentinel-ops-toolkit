# Mini-SOC Dashboard

Unifica os relatórios JSON do Config Drift Detector, Password Spray Detector
e File Integrity Monitor numa única página HTML — um painel de SOC em
miniatura, gerado localmente, sem servidor, banco de dados ou dependência
externa (só biblioteca padrão do Python).

## Por que esse projeto existe

Os três detectores já respondiam perguntas diferentes: "a config mudou?",
"tem tentativa de invasão de senha?", "algum arquivo crítico foi alterado?".
Mas um analista olhando três saídas de terminal separadas, três horários
diferentes, perde o quadro geral. Um SOC de verdade (mesmo que gigante,
com Splunk/Sentinel/QRadar) resolve exatamente esse problema: agregação.
Esse projeto é uma versão em miniatura desse conceito — o primeiro passo
real na direção do "SIEM Caseiro".

## Como funciona

1. Cada detector roda normalmente e exporta seu relatório com
   `--saida-json caminho/arquivo.json` numa pasta compartilhada (`reports/`).
2. O dashboard varre essa pasta, lê todos os `.json` que seguem o schema
   padronizado (`fonte`, `gerado_em`, `achados`), e agrega tudo.
3. Gera um único arquivo HTML autocontido — pode ser aberto em qualquer
   navegador, sem precisar de servidor rodando.

## Decisões de design (e por quê)

- **HTML estático gerado, não servidor Flask/Django rodando.** Pra esse
  volume de dados (um relatório por detector, rodando periodicamente),
  um servidor web ativo seria complexidade desnecessária — mais uma coisa
  pra manter no ar e mais uma porta exposta no servidor. Um arquivo HTML
  gerado a cada execução é mais simples de operar e mais fácil de
  distribuir (pode até anexar num email).
- **Schema padronizado entre os detectores (`fonte`/`categoria`/`item`/
  `severidade`/`detalhe`).** Isso é o que permite qualquer detector novo se
  encaixar no dashboard sem precisar mudar o código de agregação — só
  seguir o schema. Prova de conceito de extensibilidade: adicionar um quarto
  detector no futuro é só rodar `--saida-json` apontando pra mesma pasta.
- **Nenhuma dependência externa (sem Flask, sem template engine).** O HTML é
  montado com f-strings do próprio Python. Decisão consciente: pra um script
  que times de infraestrutura vão rodar em servidores variados, cada
  dependência é mais uma coisa que pode não estar instalada ou dar
  conflito de versão.
- **Escape manual de HTML nos dados (`escapar()`).** Os "achados" vêm de
  dados de sistemas monitorados — nome de arquivo, nome de usuário, IP.
  Sem escapar `<`, `>`, `&`, um nome de arquivo malicioso poderia injetar
  HTML/JS na página do dashboard. Trata dado de fonte não confiável como
  não confiável, mesmo sendo "só" um relatório interno.

## Uso

```bash
# 1. Rodar os detectores reais, salvando na mesma pasta de relatórios
python config_drift_detector.py --saida-json reports/config_drift.json
python password_spray_detector.py --csv eventos.csv --saida-json reports/password_spray.json
python file_integrity_monitor.py --caminhos "C:\Scripts" --saida-json reports/file_integrity.json

# 2. Gerar o dashboard a partir dos relatórios
python mini_soc_dashboard.py --pasta-relatorios reports/ --abrir

# Ou testar tudo de uma vez, com dados simulados dos 3 detectores:
python mini_soc_dashboard.py --demo --abrir
```

O arquivo `mini_soc_dashboard.html` é regravado a cada execução — pra ter
histórico teria que salvar com nome/timestamp diferente a cada vez, ou
versionar externamente.

## Evolução natural (próximos passos, se quiser continuar)

- Rodar os 3 detectores + o dashboard numa única Scheduled Task diária
  (encadeando os comandos num `.bat`), então o painel já está atualizado
  toda manhã sem esforço manual.
- Guardar histórico: em vez de sobrescrever o HTML, salvar um snapshot por
  dia e adicionar um gráfico de tendência (achados críticos ao longo do
  tempo) — aí sim começa a virar de fato um "SIEM Caseiro".

## Limitações conhecidas (transparência > empolgação)

- Não há atualização em tempo real — é "gerar e abrir", não um painel que
  atualiza sozinho na tela. Rodar via `watchdog`/polling seria uma extensão
  possível, mas adicionaria complexidade e dependência que não se justifica
  para o volume de dados de um ambiente pequeno/médio.
- Não persiste histórico entre execuções (o HTML é sobrescrito toda vez).
- Não valida se o JSON de um detector foi adulterado — para um ambiente
  com múltiplos operadores, valeria considerar assinar os relatórios ou
  restringir permissão de escrita na pasta `reports/`.
