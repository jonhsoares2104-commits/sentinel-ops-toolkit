# Claude TI Pipeline

Pipeline de monitoramento de TI: coleta dados via PowerShell (scheduled
tasks, disco, serviços), envia para análise da API do Claude (severidade,
resumo executivo, comparação histórica) e gera um relatório em PDF —
com envio automático por email e auto-agendamento como Scheduled Task.

## Como funciona

1. **Coleta** — PowerShell lê scheduled tasks, uso de disco e serviços parados.
2. **Histórico** — compara com a execução anterior (salva em JSON).
3. **Análise** — a API do Claude classifica severidade, escreve resumo
   executivo e aponta o que mudou desde a última execução.
4. **Relatório** — PDF formatado (ReportLab), pronto para arquivar/enviar.
5. **Email** (opcional) — envia o PDF por SMTP, assunto muda conforme severidade.
6. **Agendamento** (opcional) — o script se auto-registra como Scheduled Task diária.

## Uso

```bash
# Testar sem depender de Windows nem de chave de API
python claude_ti_pipeline.py --demo

# Execução real
set ANTHROPIC_API_KEY=sua_chave_aqui
python claude_ti_pipeline.py

# Com envio por email
set SMTP_USER=ti@empresa.com
set SMTP_PASSWORD=sua_senha_ou_senha_de_app
set EMAIL_DESTINATARIOS=chefe@empresa.com
python claude_ti_pipeline.py --email

# Auto-instalar como Scheduled Task diária às 07:00, já enviando por email
python claude_ti_pipeline.py --instalar-agendamento --horario 07:00 --email
```

Ver a documentação completa (`documentacao_pipeline_ti.pdf`, gerada à parte)
para a lista de todas as variáveis de ambiente e critérios de severidade
configuráveis (`LIMITE_DISCO_CRITICO_PCT`, `PALAVRAS_CHAVE_TASK_CRITICA`,
`SERVICOS_CRITICOS`, entre outras).

## Decisões de design

- **Prompt força saída em JSON com schema fixo** — facilita parsear a
  resposta da API sem depender de regex em texto livre.
- **Retry com backoff** tanto na chamada da API quanto no envio de email —
  falha transitória de rede não derruba o pipeline inteiro.
- **Critérios de severidade configuráveis por variável de ambiente** — o
  que é "crítico" varia de empresa para empresa (nem todo ambiente tem SQL
  Server, por exemplo), então isso não devia estar hardcoded.
- **Scheduled Task não herda variáveis de ambiente de usuário** — por isso
  o script avisa explicitamente para configurar variáveis de **sistema**
  (`setx ... /M`) quando for rodar de forma agendada e desatendida.

## Limitações conhecidas

- Requer PowerShell e permissões administrativas para ler algumas
  informações de sistema (dependendo do ambiente).
- O histórico de comparação guarda apenas o snapshot da execução anterior,
  não uma linha do tempo completa — para isso, seria necessário versionar
  os snapshots por data.
