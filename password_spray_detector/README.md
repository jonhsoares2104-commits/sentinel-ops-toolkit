# Password Spray Detector

Analisa logs de logon falho do Windows (Event ID 4625) e detecta o padrão
específico de **password spray** — distinto de brute force clássico —
agrupando tentativas por IP de origem e verificando quantas contas
diferentes foram atingidas dentro de uma janela de tempo.

## Por que esse projeto existe

A maioria das ferramentas de detecção de força bruta olha para "muitas
tentativas na mesma conta". Isso pega brute force, mas **não pega spray**:
no spray, o atacante testa 1-3 senhas populares (`Primavera2026!`, `Empresa@123`)
contra uma lista grande de contas, exatamente para ficar abaixo do limite de
bloqueio de conta de cada usuário individual. É uma técnica real e comum
(inclusive citada em advisories da Microsoft e CISA) porque contorna a
defesa mais comum que existe: a política de lockout.

## Como funciona

1. Lê eventos de logon falho (via CSV exportado do `Get-WinEvent`, ou dados
   simulados com `--demo`).
2. Agrupa por **IP de origem**.
3. Para cada IP, desliza uma janela de tempo (padrão: 30 minutos) e conta
   quantas **contas distintas** foram alvo dentro dela.
4. Se esse número passar do limite configurado (padrão: 5 contas), sinaliza
   como spray suspeito — com IP, janela, contas atingidas e recomendação.
5. Roda também uma detecção complementar de brute force clássico (mesma
   conta, muitas tentativas), só para contraste e cobertura mais completa.

## Decisões de design (e por quê)

- **Agrupamento por IP + contas distintas, não por volume total de eventos.**
  Um IP com 200 tentativas na mesma conta é brute force, não spray. O que
  importa pro spray é a *variedade de contas*, não o volume bruto.
- **Janela deslizante, não janela fixa (ex: "por hora cheia").** Um ataque
  que começa às 09:47 e termina às 10:15 seria dividido em duas janelas fixas
  de hora, cada uma parecendo abaixo do limite. A janela deslizante evita
  esse ponto cego.
- **Lista de IPs confiáveis (`IPS_CONFIAVEIS`).** Jump hosts, gateways VPN
  corporativos, ou scanners de vulnerabilidade internos geram falhas de
  logon em várias contas legitimamente (ex: durante testes de política de
  senha). Sem essa lista, o script geraria falso positivo constante nesses
  IPs conhecidos.
- **Detecção de brute force junto, não como projeto separado.** Um analista
  de segurança vendo o relatório precisa saber os dois padrões ao mesmo
  tempo — muitas vezes um ataque usa as duas táticas em sequência.

## Uso

```bash
# Testar com dados simulados (spray + brute force + ruído normal)
python password_spray_detector.py --demo

# Uso real: primeiro exportar os eventos do Windows
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  Select-Object TimeCreated,
    @{N='Usuario';E={$_.Properties[5].Value}},
    @{N='IPOrigem';E={$_.Properties[19].Value}} |
  Export-Csv eventos_4625.csv -NoTypeInformation -Encoding UTF8

# Depois analisar o CSV exportado
python password_spray_detector.py --csv eventos_4625.csv

# Ajustando sensibilidade (ambiente pequeno pode usar limite menor)
python password_spray_detector.py --csv eventos_4625.csv --min-contas 3 --janela-minutos 15
```

## Limitações conhecidas (transparência > empolgação)

- Depende de auditoria de logon habilitada via GPO
  (`Audit Logon Events` / `Audit Logon` em Advanced Audit Policy) — sem
  isso, o Event ID 4625 não é gerado.
- Não resolve geolocalização de IP nem correlaciona com threat intel feeds
  automaticamente — seria uma extensão natural (ex: consultar uma API de
  reputação de IP antes de reportar).
- A janela deslizante atual é O(n²) no pior caso (compara cada evento contra
  os seguintes). Para volumes muito grandes de log, valeria a pena trocar
  por uma abordagem com ponteiros de janela (two-pointer), que é O(n).
