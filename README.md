# [Home Lab] Threat Hunting e Detecção de LOLBins (certutil.exe) com Wazuh e Sysmon

## 📝 Descrição
Projeto prático de **Threat Hunting** focado em operações de SOC (Security Operations Center), demonstrando habilidades de análise de logs, investigação de endpoints (EDR) e triagem de eventos. Utilização da stack **Wazuh + Sysmon** para rastrear cadeia de processos, isolar ruídos (falsos positivos) e identificar o uso indevido de ferramentas nativas do Windows (*Living off the Land* - LOLBins).

## 🎯 1. Objetivo do Laboratório
* Simular a execução de comandos suspeitos utilizando binários nativos do Windows (Tática de *Living off the Land*).
* Utilizar o SIEM/XDR Wazuh em conjunto com o Microsoft Sysmon para detectar, investigar e analisar os artefatos gerados pelo ataque.
* Praticar a diferenciação entre atividades normais do sistema (falsos positivos) e anomalias de segurança.

## 🛠️ 2. Ambiente (Setup)
* **SIEM / EDR:** Wazuh Server.
* **Máquina Vítima:** Windows (Hostname: `win-victima` / Agent ID: `001`).
* **Coletores de Log:** Wazuh Agent e Microsoft Sysmon.

## ⚔️ 3. Simulação do Ataque (Execução)
Para simular um comportamento malicioso, foi executado um script via PowerShell que invocou o Prompt de Comando (`cmd.exe`) para utilizar a ferramenta nativa `certutil.exe`. 

O objetivo do comando foi calcular o hash de um binário do sistema, técnica frequentemente usada por atacantes para camuflar o download de *payloads* maliciosos ou decodificar arquivos base64 disfarçados de certificados.

**Comando executado:**
`"C:\Windows\system32\certutil.exe" -hashfile C:\windows\System32\cmd.exe MD5`

## 🔎 4. Investigação e Detecção (Threat Hunting)
Durante o monitoramento no painel de *Security Events* do Wazuh, a seguinte metodologia de triagem foi aplicada:

### Passo 1: Triagem Inicial e Falsos Positivos
Durante a filtragem por alertas de Alta Severidade (Level 12 a 14), foi identificado um alerta envolvendo o `explorer.exe` (Regra 61640: *Sysmon - Suspicious Process*).

Ao expandir os detalhes do log (campo `data.win.eventdata.parentImage`), identificou-se a origem:
`C:\Users\owerb\AppData\Local\Microsoft\OneDrive\OneDrive.exe`

**Ação:** O evento foi classificado e descartado como um **Falso Positivo**, visto que é um comportamento legítimo de sincronização do OneDrive com o Windows Explorer.

<img width="776" height="765" alt="image" src="https://github.com/user-attachments/assets/dde379c0-1418-42b4-8285-da3df47b558b" />
<img width="775" height="761" alt="image" src="https://github.com/user-attachments/assets/7afe2b88-8459-43c0-b5d8-920e2bbb6e6e" />


### Passo 2: Identificação da Ameaça Real
Removendo os filtros restritivos de severidade e buscando pela cadeia de execução, o Wazuh apontou com sucesso o comportamento anômalo do PowerShell acionando o CMD.

* **Regra Disparada:** `Powershell process spawned Windows command shell instance`
* **Processo Pai:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

### Passo 3: Análise Profunda (Deep Dive)
Expandindo os logs em formato JSON e analisando os campos coletados pelo Sysmon, foi possível confirmar a "arma do crime". No campo `data.win.eventdata.commandLine`, localizou-se a linha de comando exata utilizada no ataque.

```json
        "commandLine": "\\\"C:\\\\Windows\\\\system32\\\\certutil.exe\\\" -hashfile C:\\\\windows\\\\System32\\\\cmd.exe MD5",

            "data": {
      "win": {
        "eventdata": {
          "originalFileName": "CertUtil.exe",
