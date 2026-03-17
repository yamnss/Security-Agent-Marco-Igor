


16/03/2026.

Tenha cuidado ao instalar esse EDR sem verificar o Sources.list no Ubuntu. Testado em um 24.10 Desktop ele solicita a requisição para instalar pacotes da mais nova fonte fornecida pela Ubuntu porém o programa utiliza pacotes da Old Release.
A máquina atual testada já foi configurada para suportar o programa e conta com comandos simples instalados como o snap e o curl, além dos que são necessários para o funcionamento do agente mas esses são instalados a parte pelo próprio instalador
fornecido neste repositório. 
Testei apenas comando básicos de Nmap para realizar algum teste e analisar o arquivo de log gerado pelo EDR porém não tive sucesso até o momento. Estou me programando para criar uma máquina Kali que sirva como um atacante em sandbox para realizar o ataque. 

Comando para instaldor: sudo curl -o /opt/edr-agent/edr_agent.py \
https://raw.githubusercontent.com/yamnss/Security-Agent-Marco-Igor/main/edr.agent.py


17/03/2026

Primeiros testes feitos e update no código fonte. Testes com nmap e SSH tiveram sucesso. EDR detecta conexões simultâneas como o do nmap e avisa no arquivo de log para quem estiver monitorando. Conexões SSH que excedem 3 tentativas têm seu IP bloqueado e regra atualizada no Firewall para priorizar a negação. 
