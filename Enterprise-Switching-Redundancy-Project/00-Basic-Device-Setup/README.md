00 - Basic Device Setup

Este directório contém as configurações base (bootstrap) para cada equipamento do laboratório/implantação. Cada ficheiro parte da suposição de um equipamento "novo" e aplica um conjunto mínimo de configurações necessárias para gestão segura e conectividade L3 onde faz sentido.

O propósito destas configurações é garantir um ponto de partida consistente antes de aplicar as configurações específicas de switching, HSRP, OSPF, VLANs e outros serviços que serão introduzidos nas pastas seguintes. Ou seja: os subprojetos posteriores assumem que estes ficheiros básicos já foram aplicados.

Notas:
- As passwords usam placeholders (`ADMIN_PASSWORD`, `ENABLE_PASSWORD`) — substitui por valores seguros no teu ambiente antes de aplicar.
- Não são definidos SVIs, VLANs, HSRP, OSPF ou subinterfaces aqui; esses itens são tratados nos subprojetos específicos.
- Cada ficheiro contém comentários e indicações de onde continuar a configuração nos passos seguintes.

## Verificação do bootstrap básico (comandos e resultados esperados)

Esta secção descreve comandos `show` e passos de teste para validar que o `basic-config` foi aplicado corretamente em cada equipamento antes de avançar para os subprojetos seguintes.

Recomenda-se executar estes comandos localmente via consola e remotamente via SSH (depois de gerar as chaves e activar SSH).

- Verificar identidade e domínio

	Comandos:

	- `show running-config | include hostname`
	- `show running-config | include ip domain-name`

	Resultados esperados:

	- O `hostname` deve corresponder ao nome do ficheiro (ex.: `R5`, `DIST-SW6`, `ACCESS-SW1`).
	- `ip domain-name porto-gaia.lab` deve estar presente.

- Verificar chave RSA e versão SSH

	Comandos:

	- `show crypto key mypubkey rsa`
	- `show ip ssh`

	Resultados esperados:

	- A chave RSA deve existir (gera com `crypto key generate rsa modulus 2048`).
	- `IP SSH Version` deve indicar `2`.

- Verificar utilizadores e enable secret

	Comandos:

	- `show running-config | include username`
	- `show running-config | include enable secret`

	Resultados esperados:

	- A conta `admin` com privilégio 15 deve aparecer (`username admin privilege 15 secret ...`).
	- `enable secret` deve estar configurado (o valor será encriptado e não legível em claro).

- Verificar interfaces L3 e estado

	Comandos:

	- `show ip interface brief`
	- `show interfaces status` (em switches)

	Resultados esperados:

	- As interfaces L3 configuradas devem apresentar o IP e estado `up` (quando o link físico estiver ligado): ex.: `10.51.0.5` em R5.
	- Em switches de acesso, as interfaces sem IP configurado devem aparecer `notconnect` ou `down` até serem utilizadas.

- Verificar linhas de consola e VTY

	Comandos:

	- `show running-config | section line con`
	- `show running-config | section line vty`

	Resultados esperados:

	- A consola (`line con 0`) deve ter `logging synchronous` e `exec-timeout 0 0` conforme os ficheiros.
	- As linhas `vty` devem estar configuradas com `login local`, `transport input ssh` e `exec-timeout 10 0`.

- Verificação básica de conectividade e teste SSH

	Passos:

	1. A partir de um dispositivo na mesma rede de gestão, tenta `ssh admin@<ip_do_dispositivo>` e confirma que a sessão inicia.
	2. Pinga um vizinho L3 configurado (ex.: em R5, `ping 10.51.0.6` para DIST-SW6) para validar conectividade L3.
	3. Gera tráfego simples numa porta de access (liga um PC ou emulador) e verifica `show mac address-table dynamic` no switch de acesso.

	Resultados esperados:

	- Conexão SSH activa (após aceitar a chave RSA). Se o SSH falhar, confirma `show ip ssh` e a existência da chave RSA.
	- `ping` para IPs L3 configurados deve responder quando o link físico e o dispositivo remoto estiverem activos.
	- A `mac address-table` deve registar entradas dinâmicas nas portas de access após tráfego.

- Logs e mensagens

	Comandos:

	- `show logging`
	- `show version`

	O que procurar:

	- Mensagens de erro no `show logging` relacionadas com interfaces ou negociações de trunk.
	- A versão do sistema e uptime com `show version` para confirmar que o equipamento arrancou correctamente.

Sequência recomendada curta

1. Verifica `hostname` e `ip domain-name`.
2. Confirma existência da chave RSA e versão do SSH.
3. Verifica utilizadores e `enable secret`.
4. Confirma IPs das interfaces com `show ip interface brief` e testa `ping` para vizinhos L3.
5. Testa login SSH e inspeciona `show logging` para mensagens relevantes.

Esta checklist deve ser incluída nos procedimentos de validação antes de seguir para as etapas de VLAN, HSRP, OSPF e demais configurações avançadas.

***

