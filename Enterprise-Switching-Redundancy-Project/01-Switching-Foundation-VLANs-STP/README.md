01 - Switching Foundation (VLANs & STP)

Este directório contém as configurações de base para a camada de acesso: definições de VLAN, ajustes de Spanning Tree (Rapid-PVST), portas de acesso para estações e trunks simples para uplinks.

Notas importantes:
- Estas configurações assumem que o conteúdo da pasta `00-Basic-Device-Setup/` já foi aplicado em cada equipamento.
- Apenas são criadas VLANs, regras STP e o modo das portas (access/trunk). Não se alteram SVIs, HSRP, OSPF ou outras configurações L3 aqui.
- Os dispositivos `DIST-*` são tratados como routers L3 no âmbito do projecto e não recebem configurações de `switchport` nesta etapa.
- Os trunks configurados são simples (sem PortChannel). O uso de PortChannel e políticas adicionais será tratado em `02-Uplinks-PortChannel-and-PortSecurity/`.

Substitui os exemplos de interface pelos números reais correspondentes ao teu equipamento antes de aplicar.

Placeholder passwords e segurança
- Mantém os placeholders `ADMIN_PASSWORD` / `ENABLE_PASSWORD` nos ficheiros iniciais. Substitui por credenciais seguras no ambiente de produção.

Próximos passos
- Depois de aplicar estas configurações, podemos adicionar SVIs e gateway redundante em `03-Router-on-a-Stick-InterVLAN-Routing/` e `04-Redundant-Gateway-HSRP-and-DHCP/`.

## Verificação e comandos de diagnóstico

Esta secção descreve uma sequência de comandos `show` e os resultados esperados para validar que as VLANs e o Spanning Tree foram configurados corretamente. A ideia é dar aos engenheiros um checklist simples para validar o estado após aplicar as configurações.

Importante: execute estes comandos em cada `ACCESS-*` depois de aplicar o `basic-config` (pasta `00`) e a configuração desta pasta (`01`).

- Verificar VLANs

	Comandos:

	- `show vlan brief`
	- `show vlan id <vlan-id>` (ex.: `show vlan id 10`)
	- `show interface status`

	O que verificar / resultados esperados:

	- As VLANs configuradas devem aparecer na lista (ex.: VLAN 10, 20 para Porto; 73, 74, 75 para Gaia).
	- As portas de acesso devem mostrar o modo `access` e a VLAN correcta na coluna `VLAN` quando for o caso.
	- As interfaces configuradas como trunk devem aparecer como `trunk` e não como `access`.

- Verificar trunks

	Comandos:

	- `show interface trunk`
	- `show running-config interface <interface>` (ex.: `show run interface Ethernet0/1`)

	O que verificar / resultados esperados:

	- `show interface trunk` deve listar os trunks activos e as VLANs permitidas (ex.: `10,20` ou `73,74,75`).
	- A configuração `switchport trunk allowed vlan` deve corresponder às VLANs que definiste.
	- `switchport nonegotiate` activo nos uplinks quando definido.

- Verificar Spanning Tree (STP / Rapid-PVST)

	Comandos:

	- `show spanning-tree summary`
	- `show spanning-tree vlan <vlan-id>` (ex.: `show spanning-tree vlan 10`)
	- `show spanning-tree interface <interface>` (ex.: `show spanning-tree interface Ethernet0/1`)

	O que verificar / resultados esperados:

	- `show spanning-tree summary` deve indicar `Rapid-PVST` como modo activo.
	- Para cada VLAN, `show spanning-tree vlan <id>` deve indicar a root bridge e as portas em estado `Forwarding` ou `Blocking` conforme o desenho topológico.
	- Os uplinks devem normalmente estar em `Forwarding` e portas redundantes (se existirem) poderão estar `Blocking` até que PortChannel/agg seja configurado.

- Verificar tabela de endereços MAC e conectividade básica

	Comandos:

	- `show mac address-table dynamic`
	- `show ip interface brief` (quando aplicável para SVIs/mgmt)
	- `show logging` (verificar mensagens STP/errores)

	O que verificar / resultados esperados:

	- A `mac address-table` deve mostrar entradas dinâmicas aprendidas nas portas de access após tráfego de teste.
	- Se tiveres configurado uma SVI de gestão (neste projecto não foi definida), `show ip interface brief` vai mostrar o SVI com IP e estado `up/up`.

Sequência de teste recomendada (passo a passo)

1. Assegura que `basic-config` (00) está aplicado e que o equipamento tem gestão mínima (SSH, hostname, etc.).
2. Aplica os ficheiros `ACCESS-SW*-VLANs-STP.txt` correspondentes.
3. Em cada access switch, executa `show vlan brief` e `show interface status` para confirmar que as portas de access correspondem às VLANs previstas.
4. Verifica os trunks com `show interface trunk` e confirma as VLANs permitidas.
5. Verifica STP com `show spanning-tree summary` e `show spanning-tree vlan <id>`; confirma que não existe um root inesperado para as VLANs locais.
6. Gera tráfego simples (ex.: ping entre máquinas na mesma VLAN) e confirma que as entradas MAC aparecem com `show mac address-table dynamic`.

Resultados de referência (exemplo)

- `show vlan brief` deve listar algo semelhante a:

	VLAN Name                             Status    Ports
	---- -------------------------------- --------- -------------------------------
	10   VLAN10-Users                     active    Et0/0
	20   VLAN20-Users                     active    Et0/0

- `show interface trunk` deve mostrar o trunk Et0/1 com `Allowed VLANs: 10,20`.

- `show spanning-tree vlan 10` deverá indicar que a interface do uplink está em `Designated/Forwarding` e que o switch participa no STP Rapid‑PVST.

Se encontrares inconsistências

- Confirma que aplicaste o `basic-config` (ex.: `hostname`, `crypto key`, `username`) antes de aplicar os ficheiros de VLAN/STP.
- Verifica se a porta foi configurada correctamente (`switchport mode access` vs `switchport mode trunk`).
- Revisa cablagens físicas e a topologia — muitas anomalias STP têm origem em ligações físicas inesperadas.

Esta secção serve como checklist rápido para validar as configurações de switching antes de passares para agregação de uplinks (PortChannel), configuração de SVIs, HSRP e roteamento intersite.

***

