04 - Redundant Gateway (HSRP) & DHCP Relay

Esta pasta contém as configurações para criar gateways redundantes (HSRP) nas VLANs de Porto e configurar o R5 como servidor DHCP com relay (ip helper) nos distribution switches.

Ficheiros incluídos
- `DIST-SW6-HSRP-DHCPRelay.txt` — DIST-SW6 configurado como ACTIVE (priority 110) para os grupos HSRP 10 e 20; ip helper apontando para R5 (10.51.0.5).
- `DIST-SW7-HSRP-DHCPRelay.txt` — DIST-SW7 configurado como STANDBY (priority 100) para os grupos HSRP 10 e 20; ip helper apontando para R5 via 10.52.0.5.
- `R5-DHCP-Server.txt` — Configuração de pools DHCP para VLAN10 e VLAN20 no R5; exclusão das primeiras 10 IPs para infra/gateway.

Comportamento planeado
- VIPs (gateways): VLAN10 -> `10.10.0.1`, VLAN20 -> `10.20.0.1`.
- DIST-SW6 deverá assumir Active (priority 110) e responder às requisições ARP para o VIPs; DIST-SW7 será Standby.
- Requests DHCP provenientes das VLANs serão encaminhados (ip helper) para o R5, que atribui IPs de acordo com os pools.

Verificação e comandos de diagnóstico

- Verificar estado HSRP

  Comandos:

  - `show standby brief`
  - `show standby`
  - `show standby vlan <vlan-id>` (se suportado)

  Resultados esperados:

  - Em `DIST-SW6`, os grupos 10 e 20 devem aparecer como `Active` (priority 110).
  - Em `DIST-SW7`, os mesmos grupos devem aparecer como `Standby` (priority 100).

- Verificar DHCP Relay e bindings

  Comandos (no DIST e no R5):

  - `show ip interface brief` (verificar subinterfaces respondem `up`)
  - `show ip dhcp binding` (no R5)
  - `show ip dhcp server statistics` (se disponível)
  - `show running-config interface <subinterface>` (verifica `ip helper-address`)

  Resultados esperados:

  - `show ip dhcp binding` no R5 deverá mostrar leases atribuídos após clientes pedirem DHCP.
  - `show running-config interface Ethernet1/0.10` (DIST-SW6) deve listar `ip helper-address 10.51.0.5`.

- Testes práticos recomendados

1. Em ACCESS-SW1 (VLAN10): configura um PC para DHCP e solicita um IP; esperar um IP sob `10.10.0.0/24` e gateway `10.10.0.1`.
2. Em ACCESS-SW2 (VLAN20): configura um PC para DHCP e solicita um IP; esperar um IP sob `10.20.0.0/24` e gateway `10.20.0.1`.
3. No DIST-SW6, executa `show standby brief` para confirmar `Active` nos grupos 10 e 20.
4. Simula falha em DIST-SW6 (shutdown na subinterface física) e confirma que DIST-SW7 passa a `Active`.
5. Verifica `show ip dhcp binding` no R5 para ver os leases activos.

Notas e cuidados
- HSRP manipula ARP para o VIP — assegura que não há SVIs adicionais conflitantes que respondam ao mesmo VIP.
- As ACLs podem bloquear tempo de DHCP/relay — confirma que ICMP/UDP 67/68 e tráfego entre DIST e R5 estão permitidos.

Próximos passos
- Depois de validar HSRP e DHCP Relay, iremos introduzir serviços adicionais e roteamento intersite em `05-OSPF-InterSite-Routing-Porto-Gaia/`.
