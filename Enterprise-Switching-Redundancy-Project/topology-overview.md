Topology Overview — Enterprise Switching & Redundancy (Porto ↔ Vila Nova de Gaia)

Resumo

Este documento fornece uma visão geral concisa da topologia do projecto, mapeando os dispositivos, sub‑redes e serviços principais (VLANs, HSRP, Router‑on‑a‑Stick, OSPF). Inclui também uma lista de verificações rápidas e comandos úteis para validar a configuração no laboratório.

Diagrama

- Ficheiro de topologia (sugerido): `topology.png` — coloca a imagem na raiz do projecto para aparecer nos READMEs.

Dispositivos e papéis

- Porto:
  - R5 — Core (router): enlaces para DIST-SW6 (10.51.0.5), DIST-SW7 (10.52.0.5) e ligações para R7 (10.55.0.5 / 10.77.0.5). Hospeda o servidor DHCP neste projecto.
  - DIST-SW6 — Distribution Porto: L3 com subinterfaces para VLAN10/20 (10.10.0.2 / 10.20.0.2). HSRP active configurado.
  - DIST-SW7 — Distribution Porto: L3 com subinterfaces para VLAN10/20 (10.10.0.3 / 10.20.0.3). HSRP standby configurado.
  - ACCESS-SW1 / ACCESS-SW2 — Switches de acesso do Porto: VLANs 10 / 20, trunks e PortChannel entre eles; port‑security nas portas de PC.

- Vila Nova de Gaia:
  - R7 — Core (router Gaia): enlaces para R5 (10.55.0.7 / 10.77.0.7) e subinterfaces para VLANs 73/74/75 (10.73.0.254 / 10.74.0.254 / 10.75.0.254).
  - ACCESS-SW3 — Switch de acesso (Gaia): VLANs 73/74/75, trunks e port‑security nas portas de PC.

Endereçamento (resumo rápido)

- Enlaces core/distribution
  - R5 <-> DIST-SW6: 10.51.0.5 / 10.51.0.6 (/24)
  - R5 <-> DIST-SW7: 10.52.0.5 / 10.52.0.7 (/24)
  - R5 <-> R7: 10.55.0.x (/24) e 10.77.0.x (/24) (duplo link no projecto)

- VLANs e gateways
  - VLAN 10 (Porto): 10.10.0.0/24
    - Gateway (HSRP VIP): 10.10.0.1
    - DIST-SW6 subif: 10.10.0.2
    - DIST-SW7 subif: 10.10.0.3
  - VLAN 20 (Porto): 10.20.0.0/24
    - Gateway (HSRP VIP): 10.20.0.1
    - DIST-SW6 subif: 10.20.0.2
    - DIST-SW7 subif: 10.20.0.3
  - VLAN 73 (Gaia): 10.73.0.0/24 — gateway R7: 10.73.0.254
  - VLAN 74 (Gaia): 10.74.0.0/24 — gateway R7: 10.74.0.254
  - VLAN 75 (Gaia): 10.75.0.0/24 — gateway R7: 10.75.0.254

Serviços e protocolos

- Router‑on‑a‑Stick: subinterfaces com `encapsulation dot1Q` nos distribution (Porto) e em R7 (Gaia) para inter‑VLAN routing.
- HSRP: grupos 10 e 20 em DIST‑SW6/7 (DIST‑SW6 priority 110 → Active; DIST‑SW7 priority 100 → Standby). VIPs: 10.10.0.1 / 10.20.0.1.
- DHCP: R5 é servidor DHCP para VLAN10/20; DISTs usam `ip helper‑address` para encaminhar pedidos DHCP para R5.
- OSPF: area 0 única, OSPF em R5, R7, DIST‑SW6, DIST‑SW7 para anunciar enlaces e redes das VLANs.

Ficheiros principais (localização)

- `00-Basic-Device-Setup/` — bootstrap configs por dispositivo (hostnames, SSH, usuários, IPs L3 onde aplicável).
- `01-Switching-Foundation-VLANs-STP/` — VLANs, Rapid‑PVST e configuração de portas access/trunk.
- `02-Uplinks-PortChannel-and-PortSecurity/` — PortChannel, trunks e port‑security.
- `03-Router-on-a-Stick-InterVLAN-Routing/` — subinterfaces e IPs das VLANs nos routers/distribution.
- `04-Redundant-Gateway-HSRP-and-DHCP/` — HSRP e DHCP server/relay.
- `05-OSPF-InterSite-Routing-Porto-Gaia/` — configuração OSPF e verificação.

Verificação rápida / comandos úteis

Bootstrap (em cada dispositivo):
- `show running-config | include hostname`
- `show ip interface brief`
- `show ip ssh`

Switching (access switches):
- `show vlan brief`
- `show interface trunk`
- `show spanning-tree summary`
- `show mac address-table dynamic`

PortChannel & Port‑Security:
- `show etherchannel summary`
- `show interfaces port-channel 1`
- `show port-security`
- `show mac address-table secure`

Router‑on‑a‑Stick / HSRP / DHCP (distribution & routers):
- `show ip interface brief`
- `show running-config interface <subinterface>`
- `show standby brief`
- `show ip dhcp binding` (no R5)

OSPF / Inter‑site:
- `show ip ospf neighbor`
- `show ip route ospf`
- `show ip route 10.73.0.0` (ex.: confirmar reachability)

Checks de conectividade (exemplos)

- Do host em VLAN10: `ping 10.10.0.1` (gateway HSRP VIP)
- Do host em VLAN10 → host em VLAN73: `ping <host_vlan73>` (verifica encaminhamento OSPF + HSRP)
- No R5: `show ip ospf neighbor` e `show ip route ospf` deve mostrar as redes remotas de Gaia (10.73/74/75)

Notas finais e próximos passos

- Coloca a imagem `topology.png` na raiz (`Enterprise-Switching-Redundancy-Project/topology.png`) se quiseres que seja mostrada automaticamente nos READMEs. Posso gravá‑la aqui se me forneceres o ficheiro binário.
- Após validar a topologia e os passos anteriores, próximos passos típicos: testes de resiliência (fazer `shutdown` em membros do port‑channel, simular falha do DIST‑SW6 para validar HSRP failover), e adicionar monitorização/telemetria.

---

*Documento gerado como visão geral da topologia para o projecto Porto ↔ Vila Nova de Gaia.*
