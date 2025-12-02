03 - Router-on-a-Stick (Inter-VLAN Routing)

Esta pasta contém exemplos de configuração para implementar inter‑VLAN routing usando subinterfaces (Router‑on‑a‑Stick). Estes ficheiros assumem que o `basic-config` (pasta `00`) e as configurações L2 (pasta `01` e `02`) já foram aplicadas.

Ficheiros incluídos
- `DIST-SW6-RouterOnStick.txt` — Subinterfaces em Ethernet1/0 para VLANs 10 e 20 (Porto).
- `DIST-SW7-RouterOnStick.txt` — Subinterfaces em Ethernet2/0 para VLANs 10 e 20 (Porto).
- `R7-RouterOnStick.txt` — Subinterfaces em Ethernet0/0 para VLANs 73, 74 e 75 (Gaia).

O que estes ficheiros fazem
- Definem a interface física sem IP e criam subinterfaces `interface X.Y` com `encapsulation dot1Q <Y>` e um `ip address` para cada VLAN.
- Não configuram HSRP, DHCP, OSPF, ou DHCP Relay — esses serviços serão tratados nos subprojetos `04` e `05`.

Verificação e comandos de diagnóstico

- Verificar subinterfaces e endereços IP

  Comandos:

  - `show ip interface brief`
  - `show running-config interface <subinterface>` (ex.: `show running-config interface Ethernet1/0.10`)

  Resultados esperados:

  - As subinterfaces devem aparecer com os IPs configurados (ex.: `10.10.0.2` / `10.20.0.2` em `DIST-SW6`).
  - `show run` na subinterface deve mostrar `encapsulation dot1Q <vlan>` e o `ip address` correspondente.

- Verificar encaminhamento entre VLANs (após configuração do Router-on-a-Stick e com hosts em cada VLAN)

  Comandos / passos:

  1. A partir de um host na VLAN A (ex.: VLAN10), ping ao gateway na subinterface correspondente (ex.: `ping 10.10.0.2`).
  2. Ping entre hosts em VLANs diferentes (ex.: host em VLAN10 → host em VLAN20) para confirmar encaminhamento L3.
  3. `show ip route` no router/distribution para confirmar que as redes VLAN estão presentes na tabela de encaminhamento.

  Resultados esperados:

  - `ping` ao gateway da VLAN deve responder.
  - Ping entre hosts em VLANs diferentes deve funcionar se o Router-on-a-Stick estiver activo e não houver ACLs a bloquear o tráfego.
  - `show ip route` deverá listar rotas directas para as sub‑redes das VLANs (ex.: `10.10.0.0/24 via Ethernet1/0.10`).

Notas práticas

- Certifica‑te de que a interface física no switch de acesso está em trunk e permite as VLANs relevantes antes de aplicar as subinterfaces no router.
- Evita configurar SVIs duplicadas nos switches de distribuição que entrem em conflito com as subinterfaces (define a responsabilidade de gateway claramente: R‑on‑a‑Stick neste passo).

Próximos passos

- Após validar o Router‑on‑a‑Stick, iremos introduzir `04-Redundant-Gateway-HSRP-and-DHCP/` para alta‑disponibilidade de gateway e `05-OSPF-InterSite-Routing-Porto-Gaia/` para a interligação dinâmica dos sites.
