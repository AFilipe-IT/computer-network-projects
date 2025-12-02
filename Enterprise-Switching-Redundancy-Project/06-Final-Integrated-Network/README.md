06 - Final Integrated Network

Content: ficheiros finais de configuração por dispositivo para a topologia Porto–Gaia.

Ficheiros incluídos:
- `FINAL-R5.txt` (R5, Core Porto) — L3 links, DHCP pools VLAN10/20, OSPF, SSH
- `FINAL-R7.txt` (R7, Core Gaia) — Router-on-a-stick subinterfaces, L3 links, OSPF, SSH
- `FINAL-DIST-SW6.txt` (Distribution Porto) — SVIs (dot1Q subinterfaces) com HSRP, ip helper, OSPF, SSH
- `FINAL-DIST-SW7.txt` (Distribution Porto) — SVIs com HSRP, ip helper, OSPF, SSH
- `FINAL-ACCESS-SW1.txt`, `FINAL-ACCESS-SW2.txt`, `FINAL-ACCESS-SW3.txt` — VLANs, STP, EtherChannel/Port-channel, port-security, uplinks

Evidência (imagens):
- As imagens de validação estão em `06-Final-Integrated-Network/evidence/`.
- Ficheiros:
  - `evidence-ospf-neighbors.png`
  - `evidence-ip-route-R5.png`
  - `evidence-hsrp-dist-sw6.png`
  - `evidence-dhcp-bindings-R5.png`
  - `evidence-trunks-portchannel.png`
  - `evidence-port-security.png`
  - `evidence-ping-vlan10-to-73.png`

Consulte `06-Final-Integrated-Network/EVIDENCE.md` para ver embeds e descrições de cada imagem.

Notas rápidas de verificação:
- Substituir `ENABLE_PASSWORD` e `ADMIN_PASSWORD` pelos valores reais antes de aplicar.
- Ver comandos úteis:
  - `show ip interface brief`
  - `show running-config | section interface`
  - `show ip route` / `show ip ospf neighbor`
  - `show standby` (HSRP)
  - `show ip dhcp binding` (no R5)
  - `show etherchannel summary` / `show interfaces trunk`
  - `show port-security interface <if>` / `show mac address-table`

Recomenda-se aplicar em fases: cores (R5/R7) → distribution → access e validar HSRP/ DHCP/ OSPF/ trunking entre cada etapa.
