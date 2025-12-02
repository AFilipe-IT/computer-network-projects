05 - OSPF InterSite Routing (Porto ↔ Vila Nova de Gaia)

Objectivo

Esta pasta contém exemplos para activar OSPF na área 0 entre os routers/core e os distribution switches apresentados no projecto. O desenho é intencionalmente simples: uma única área 0 que anuncia os enlaces de backbone e as sub‑redes das VLANs configuradas anteriormente.

Ficheiros incluídos
- `R5-OSPF.txt` — OSPF para R5 (router-id 5.5.5.5), anuncia links para DIST-SW6/7 e os links para R7.
- `DIST-SW6-OSPF.txt` — OSPF para DIST-SW6 (router-id 6.6.6.6), anuncia link para R5 e redes 10.10.0.0/24 e 10.20.0.0/24.
- `DIST-SW7-OSPF.txt` — OSPF para DIST-SW7 (router-id 7.7.7.7), anuncia link para R5 e redes 10.10.0.0/24 e 10.20.0.0/24.
- `R7-OSPF.txt` — OSPF para R7 (router-id 10.10.10.10), anuncia links para R5 e redes 10.73/74/75.0/24.

Notas
- É intencional que `DIST-SW6` e `DIST-SW7` anunciem as mesmas redes (10.10.0.0/24 e 10.20.0.0/24) — ambos têm subinterfaces nessas redes por causa do Router‑on‑a‑Stick e HSRP.
- Todas as redes são anunciadas em `area 0`.

Verificação e comandos de diagnóstico

Recomendações de comandos a executar após aplicar OSPF em cada equipamento:

- Em R5

  - `show ip ospf neighbor`
  - `show ip route ospf`
  - `show ip protocols`

- Em R7

  - `show ip ospf neighbor`
  - `show ip route`

- Em DIST-SW6 / DIST-SW7

  - `show ip ospf neighbor`
  - `show ip route 10.73.0.0`
  - `show ip route 10.74.0.0`
  - `show ip route 10.75.0.0`

Resultados esperados (rápido)

- `show ip ospf neighbor` deve mostrar adjacências OSPF entre R5 ↔ DIST-SW6, R5 ↔ DIST-SW7 e R5 ↔ R7 (dependendo do desenho fisico e links configurados).
- `show ip route` / `show ip route ospf` deve apresentar rotas para as sub‑redes remotas (ex.: 10.73.0.0/24 via R7).
- PCs em VLAN 10/20 (Porto) e VLAN 73/74/75 (Gaia) devem poder comunicar quando HSRP e DHCP/assim estiverem configurados e os encaminhamentos OSPF estiverem estabelecidos.

Sequência de testes sugerida

1. Aplica OSPF em R5, DIST-SW6, DIST-SW7 e R7.
2. Em cada router/switch, confirma `show ip ospf neighbor` e espera que as adjacências fiquem `FULL`.
3. Verifica `show ip route ospf` em R5 e R7 para confirmar que as redes remotas são visíveis.
4. Testa conectividade ICMP entre hosts em Porto ↔ Gaia (por exemplo, host em VLAN73 → host em VLAN10).

Notas operacionais

- Se as adjacências não formarem, confirma as configurações IP das interfaces físicas e subinterfaces, e que os níveis de MTU e timers não estão a bloquear a formação (ex.: mismatched MTU em trunks).
- Para ambientes maiores considerar sumarização e políticas de redistribuição; neste laboratório mantemos tudo em área 0 para simplicidade.

Próximos passos

- Depois de validar OSPF, poderemos adicionar monitorização, filtros (ACLs/route‑maps) e documentação extra sobre o planeamento de áreas caso seja necessário dividir a topologia.
