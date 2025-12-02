02 - Uplinks, Port-Channel & Port-Security

Este directório concentra exemplos e guias para configurar uplinks L2, agregação de ligações (Port-Channel) e políticas de Port-Security nas portas de acesso. Não são criadas VLANs nem alterações STP aqui — essas ficam em `01-Switching-Foundation-VLANs-STP/`.

Conteúdo
- `ACCESS-SW1-Uplinks-PortSecurity.txt` — Configuração de Port-channel entre ACCESS-SW1 e ACCESS-SW2, trunk para DIST-SW6 e port-security na porta de acesso.
- `ACCESS-SW2-Uplinks-PortSecurity.txt` — Configuração simétrica em ACCESS-SW2 (Port-channel para ACCESS-SW1) e trunk para DIST-SW7.
- `ACCESS-SW3-Uplinks-PortSecurity.txt` — Port-security nas portas de acesso e trunk para R7.

Verificação e comandos de diagnóstico

Esta secção fornece comandos `show` e passos de teste para validar Port-Channels, trunks e Port-Security.

- Verificar Port-Channel / EtherChannel

  Comandos:

  - `show etherchannel summary`
  - `show etherchannel detail`
  - `show interfaces port-channel 1`
  - `show running-config interface Port-channel1`

  O que verificar / resultados esperados:

  - `show etherchannel summary` deverá mostrar o Port-Channel com os membros (ex.: Et0/1, Et0/2) e o protocolo LACP em modo activo.
  - `show interfaces port-channel 1` mostra o estado do Port-channel (up/up) e as estatísticas de tráfego.
  - A configuração do Port-channel (`show run int Port-channel1`) deve corresponder ao modo trunk e vlans permitidas.

- Verificar trunks (após Port-Channel activo)

  Comandos:

  - `show interface trunk`
  - `show interface status`

  Resultados esperados:

  - O Port-channel deve aparecer como trunk com as VLANs permitidas listadas.
  - As portas físicas membros (Et0/1, Et0/2) normalmente aparecem como `trunk` e `connected` quando o Port-channel está a funcionar.

- Verificar Port-Security

  Comandos:

  - `show port-security`
  - `show port-security interface <interface>` (ex.: `show port-security interface Ethernet0/0`)
  - `show mac address-table secure`

  O que verificar / resultados esperados:

  - `show port-security` mostra o número de portas com port-security activo e estatísticas de violações.
  - `show port-security interface Ethernet0/0` deve mostrar `Port Security: Enabled`, a MAC sticky (quando aplicada) e o número de violações.
  - `show mac address-table secure` mostrará as entradas de MAC aprendidas via sticky.

Sequência de teste recomendada (passo a passo)

1. Aplica as configurações nos dois switches que fazem parte do Port-channel (ACCESS-SW1 e ACCESS-SW2).
2. Verifica `show etherchannel summary` e confirma que ambos os membros aparecem no grupo 1.
3. Verifica `show interfaces port-channel 1` para confirmar `up/up` e tráfego.
4. Testa a redundância física: desliga temporariamente uma das interfaces físicas (por exemplo `shutdown` em Et0/1) e confirma que o Port-channel continua a passar tráfego através da outra interface.
5. Em portas com port-security sticky: liga um PC e confirma que a MAC é aprendida como sticky com `show mac address-table secure`.
6. Simula uma violação (liga um dispositivo com MAC diferente na mesma porta) e observa `show port-security interface <int>` e `show logging` para verificar se houve violação e a acção tomada.

Notas práticas

- `channel-group 1 mode active` configura LACP; podes usar `mode passive` se preferires uma configuração passive/active conforme desenho.
- `switchport nonegotiate` evita DTP; é recomendável quando controlas a configuração em ambos os lados.
- A política de violação de port-security (`violation shutdown|restrict|protect`) não foi explicitamente definida nos ficheiros iniciais — ajusta conforme a tua política (o default pode variar entre plataformas).

Próximos passos

- Se tudo estiver validado, iremos consolidar políticas de agregação e QoS, e aplicar Port-Channel também aos uplinks de distribution quando apropriado.
