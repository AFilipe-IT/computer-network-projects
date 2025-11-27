# IP Subnetting & VLSM Calculator

**Descrição:** Ferramenta prática para calcular planos de endereçamento IPv4 usando VLSM e divisão em sub-redes iguais. Ideal para alunos e administradores de rede aprenderem alocação eficiente de IPs.

🇵🇹 Nota: este documento está escrito em pt-PT. Algumas expressões técnicas em inglês (por exemplo `CIDR`, `VLSM`, `JSON`) foram mantidas para clareza.

Ferramenta simples para calcular planos de endereçamento IPv4.

Funcionalidades:
- Cálculo VLSM: fornece sub-redes otimizadas para uma lista de requisitos de hosts.
- Subnets iguais: divide uma rede em N sub-redes iguais.


Uso (CLI):

Non-interactive examples:

```
python -m ip_subnet_calculator.cli --network 192.168.0.0/24 --hosts 100,50,10
python -m ip_subnet_calculator.cli --network 10.0.0.0/24 --subnets 4
```

Interactive mode (recommended):

```
python -m ip_subnet_calculator.cli
```

No modo interativo o programa irá pedir:
- `base network` (CIDR) — obrigatório
- `host requirements` (ex.: `100,50,10`) — pressione Enter para pular
- `number of equal subnets` — pressione Enter para pular
- `explicit CIDR list` — pressione Enter para pular

Detalhes dos prompts interativos

1) `base network` (CIDR) — obrigatório
- O que é: a rede base onde o programa irá alocar sub-redes. Deve ser informada em formato CIDR (ex.: `192.168.0.0/24`, `10.0.0.0/16`).
- Quando usar: sempre — sem esta informação não é possível calcular sub-redes.
- Observação: se a rede for grande (por exemplo `/16`) e os requisitos pedirem muitas sub-redes grandes, pode faltar espaço; o programa validará e avisará.

2) `host requirements` (ex.: `100,50,10`) — pressione Enter para pular
- O que é: lista separada por vírgulas com o número de hosts necessários em cada sub-rede. Cada número indica a quantidade de hosts utilizáveis que precisas naquela sub-rede.
- Exemplo: `500,100,20` pede primeiro uma sub-rede para 500 hosts, depois 100, depois 20. O programa usa VLSM (divide o bloco de forma otimizada) e aloca sub-redes do maior para o menor.
- Observação: informe apenas os hosts utilizáveis (não inclui network/broadcast). Se preferires não calcular por hosts, podes pular este campo e usar a opção de sub-redenes iguais.

3) `number of equal subnets` — pressione Enter para pular
- O que é: número inteiro indicando em quantas sub-redes iguais queres dividir a `base network`.
- Exemplo: `4` divide o bloco em 4 sub-redes de tamanho igual (p.ex. dividir um `/22` em quatro `/24`, quando possível).
- Observação: o número é arredondado para a potência de dois necessária; se for impossível dividir (por falta de prefixo disponível) o programa avisará.

4) `explicit CIDR list` — pressione Enter para pular
- O que é: lista de sub-redes em formato CIDR que já tens definidas manualmente e queres que o programa valide/mostre informações (máscara por extenso, broadcast, intervalo utilizável, etc.).
- Quando usar: quando tiveres um plano manual ou quiseres apenas inspecionar/formatar redes já escolhidas.
- Exemplo de entrada válida: `10.0.0.0/24,10.0.1.0/24,192.168.0.0/26`
- Comportamento: se preencheres este campo, o programa ignora `hosts` e `number of equal subnets` e apresenta as redes tal como informadas (apenas validando os CIDRs).


O programa prioriza entradas na seguinte ordem: explicit CIDR list -> hosts (VLSM) -> equal subnets.

O programa imprime a tabela de sub-redes e pode produzir saída JSON com `--json`.

Exemplo de saída (campos adicionais: `Netmask`, `Broadcast`, `Usable Range`):

```
Plan de endereçamento para 192.168.0.0/16
CIDR               Network         Prefix  Netmask         Broadcast       Usable Range                         Usable  Requested
-----------------  ---------------  ------  ---------------  ---------------  -----------------------------------  ------  ---------
192.168.0.0/23     192.168.0.0     23      255.255.254.0   192.168.1.255   192.168.0.1 - 192.168.1.254        510     500
192.168.2.0/25     192.168.2.0     25      255.255.255.128 192.168.2.127   192.168.2.1 - 192.168.2.126        126     100
192.168.2.128/27   192.168.2.128   27      255.255.255.224 192.168.2.159   192.168.2.129 - 192.168.2.158      30      20
```

Arquivos:
- `calculator.py` : lógica de VLSM e divisão em sub-redes.
- `cli.py` : ferramenta de linha de comando.
- `tests/test_calculator.py` : testes básicos com pytest.

Requisitos: Python 3.8+ (usa apenas stdlib)
