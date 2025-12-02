# Enterprise Switching & Redundancy Project

## Introdução
Este repositório contém uma arquitetura completa de switching empresarial e redundância, concebida para interligar dois locais corporativos — Porto e Vila Nova de Gaia — com práticas de engenharia de rede resistentes, escaláveis e seguras. O desenho privilegia elevada disponibilidade, comportamento previsível da malha de campus e separação de tráfego por função, permitindo suportar serviços críticos de negócio e segmentação por departamentos ou clientes. Destina‑se a engenheiros de rede, arquitetos e equipas de operações como um guia prático e adaptável para implementação de campus resilientes e conectividade entre sites.

## Objetivo do Projeto
Os objetivos principais deste projeto são:

- Redundância: Garantir resiliência na infraestrutura de switching e gateways, com failover rápido para minimizar interrupções e cumprir os objetivos de disponibilidade empresariais.
- Segmentação VLAN: Aplicar separação de tráfego através de VLANs para isolar grupos de utilizadores, serviços e planos de gestão, reforçando a segurança e a operacionalidade.
- Switching de campus: Implementar uma malha de switching multilayer robusta, com comportamento STP previsível, agregação de ligações e separação clara entre camadas de acesso e agregação.
- Roteamento entre sites: Assegurar roteamento dinâmico e escalável entre Porto e Vila Nova de Gaia, com políticas claras de alcance e planeamento de rotas.
- Serviços essenciais: Documentar e demonstrar a configuração de serviços essenciais (por exemplo DHCP, HSRP para gateway redundante, Router‑on‑a‑Stick para inter‑VLAN routing, DHCP Relay quando aplicável) e medidas básicas de hardening dos equipamentos (SSH, AAA, gestão).

## Tecnologias-chave Implementadas
- VLANs
- Rapid‑PVST
- EtherChannel (Port‑Channel)
- Port Security
- Router‑on‑a‑Stick
- DHCP + DHCP Relay
- HSRP
- OSPF
- Configuração básica de dispositivos (SSH, hostname, banners, NTP, logging)

## Visão Geral da Arquitetura (alto‑nível)
A arquitetura modela dois sites físicos — Porto e Vila Nova de Gaia — interligados por um transporte resiliente ou link WAN agregado. Cada site é organizado como um campus multilayer com camadas de acesso e agregação distintas, usando VLANs para segmentação e EtherChannel para uplinks agregados. Gateways redundantes (HSRP) fornecem continuidade de serviço por VLAN, enquanto o alcance entre sites é gerido por um protocolo de roteamento (OSPF). O desenho é propositalmente flexível para acomodar várias topologias físicas (ex.: um ou múltiplos switches de agregação), tipos de transporte (MPLS, fibra, VPN) e diferentes exigências de escala.

## Estrutura de Subprojectos (futura)
As seguintes pastas serão criadas e preenchidas com documentação e configurações; cada entrada inclui uma frase curta sobre o propósito planeado.

- `00-Basic-Device-Setup/` — Bootstrap e configuração base de dispositivos (hostnames, SSH, banners, NTP, utilizadores e acesso de gestão seguro).
- `01-Switching-Foundation-VLANs-STP/` — Projeto de VLANs, exemplos de SVIs e afinação de Rapid‑PVST/STP para comportamento previsível no campus.
- `02-Uplinks-PortChannel-and-PortSecurity/` — Configuração de uplinks agregados com EtherChannel e políticas de Port Security na camada de acesso.
- `03-Router-on-a-Stick-InterVLAN-Routing/` — Exemplos de Router‑on‑a‑Stick e orientação para inter‑VLAN routing (subinterfaces, encapsulação) e alternativas com SVIs.
- `04-Redundant-Gateway-HSRP-and-DHCP/` — Configurações de gateway redundante (HSRP), padrões de implementação de DHCP e Relay, e procedimentos de verificação.
- `05-OSPF-InterSite-Routing-Porto-Gaia/` — Exemplos de topologia OSPF, recomendações de design de áreas e sumarização de rotas entre Porto ↔ Gaia.
- `06-Final-Integrated-Network/` — Laboratório integrado final com configurações consolidadas, casos de teste e checklist de validação para prontidão de produção.

## Início Rápido
Este ficheiro é o ponto de partida. As pastas acima irão conter fragmentos de configuração, diagramas de topologia, instruções passo‑a‑passo para laboratório e comandos de validação. Para começar a preparar um ambiente de testes ou implantação, consulte primeiro `00-Basic-Device-Setup/` quando disponível.

## Contribuições
Contribuições de engenheiros de rede e revisores são bem‑vindas. Ao submeter alterações, inclua mensagens de commit claras, passos de teste em laboratório para as alterações de configuração e uma justificação técnica para as decisões de desenho.

## Licença e Atribuição
Este repositório incluirá um ficheiro de licença na raiz quando o projeto for inicializado. A menos que indicado em contrário, as configurações e documentos são referências técnicas e devem ser adaptados às políticas operacionais locais antes de utilização em produção.

---
*Documento preparado como referência de arquitectura empresarial para conectividade Porto ↔ Vila Nova de Gaia e resiliência de switching de campus.*
# Enterprise Switching & Redundancy Project

## Introduction

This repository contains a complete enterprise switching and redundancy architecture designed to interconnect two corporate sites — Porto and Vila Nova de Gaia — with resilient, scalable, and secure networking best practices. The design emphasizes high availability, predictable campus switching behavior, and clear traffic separation to support business-critical services and multi-tenant or departmental segmentation. It is intended as a practical, deployable reference architecture for network engineers, architects, and operations teams implementing resilient campus and inter-site connectivity.

## Purpose

The primary goals of this project are:

- Redundância: Provide network resiliency and fast failover at the switching and gateway layers to minimize service interruption and meet enterprise availability targets.
- Segmentação VLAN: Enforce traffic separation using VLANs to isolate user groups, services, and management planes for security and operational clarity.
- Switching de campus: Implement a robust multilayer switching fabric with predictable STP behavior, port channeling, and appropriate access/aggregation separation.
- Roteamento entre sites: Provide dynamic, scalable routing between Porto and Vila Nova de Gaia with clear policies for reachability and traffic engineering.
- Serviços essenciais: Document and demonstrate the deployment of essential services such as DHCP, HSRP (redundant gateway), Router-on-a-Stick for inter‑VLAN routing, DHCP Relay where appropriate, and basic device hardening (SSH, AAA, management access).

## Key Technologies Implemented

- VLANs
- Rapid-PVST
- EtherChannel (Port-Channel)
- Port Security
- Router-on-a-Stick (subinterfaces / SVI interaction)
- DHCP + DHCP Relay
- HSRP (Hot Standby Router Protocol)
- OSPF (for inter-site routing)
- Basic device configuration (SSH, hostname, banners, NTP, logging)

## High-level Network Architecture Overview

The architecture models two physical sites — Porto and Vila Nova de Gaia — connected by a resilient WAN link or aggregated transport. Each site is built as a multilayer campus with distinct access and aggregation layers, using VLANs to segment traffic and EtherChannel to provide aggregated uplinks. Redundant gateway services (HSRP) provide per‑VLAN gateway resiliency, while inter-site reachability is handled by a routing protocol (OSPF) with clear area/LSA planning. The design remains intentionally flexible so it can be adapted to different physical topologies (single vs multiple aggregation switches), transport types (MPLS, dark fiber, VPN), and scale requirements.

## Subproject Structure (future)

Each subproject listed below will be created and expanded later; the short sentence beside each describes the planned focus area.

- `00-Basic-Device-Setup/` — Device bootstrap and baseline configuration examples (hostnames, SSH, banners, NTP, users, and secure management access).
- `01-Switching-Foundation-VLANs-STP/` — VLAN design, IP SVI examples, and Rapid-PVST/STP tuning for predictable campus switching behavior.
- `02-Uplinks-PortChannel-and-PortSecurity/` — Aggregated uplink configuration using EtherChannel and port security policies for access-layer enforcement.
- `03-Router-on-a-Stick-InterVLAN-Routing/` — Router-on-a-Stick examples and guidance for inter‑VLAN routing, subinterface and encapsulation setup, and SVI alternatives.
- `04-Redundant-Gateway-HSRP-and-DHCP/` — Redundant gateway configurations using HSRP, DHCP server and DHCP Relay deployment patterns and verification steps.
- `05-OSPF-InterSite-Routing-Porto-Gaia/` — OSPF topology examples, area/design recommendations, and inter-site route summarization for Porto ↔ Gaia.
- `06-Final-Integrated-Network/` — Complete integrated lab with combined configurations, test cases, and verification/checklists for production readiness.

## Getting Started (short)

This README is the canonical starting point. Subsequent directories will include device configuration snippets, topology diagrams, step-by-step lab instructions, and validation commands. For immediate reference, the `00-Basic-Device-Setup/` will be the first place to look when beginning a deployment or lab exercise.

## Contributing

Contributions are welcome from networking engineers and reviewers. When contributing, please follow clear commit messages, provide lab test steps for any configuration changes, and include a rationale for design decisions.

## License & Attribution

This repository will include a licensing file in the root when the project is initialized. Unless otherwise stated, configurations and design documents are intended as technical references and should be adapted to local operational policies before production use.

---

*Prepared as an enterprise reference architecture for Porto ↔ Vila Nova de Gaia connectivity and campus switching resiliency.*
