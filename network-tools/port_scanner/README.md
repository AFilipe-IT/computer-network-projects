# Port Scanner (simplificado)

Pequeno utilitário para varredura de portas TCP em um host, implementado em Python.

Funcionalidades:
- Recebe `--host` (hostname ou IP) e intervalo de portas (`--start`, `--end`).
- Usa threads para acelerar a execução (`--threads`).
- Parâmetro `--timeout` para ajustar o tempo de espera por conexão.
- Saídas claras em PT-PT com lista de portas abertas e tempo total.

Exemplo de uso:

```powershell
python -m port_scanner.scanner --host 127.0.0.1 --start 1 --end 1024 --threads 200 --timeout 0.3
```

Notas:
- Executar scans em hosts que não são de tua propriedade pode ser ilegal ou contra políticas. Usa com responsabilidade.
