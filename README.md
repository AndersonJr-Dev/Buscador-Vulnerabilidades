# Scanner de Vulnerabilidades Web - Hacker Ético

Um programa para busca de vulnerabilidades em sistemas web, desenvolvido para profissionais de segurança e participantes de programas de bug bounty.

## Funcionalidades

- Interface gráfica intuitiva para escaneamento de vulnerabilidades
- Detecção de múltiplos tipos de vulnerabilidades:
  - Injeção SQL
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - Redirecionamento Aberto
  - Directory Traversal
  - File Inclusion
  - Divulgação de Informações
  - Cabeçalhos Inseguros
  - Vulnerabilidades SSL/TLS
  - Vulnerabilidade a Força Bruta
- Classificação de vulnerabilidades por nível de risco
- Geração de relatórios em múltiplos formatos (HTML, PDF, JSON, CSV)
- Configurações personalizáveis para escaneamento

## Requisitos

- Python 3.7 ou superior
- Bibliotecas Python listadas em `requirements.txt`

## Instalação

1. Clone ou baixe este repositório
2. Instale as dependências:

```
pip install -r requirements.txt
```

## Uso

Execute o programa principal:

```
python web_vulnerability_scanner.py
```

### Passos para escaneamento:

1. Insira a URL do alvo no campo "URL do Alvo"
2. Selecione os tipos de vulnerabilidades que deseja escanear
3. Clique em "Iniciar Escaneamento"
4. Acompanhe o progresso no log de escaneamento
5. Visualize os resultados na aba "Resultados"
6. Gere relatórios na aba "Relatórios"

## Configurações

Na aba "Configurações", você pode personalizar:

- Timeout para requisições
- Número de threads para escaneamento paralelo
- User-Agent para requisições
- Diretório para salvar relatórios

## Aviso Legal

Este programa deve ser usado apenas para fins éticos e legais, como:

- Testar a segurança de seus próprios sistemas
- Realizar testes autorizados em sistemas de terceiros
- Participar de programas de bug bounty com autorização explícita

O uso deste programa para atividades não autorizadas pode violar leis de segurança cibernética e resultar em penalidades legais. O autor não se responsabiliza pelo uso indevido desta ferramenta.

## Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests com melhorias.

## Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.