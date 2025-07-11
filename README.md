Sistema de Chat P2P com Salas em Rede Local

🔍 Objetivo

Autenticação centralizada via Tracker

Chat privado (1:1) e em salas de grupo

Comunicação segura com criptografia RSA/OAEP

🗂️ Estrutura de Arquivos

Arquivo

Descrição

trackerModificado.py

Servidor Tracker: autentica usuários, gerencia peers ativos e salas de chat.

auth_utils.py

Funções de hash de senha e verificação de credenciais (SHA-256 + salt).

cadastrar_usuario.py

Script CLI para cadastro de novos usuários no Tracker via comando CADASTRO.

ClientePeerModificado.py

Script principal do Peer: login, criação/entrada em salas e troca de mensagens criptografadas.

crypto_utils.py

Geração de chaves RSA e funções de criptografia/descriptografia de mensagens.

README.md

Documentação do projeto.

⚙️ Requisitos de Software

Python 3.7+

Biblioteca cryptography

(Opcional) Wireshark para análise de pacotes

Instale dependências com:

pip install cryptography

🚀 Como Executar

Iniciar o Tracker

python trackerModificado.py

O Tracker escutará em localhost:12345.

Cadastrar Usuário
Em um novo terminal:

python cadastrar_usuario.py <usuario> <senha>

Exemplo:

python cadastrar_usuario.py alice senha123

Iniciar Peers
Para cada cliente, abra um terminal separado:

python ClientePeerModificado.py <porta>

Exemplos:

python ClientePeerModificado.py 5001
python ClientePeerModificado.py 5002

Comandos no Peer

LOGIN <usuario> <senha>: autentica no Tracker

LISTAR_USUARIOS: lista peers online

CRIAR <nome_sala> [senha]: cria sala

ENTRAR <nome_sala> [senha]: entra em sala

MSG <nome_sala> <mensagem>: envia mensagem em grupo

PRIVADO <usuario> <mensagem>: envia mensagem privada

HISTORICO <SALA|PRIVADO> <nome>: exibe log de conversas

KICK <nome_sala> <usuario>: expulsa usuário (moderador)

MUDAR_SENHA <nome_sala> <nova_senha>: altera senha da sala (moderador)

SAIR: encerra o peer

📡 Protocolos e Fluxo

Tracker ↔ Peer: TCP/JSON

Payloads JSON com comandos e parâmetros.

Campos principais:

CADASTRO: { "cmd": "CADASTRO", "user": "alice", "pass": "hash" }

LOGIN: { "cmd": "LOGIN", "user": "alice", "pass": "hash", "port": 5001, "pub_key": "<PEM>" }

Outros: CREATE_ROOM, JOIN_ROOM, LIST_MEMBERS, GET_USER_INFO, LIST_USERS, KICK_USER, CHANGE_ROOM_PASS.

Peer ↔ Peer: TCP/RSA-OAEP

Peer A consulta Tracker (GET_USER_INFO) para obter (IP, porta, public_key) de B.

A serializa mensagem: "[TAG] A: texto".

A criptografa com a chave pública de B e envia bytes via TCP.

B descriptografa com chave privada e exibe.

🛡️ Segurança e Hash de Senhas

Hash de senha: SHA-256 com salt fixo ("Universidade de Brasilia").

A senha é convertida para hex, concatenada ao salt em hex e hasheada.

O peer envia somente o hash ao Tracker.

Criptografia RSA:

Chaves RSA 2048 bits (biblioteca cryptography).

OAEP com MGF1(SHA-256) para confidencialidade ponta-a-ponta.

📝 Captura de Pacotes (Wireshark)

Selecione a interface loopback (lo em Linux/macOS ou Adapter for loopback no Windows).

Inicie captura e realize operações de cadastro, login e chat.

Use filtros:

tcp.port == 12345       # JSON Tracker ↔ Peer
tcp.port >= 5001 && tcp.port <= 6000  # Tráfego P2P

Utilize “Follow TCP Stream” para diferenciar JSON legível e ciphertext binário.

✅ Requisitos Atendidos

Funcionalidade

Status

Autenticação centralizada via Tracker    ✔️

Chat privado (1:1) e em salas de grupo   ✔️

Criptografia RSA para mensagens P2P      ✔️

Hash de senha no cliente e armazenamento seguro pelo Tracker  ✔️

Comunicação via TCP/JSON e sockets Python ✔️

CLI simples sem GUI    ✔️
