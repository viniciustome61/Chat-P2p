import socket
import json
import sys
#Importa as funções do módulo central de autenticação
import auth_utils 

def cadastrar(username, password):
    HOST = 'localhost'
    PORT = 12345
    
    # Agora, o cadastro é feito pelo tracker, que usa a lógica centralizada
    # do auth_utils. Este script apenas envia o comando.
    msg = {"cmd": "CADASTRO", "user": username, "pass": password}
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(json.dumps(msg, ensure_ascii=False).encode('utf-8'))
            resposta = s.recv(1024)
            print('Resposta do Tracker:', resposta.decode('utf-8'))
    except ConnectionRefusedError:
        print("[ERRO] Não foi possível conectar ao tracker. Ele está rodando?")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 cadastrar_usuario.py <nome_de_usuario> <senha>")
        sys.exit(1)
    
    cadastrar(sys.argv[1], sys.argv[2])