import socket
import json
import threading
import auth_utils

HOST = 'localhost'
PORT = 12345

dictUsuarios = {}
dictSalas = {}
lock = threading.Lock()

def processar_comando(msg_json, addr):
    cmd = msg_json.get("cmd")
    user = msg_json.get("user")
    
    with lock:
        # --- Comandos de Autenticação e Informação ---
        if cmd == "CADASTRO":
            senha = msg_json.get("pass")
            ok, mensagem = auth_utils.cadastrar_usuario(user, senha, dictUsuarios)
            return {"status": "OK" if ok else "ERRO", "msg": mensagem}
        
        elif cmd == "LOGIN":
            senha = msg_json.get("pass")
            peer_port = msg_json.get("port")
            pub_key = msg_json.get("pub_key")
            
            ok, mensagem = auth_utils.login_usuario(user, senha, dictUsuarios)
            if ok:
                if user in dictUsuarios:
                    dictUsuarios[user]["addr"] = (addr[0], peer_port)
                    dictUsuarios[user]["pub_key"] = pub_key
                    # LINHA DE DEBUG ADICIONADA:
                    print(f"[DEBUG LOGIN] Usuário '{user}' logado. Estado atual de dictUsuarios: {dictUsuarios}")
                return {"status": "OK", "msg": "Login bem-sucedido."}
            return {"status": "ERRO", "msg": mensagem}

        elif cmd == "GET_USER_INFO":
            user_to_find = msg_json.get("user_to_find")
            if user_to_find in dictUsuarios and dictUsuarios[user_to_find].get("addr"):
                user_info = dictUsuarios[user_to_find]
                return {"status": "OK", "user": user_to_find, "addr": user_info["addr"], "pub_key": user_info["pub_key"]}
            return {"status": "ERRO", "msg": f"Usuário '{user_to_find}' não encontrado ou offline."}

        elif cmd == "LIST_USERS":
            # BLOCO DE DEBUG ADICIONADO:
            print(f"\n[DEBUG LISTAR] Recebido pedido para listar usuários.")
            print(f"[DEBUG LISTAR] Estado de dictUsuarios antes de filtrar: {dictUsuarios}")
            
            online_users = [u for u, data in dictUsuarios.items() if "addr" in data]
            
            print(f"[DEBUG LISTAR] Usuários online encontrados após filtrar: {online_users}")
            return {"status": "OK", "users": online_users}

        # --- Comandos para Salas de Chat (com Moderação) ---
        elif cmd == "CREATE_ROOM":
            room_name = msg_json.get("room")
            password = msg_json.get("password")
            if room_name in dictSalas:
                return {"status": "ERRO", "msg": f"Sala '{room_name}' já existe."}
            dictSalas[room_name] = {"owner": user, "password": password, "members": [user]}
            msg = f"Sala '{room_name}' criada."
            if password:
                msg += " A sala é protegida por senha."
            return {"status": "OK", "msg": msg}

        elif cmd == "JOIN_ROOM":
            room_name = msg_json.get("room")
            password_attempt = msg_json.get("password", None)
            if room_name not in dictSalas:
                return {"status": "ERRO", "msg": f"Sala '{room_name}' não existe."}
            
            room = dictSalas[room_name]
            if room["password"] and room["password"] != password_attempt:
                return {"status": "ERRO", "msg": "Senha da sala incorreta."}
            
            if user not in room["members"]:
                room["members"].append(user)
            return {"status": "OK", "msg": f"Você entrou na sala '{room_name}'.", "members": room["members"]}

        elif cmd == "LIST_MEMBERS":
            room_name = msg_json.get("room")
            if room_name not in dictSalas: return {"status": "ERRO", "msg": f"Sala '{room_name}' não existe."}
            return {"status": "OK", "members": dictSalas[room_name]["members"]}

        # --- Comandos de Moderação ---
        elif cmd == "KICK_USER":
            room_name = msg_json.get("room")
            user_to_kick = msg_json.get("user_to_kick")
            if room_name not in dictSalas: return {"status": "ERRO", "msg": "Sala não existe."}
            
            room = dictSalas[room_name]
            if room["owner"] != user:
                return {"status": "ERRO", "msg": "Apenas o moderador pode remover usuários."}
            if user_to_kick not in room["members"]:
                return {"status": "ERRO", "msg": "Usuário não está na sala."}
            
            room["members"].remove(user_to_kick)
            
            response_data = {"status": "OK", "msg": f"Usuário '{user_to_kick}' foi removido da sala '{room_name}'."}
            if user_to_kick in dictUsuarios and "addr" in dictUsuarios[user_to_kick]:
                kicked_user_info = {
                    "user": user_to_kick,
                    "addr": dictUsuarios[user_to_kick]["addr"],
                    "pub_key": dictUsuarios[user_to_kick]["pub_key"]
                }
                response_data["kicked_user_info"] = kicked_user_info
            return response_data

        elif cmd == "CHANGE_ROOM_PASS":
            room_name = msg_json.get("room")
            new_password = msg_json.get("new_password")
            if room_name not in dictSalas: return {"status": "ERRO", "msg": "Sala não existe."}

            room = dictSalas[room_name]
            if room["owner"] != user:
                return {"status": "ERRO", "msg": "Apenas o moderador pode alterar a senha."}
            
            room["password"] = new_password
            return {"status": "OK", "msg": f"Senha da sala '{room_name}' foi alterada."}

        else:
            return {"status": "ERRO", "msg": "Comando desconhecido"}

def handle_client(conn, addr):
    with conn:
        try:
            data = conn.recv(4096)
            if not data: return
            msg_json = json.loads(data.decode('utf-8'))
            resposta = processar_comando(msg_json, addr)
            conn.sendall(json.dumps(resposta, ensure_ascii=False).encode('utf-8'))
        except Exception as e:
            print(f"Ocorreu um erro: {e}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Tracker ouvindo em", (HOST, PORT))
    while True:
        conn, addr = s.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
