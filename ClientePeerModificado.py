import socket
import json
import threading
import sys
import os
from datetime import datetime
from crypto_utils import gerar_chaves, serializar_chave_publica, desserializar_chave_publica, criptografar_mensagem, descriptografar_mensagem

TRACKER_HOST = 'localhost'
TRACKER_PORT = 12345

class Peer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.private_key, self.public_key = gerar_chaves()
        self.username = ""
        self.history_path = "history"
        if not os.path.exists(self.history_path):
            os.makedirs(self.history_path)

    def _log_message(self, context, message):
        filename = os.path.join(self.history_path, f"hist_{context}.txt")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(filename, "a", encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")

    def _comunicar_tracker(self, msg):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((TRACKER_HOST, TRACKER_PORT))
                s.sendall(json.dumps(msg).encode('utf-8'))
                resposta = s.recv(4096)
                return json.loads(resposta.decode('utf-8'))
        except ConnectionRefusedError:
            return {"status": "ERRO", "msg": "Não foi possível conectar ao tracker."}
        except json.JSONDecodeError:
             return {"status": "ERRO", "msg": "O tracker retornou uma resposta inválida (vazia)."}

    def _ouvir_conexoes(self):
        self.server_socket.listen()
        print(f"Peer ouvindo por conexões em {self.host}:{self.port}")
        while True:
            try:
                conn, addr = self.server_socket.accept()
                thread = threading.Thread(target=self._handle_peer_connection, args=(conn, addr))
                thread.start()
            except OSError:
                break

    def _handle_peer_connection(self, conn, addr):
        with conn:
            try:
                data = conn.recv(2048)
                if not data: return
                mensagem_descriptografada = descriptografar_mensagem(self.private_key, data)
                
                try:
                    # Formato esperado: "[TAG] remetente: mensagem"
                    # Ex: "[salavip] user2: Oi"
                    if mensagem_descriptografada.startswith('[') and ']: ' in mensagem_descriptografada:
                        partes = mensagem_descriptografada.split(']: ', 1)
                        tag = partes[0][1:] # Remove o '[' inicial -> "salavip" ou "PRIVADO"
                        
                        conteudo_msg = partes[1] # "user2: Oi"
                        remetente = conteudo_msg.split(':', 1)[0]

                        if tag == "PRIVADO":
                            contexto_log = f"privado_{remetente}"
                            self._log_message(contexto_log, mensagem_descriptografada)
                        elif tag != "SISTEMA": # Qualquer outra tag é uma sala
                            contexto_log = f"sala_{tag}"
                            self._log_message(contexto_log, mensagem_descriptografada)
                except Exception as e:
                    print(f"[DEBUG] Erro ao processar log da mensagem recebida: {e}")
                # --- FIM DA CORREÇÃO ---

                print(f"\r[NOVA MENSAGEM] {mensagem_descriptografada}\n>> ", end="", flush=True)

            except Exception as e:
                print(f"\n[ERRO] Erro ao receber mensagem: {e}")

    def _enviar_mensagem_ponto_a_ponto(self, target_user, message, context_tag=""):
        resposta_info = self._comunicar_tracker({"cmd": "GET_USER_INFO", "user_to_find": target_user})
        if resposta_info.get("status") == "OK":
            try:
                peer_addr = tuple(resposta_info["addr"])
                peer_pub_key = desserializar_chave_publica(resposta_info["pub_key"])
                
                full_message = f"{context_tag}{self.username}: {message}"
                msg_cifrada = criptografar_mensagem(peer_pub_key, full_message)
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer_socket:
                    peer_socket.connect(peer_addr)
                    peer_socket.sendall(msg_cifrada)
                
                if context_tag.startswith("[PRIVADO]"):
                    self._log_message(f"privado_{target_user}", f"Eu: {message}")
                return True, f"Mensagem enviada para {target_user}."
            except Exception as e:
                return False, f"Falha ao enviar para {target_user}: {e}"
        return False, f"Não foi possível obter informações de {target_user}"
        
    def _enviar_mensagem_broadcast(self, room_name, message):
        resposta_membros = self._comunicar_tracker({"cmd": "LIST_MEMBERS", "room": room_name})
        if resposta_membros.get("status") != "OK":
            print(f"[Tracker]: {resposta_membros.get('msg')}")
            return
        
        self._log_message(f"sala_{room_name}", f"Eu: {message}")

        for member in resposta_membros.get("members", []):
            if member == self.username:
                continue
            self._enviar_mensagem_ponto_a_ponto(member, message, f"[{room_name}] ")
            
    def iniciar(self):
        server_thread = threading.Thread(target=self._ouvir_conexoes)
        server_thread.daemon = True
        server_thread.start()
        self.interface_de_comandos()

    def interface_de_comandos(self):
        print("Bem-vindo! Comandos disponíveis: LOGIN, LISTAR_USUARIOS, CRIAR, ENTRAR, MSG, PRIVADO, HISTORICO, KICK, MUDAR_SENHA, SAIR")
        while True:
            cmd_input = input(">> ").strip().split(" ", 2)
            cmd = cmd_input[0].upper()

            if cmd == "LOGIN":
                if len(cmd_input) < 3: print("Uso: LOGIN <usuario> <senha>"); continue
                self.username = cmd_input[1]
                resposta = self._comunicar_tracker({
                    "cmd": "LOGIN", "user": self.username, "pass": cmd_input[2],
                    "port": self.port, "pub_key": serializar_chave_publica(self.public_key)
                })
                print(f"[Tracker]: {resposta.get('msg')}")

            elif cmd == "LISTAR_USUARIOS":
                resposta = self._comunicar_tracker({"cmd": "LIST_USERS"})
                if resposta.get("status") == "OK":
                    print(f"Usuários online: {', '.join(resposta.get('users', []))}")

            elif cmd == "CRIAR":
                if len(cmd_input) < 2: print("Uso: CRIAR <nome_sala> [senha_opcional]"); continue
                password = cmd_input[2] if len(cmd_input) > 2 else None
                resposta = self._comunicar_tracker({"cmd": "CREATE_ROOM", "room": cmd_input[1], "user": self.username, "password": password})
                print(f"[Tracker]: {resposta.get('msg')}")

            elif cmd == "ENTRAR":
                if len(cmd_input) < 2: print("Uso: ENTRAR <nome_sala> [senha_se_necessario]"); continue
                password = cmd_input[2] if len(cmd_input) > 2 else None
                resposta = self._comunicar_tracker({"cmd": "JOIN_ROOM", "room": cmd_input[1], "user": self.username, "password": password})
                print(f"[Tracker]: {resposta.get('msg')}")

            elif cmd == "MSG":
                if len(cmd_input) < 3: print("Uso: MSG <nome_sala> <sua_mensagem>"); continue
                self._enviar_mensagem_broadcast(cmd_input[1], cmd_input[2])

            elif cmd == "PRIVADO":
                if len(cmd_input) < 3: print("Uso: PRIVADO <usuario_destino> <sua_mensagem>"); continue
                status, msg = self._enviar_mensagem_ponto_a_ponto(cmd_input[1], cmd_input[2], "[PRIVADO] ")
                print(msg)

            elif cmd == "HISTORICO":
                if len(cmd_input) < 3:
                    print("Uso: HISTORICO <SALA|PRIVADO> <nome_da_sala_ou_usuario>")
                    continue
                
                tipo = cmd_input[1].upper()
                nome_contexto = cmd_input[2]
                contexto_arquivo = f"sala_{nome_contexto}" if tipo == "SALA" else f"privado_{nome_contexto}"
                
                filename = os.path.join(self.history_path, f"hist_{contexto_arquivo}.txt")
                try:
                    with open(filename, "r", encoding='utf-8') as f:
                        print(f"--- Histórico de '{nome_contexto}' ({tipo}) ---\n{f.read()}--------------------")
                except FileNotFoundError:
                    print("Nenhum histórico encontrado para este contexto.")

            elif cmd == "KICK":
                if len(cmd_input) < 3: print("Uso: KICK <nome_sala> <usuario_a_remover>"); continue
                resposta = self._comunicar_tracker({"cmd": "KICK_USER", "room": cmd_input[1], "user_to_kick": cmd_input[2], "user": self.username})
                print(f"[Tracker]: {resposta.get('msg')}")

                if resposta.get("status") == "OK" and "kicked_user_info" in resposta:
                    kicked_user_info = resposta["kicked_user_info"]
                    target_user = kicked_user_info["user"]
                    notification_message = f"Você foi removido da sala '{cmd_input[1]}' pelo moderador."
                    
                    print(f"Enviando notificação de remoção para {target_user}...")
                    self._enviar_mensagem_ponto_a_ponto(target_user, notification_message, "[SISTEMA] ")
            
            elif cmd == "MUDAR_SENHA":
                if len(cmd_input) < 3: print("Uso: MUDAR_SENHA <nome_sala> <nova_senha>"); continue
                resposta = self._comunicar_tracker({"cmd": "CHANGE_ROOM_PASS", "room": cmd_input[1], "new_password": cmd_input[2], "user": self.username})
                print(f"[Tracker]: {resposta.get('msg')}")

            elif cmd == "SAIR":
                print("Encerrando o peer..."); self.server_socket.close(); break
            else:
                print("Comando não reconhecido.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python ClientePeer.py <porta>")
        sys.exit(1)
    peer = Peer('localhost', int(sys.argv[1]))
    peer.iniciar()
