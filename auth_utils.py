# auth_utils.py (Versão Corrigida)
import hashlib

saltSenha = "Universidade de Brasilia"

# ... (as outras funções de hash permanecem as mesmas) ...
def salt_para_hex(salt_Senha):
    return salt_Senha.encode().hex()

def hasheando_senha(senha: str, salt: str) -> str:
    senha = senha.encode().hex()
    sha256 = hashlib.sha256()
    senha_hasheada = salt_para_hex(saltSenha) + senha
    sha256.update(senha_hasheada.encode())
    senha_hasheada = sha256.hexdigest()
    return senha_hasheada 

def cadastrar_usuario(nome, senha, dictUsuarios):
    if nome in dictUsuarios:
        return False, "Usuário já existe"
    
    hash_senha = hasheando_senha(senha, saltSenha)
    # GARANTA QUE ESTA LINHA ESTÁ ASSIM:
    dictUsuarios[nome] = {"pass": hash_senha}
    return True, "Usuário cadastrado com sucesso"

def login_usuario(nome, senha, dictUsuarios):
    if nome not in dictUsuarios:
        return False, "Usuário não encontrado"
    
    hash_senha_digitada = hasheando_senha(senha, saltSenha)
    # E QUE ESTA LINHA ESTÁ ASSIM:
    if dictUsuarios[nome]["pass"] == hash_senha_digitada:
        return True, "Login realizado com sucesso"
    else:
        return False, "Senha incorreta"