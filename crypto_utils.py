from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def gerar_chaves():
    """Gera um par de chaves (privada e pública) RSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serializar_chave_publica(public_key):
    """Converte um objeto de chave pública em uma string no formato PEM para ser enviada pela rede."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def desserializar_chave_publica(pem_string):
    """Converte uma string no formato PEM de volta para um objeto de chave pública."""
    return serialization.load_pem_public_key(
        pem_string.encode('utf-8')
    )

def criptografar_mensagem(public_key, mensagem):
    """Criptografa uma mensagem usando a chave pública do destinatário."""
    return public_key.encrypt(
        mensagem.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def descriptografar_mensagem(private_key, mensagem_cifrada):
    """Descriptografa uma mensagem usando a chave privada do receptor."""
    return private_key.decrypt(
        mensagem_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')
