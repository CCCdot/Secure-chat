from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os


class CryptoUtils:
    @staticmethod
    def generate_identity_key_pair():
        """生成长期身份密钥对 (Ed25519，用于数字签名/防中间人攻击)"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_identity_public_key(public_key):
        """序列化身份公钥"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_identity_public_key(serialized_key):
        """反序列化身份公钥"""
        return serialization.load_pem_public_key(serialized_key)

    @staticmethod
    def sign_data(private_key, data):
        """使用身份私钥对二进制数据进行数字签名"""
        return private_key.sign(data)

    @staticmethod
    def verify_signature(public_key, signature, data):
        """使用身份公钥验证数字签名"""
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def generate_ecdh_key_pair():
        """生成临时ECDH密钥对（用于会话密钥交换）"""
        private_key = ec.generate_private_key(ec.SECP256R1())  # P-256曲线
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key):
        """序列化ECDH公钥以便传输"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_public_key(serialized_key):
        """反序列化接收到的ECDH公钥"""
        return serialization.load_pem_public_key(serialized_key)

    @staticmethod
    def derive_shared_key(my_private_key, peer_public_key):
        """使用自己的私钥和对方的公钥派生共享密钥"""
        shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)

        # 使用HKDF从共享密钥派生固定长度的AES密钥
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256位AES密钥
            salt=None,
            info=b'e2ee-chat-key'
        ).derive(shared_secret)

        return derived_key

    @staticmethod
    def encrypt_message(key, plaintext):
        """使用AES-GCM加密消息"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 随机数（12字节，用于GCM模式）
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return nonce + ciphertext  # 将nonce和密文拼接

    @staticmethod
    def decrypt_message(key, encrypted_data):
        """使用AES-GCM解密消息"""
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:12]  # 提取前12字节作为nonce
        ciphertext = encrypted_data[12:]  # 剩余部分是密文
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    @staticmethod
    def test_key_serialization():
        """测试密钥序列化/反序列化及签名"""
        print("=== 测试密钥与签名机制 ===")

        # 生成身份密钥与签名测试
        id_priv, id_pub = CryptoUtils.generate_identity_key_pair()
        test_data = b"hello world"
        sig = CryptoUtils.sign_data(id_priv, test_data)
        if CryptoUtils.verify_signature(id_pub, sig, test_data):
            print("1. ✓ Ed25519 签名验证通过")
        else:
            print("1. ✗ Ed25519 签名验证失败")

        # 序列化公钥
        private_key, public_key = CryptoUtils.generate_ecdh_key_pair()
        serialized = CryptoUtils.serialize_public_key(public_key)
        print(f"2. ECDH公钥序列化完成，长度: {len(serialized)} 字节")

        # 派生共享密钥测试
        private_key2, public_key2 = CryptoUtils.generate_ecdh_key_pair()
        shared_key1 = CryptoUtils.derive_shared_key(private_key, public_key2)
        shared_key2 = CryptoUtils.derive_shared_key(private_key2, public_key)

        if shared_key1 == shared_key2:
            print("3. ✓ 共享密钥派生测试通过")
        else:
            print("3. ✗ 共享密钥派生测试失败")

        return True


if __name__ == "__main__":
    CryptoUtils.test_key_serialization()