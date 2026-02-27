import socket
import json
import threading
import base64
import time
from crypto_utils import CryptoUtils


class ChatClient:
    def __init__(self, server_host='127.0.0.1', server_port=5000):
        self.client_id = None
        self.peer_id = None
        self.server_host = server_host
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.crypto = CryptoUtils()

        # 临时会话密钥 (ECDH)
        self.private_key = None
        self.public_key = None
        self.shared_key = None

        # 身份认证长期密钥 (Ed25519)
        self.id_private_key = None
        self.id_public_key = None
        self.peer_id_public_key = None  # 保存对方的身份公钥

        # 防重放攻击序列号
        self.send_seq = 0
        self.recv_seq = 0

        # 密钥交换状态
        self.key_exchange_state = {
            'my_key_sent': False,
            'peer_key_received': False,
            'handshake_complete': False
        }

        # 消息缓冲区
        self.message_buffer = []

    def connect(self, client_id, peer_id):
        """连接到服务器并初始化加密"""
        self.client_id = client_id
        self.peer_id = peer_id

        try:
            # 连接到服务器
            self.socket.connect((self.server_host, self.server_port))
        except ConnectionRefusedError:
            print(f"❌ 无法连接到服务器 {self.server_host}:{self.server_port}")
            print("请确保服务器正在运行")
            return False

        # 注册到服务器
        register_msg = json.dumps({
            'type': 'register',
            'client_id': client_id
        })
        self.socket.send(register_msg.encode())

        # 生成密钥对
        print("生成长期身份密钥对 (Ed25519) 和临时会话密钥对 (ECDH)...")
        self.id_private_key, self.id_public_key = self.crypto.generate_identity_key_pair()
        self.private_key, self.public_key = self.crypto.generate_ecdh_key_pair()

        # 启动接收线程
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # 立即发送自己的公钥
        self.send_public_key()

        # 同时请求对方的公钥
        self.request_public_key()

        print(f"已连接到服务器。你的ID: {client_id}, 对方ID: {peer_id}")
        print("正在交换公钥...")

        return True

    def send_public_key(self):
        """发送自己的公钥（附带身份签名）给对方"""
        try:
            # 序列化公钥和身份公钥
            serialized_pubkey = self.crypto.serialize_public_key(self.public_key)
            serialized_id_pubkey = self.crypto.serialize_identity_public_key(self.id_public_key)

            # 对ECDH临时公钥进行数字签名 (防中间人篡改)
            signature = self.crypto.sign_data(self.id_private_key, serialized_pubkey)

            print(f"【{self.client_id}】公钥及签名生成完成")

            # Base64编码
            b64_key = base64.b64encode(serialized_pubkey).decode()
            b64_id_key = base64.b64encode(serialized_id_pubkey).decode()
            b64_sig = base64.b64encode(signature).decode()

            # 构建消息
            message = json.dumps({
                'type': 'public_key',
                'from_id': self.client_id,
                'target_id': self.peer_id,
                'key': b64_key,
                'identity_key': b64_id_key,
                'signature': b64_sig
            })

            # 发送
            self.socket.send(message.encode())
            self.key_exchange_state['my_key_sent'] = True
            print(f"【{self.client_id}】✓ 身份公钥、会话公钥及签名已发送给 {self.peer_id}")

            # 检查是否完成交换
            if self.key_exchange_state['peer_key_received']:
                self.complete_handshake()

        except Exception as e:
            print(f"【{self.client_id}】✗ 发送公钥失败: {e}")

    def derive_shared_key(self, peer_public_key):
        """收到对方公钥后派生共享密钥"""
        if self.key_exchange_state['peer_key_received']:
            return  # 避免重复处理

        try:
            print(f"【{self.client_id}】正在派生共享密钥...")
            self.shared_key = self.crypto.derive_shared_key(self.private_key, peer_public_key)
            self.key_exchange_state['peer_key_received'] = True
            print(f"【{self.client_id}】✓ 共享密钥派生成功")

            # 检查是否完成交换
            if self.key_exchange_state['my_key_sent']:
                self.complete_handshake()

        except Exception as e:
            print(f"【{self.client_id}】✗ 派生共享密钥失败: {e}")

    def complete_handshake(self):
        """完成握手"""
        if self.key_exchange_state['handshake_complete']:
            return  # 已经完成过了

        self.key_exchange_state['handshake_complete'] = True
        print("\n" + "=" * 50)
        print("✓ 共享密钥已建立！现在可以安全通信了。")
        print("=" * 50)
        print("输入消息 (输入 'exit' 退出):")

        # 处理缓冲的消息
        if self.message_buffer:
            print(f"处理 {len(self.message_buffer)} 条缓冲消息...")
            for buffered_msg in self.message_buffer:
                self.process_buffered_message(buffered_msg)
            self.message_buffer.clear()

    def request_public_key(self):
        """向对方请求公钥"""
        message = json.dumps({
            'type': 'request_key',
            'from_id': self.client_id,
            'target_id': self.peer_id
        })
        self.socket.send(message.encode())
        print(f"【{self.client_id}】已向 {self.peer_id} 请求公钥")

    def send_message(self, message):
        """加密并发送消息 (防重放升级)"""
        if not self.shared_key:
            print("❌ 错误：共享密钥尚未建立")
            return

        try:
            # 封装带有序列号的内层载荷 (防重放攻击)
            inner_payload = json.dumps({
                'seq': self.send_seq,
                'msg': message
            })
            self.send_seq += 1

            # 加密包含序列号的消息体
            encrypted = self.crypto.encrypt_message(self.shared_key, inner_payload)
            b64_encrypted = base64.b64encode(encrypted).decode()

            # 发送到服务器
            msg_obj = json.dumps({
                'type': 'message',
                'from_id': self.client_id,
                'target_id': self.peer_id,
                'encrypted_data': b64_encrypted
            })

            self.socket.send(msg_obj.encode())
            print(f"你: {message}")

        except Exception as e:
            print(f"❌ 发送消息失败: {e}")

    def receive_messages(self):
        """接收消息的线程函数"""
        while True:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break

                try:
                    message = json.loads(data.decode())
                except json.JSONDecodeError:
                    print(f"【{self.client_id}】收到无效JSON数据")
                    continue

                if message['type'] == 'public_key':
                    print(f"【{self.client_id}】收到公钥及签名，来自: {message.get('from_id')}")

                    if 'key' not in message or 'signature' not in message or 'identity_key' not in message:
                        print(f"【{self.client_id}】✗ 错误：消息缺少公钥、身份或签名字段！")
                        continue

                    b64_key = message['key']
                    b64_id_key = message['identity_key']
                    b64_sig = message['signature']

                    try:
                        serialized_key = base64.b64decode(b64_key)
                        serialized_id_key = base64.b64decode(b64_id_key)
                        signature = base64.b64decode(b64_sig)

                        # 反序列化对方的身份公钥 (此处使用首次信任模型 TOFU)
                        peer_id_pubkey = self.crypto.deserialize_identity_public_key(serialized_id_key)

                        # 验证签名，确保ECDH公钥未被中间人篡改
                        if not self.crypto.verify_signature(peer_id_pubkey, signature, serialized_key):
                            print(f"【{self.client_id}】🚨 致命警告：数字签名验证失败！可能遭遇中间人攻击！")
                            continue

                        print(f"【{self.client_id}】✓ 数字签名验证通过，确认密钥未被篡改")
                        self.peer_id_public_key = peer_id_pubkey

                        peer_public_key = self.crypto.deserialize_public_key(serialized_key)
                        self.derive_shared_key(peer_public_key)
                    except Exception as e:
                        print(f"【{self.client_id}】✗ 处理公钥失败: {e}")

                elif message['type'] == 'key_request':
                    # 收到公钥请求，立即发送自己的公钥
                    requester = message.get('from_id', '未知')
                    print(f"【{self.client_id}】{requester} 请求你的公钥，正在发送...")
                    self.send_public_key()

                elif message['type'] == 'message':
                    if not self.shared_key:
                        print(f"【{self.client_id}】收到加密消息但共享密钥尚未建立")

                        # 缓冲消息
                        self.message_buffer.append(message)
                        print(f"【{self.client_id}】消息已缓冲，当前缓冲数: {len(self.message_buffer)}")

                        # 如果还没有收到过对方公钥，则请求
                        if not self.key_exchange_state['peer_key_received']:
                            print(f"【{self.client_id}】正在请求公钥...")
                            self.request_public_key()
                        continue

                    # 正常的消息处理
                    b64_encrypted = message['encrypted_data']
                    encrypted_data = base64.b64decode(b64_encrypted)

                    try:
                        # 解密并解析带序列号的载荷
                        decrypted_str = self.crypto.decrypt_message(self.shared_key, encrypted_data)
                        payload = json.loads(decrypted_str)

                        incoming_seq = payload.get('seq')
                        incoming_msg = payload.get('msg')

                        # 防重放攻击检查
                        if incoming_seq is None or incoming_seq < self.recv_seq:
                            print(f"\n🚨 警告：丢弃重放或过期消息！(收到 Seq: {incoming_seq}, 期望 >= {self.recv_seq})")
                            continue

                        # 验证通过，更新期望序列号并打印消息
                        self.recv_seq = incoming_seq + 1
                        print(f"\n{message['from_id']}: {incoming_msg}")
                    except Exception as e:
                        print(f"\n❌ 解密或解析失败: {e}")

                else:
                    print(f"【{self.client_id}】未知消息类型: {message}")

            except ConnectionError:
                print(f"\n【{self.client_id}】连接已断开")
                break
            except Exception as e:
                print(f"【{self.client_id}】接收错误: {e}")
                break

    def process_buffered_message(self, message):
        """处理缓冲的加密消息"""
        try:
            b64_encrypted = message['encrypted_data']
            encrypted_data = base64.b64decode(b64_encrypted)

            # 解密内层载荷
            decrypted_str = self.crypto.decrypt_message(self.shared_key, encrypted_data)
            payload = json.loads(decrypted_str)

            incoming_seq = payload.get('seq')
            # 同样应用防重放检查
            if incoming_seq is None or incoming_seq < self.recv_seq:
                print(f"\n🚨 [历史消息] 忽略重放消息")
                return

            self.recv_seq = incoming_seq + 1
            print(f"\n[历史消息] {message['from_id']}: {payload.get('msg')}")
        except Exception as e:
            print(f"\n❌ 历史消息解密失败: {e}")

    def start_chat(self):
        """开始聊天循环"""
        try:
            while True:
                if self.shared_key:  # 只有建立密钥后才能发送消息
                    try:
                        message = input()
                    except EOFError:
                        break

                    if message.lower() == 'exit':
                        break
                    self.send_message(message)
        except KeyboardInterrupt:
            pass
        finally:
            self.socket.close()
            print("聊天结束")

    def print_status(self):
        """打印当前状态"""
        status = []
        if self.key_exchange_state['my_key_sent']:
            status.append("✓ 已发送公钥(含签名)")
        else:
            status.append("✗ 未发送公钥")

        if self.key_exchange_state['peer_key_received']:
            status.append("✓ 已验证对方签名及公钥")
        else:
            status.append("✗ 未收到对方公钥")

        if self.key_exchange_state['handshake_complete']:
            status.append("✓ 握手完成")
        else:
            status.append("✗ 握手未完成")

        print("状态:", " | ".join(status))


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("用法: python chat_client.py <你的ID> <对方ID>")
        print("示例: python chat_client.py Alice Bob")
        sys.exit(1)

    client_id = sys.argv[1]
    peer_id = sys.argv[2]

    client = ChatClient()
    if client.connect(client_id, peer_id):
        # 每隔2秒打印一次状态，直到握手完成
        def status_monitor():
            while not client.key_exchange_state['handshake_complete']:
                client.print_status()
                time.sleep(2)


        monitor_thread = threading.Thread(target=status_monitor, daemon=True)
        monitor_thread.start()

        client.start_chat()