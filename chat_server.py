import socket
import threading
import json


class ChatServer:
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.clients = {}  # 客户端连接字典
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lock = threading.Lock()

    def start(self):
        """启动服务器"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"服务器启动在 {self.host}:{self.port}")

        while True:
            client_socket, address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        """处理客户端连接"""
        client_id = None
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                try:
                    message = json.loads(data.decode())
                except json.JSONDecodeError:
                    print(f"收到无效JSON数据: {data[:100]}...")
                    continue

                # 调试：显示收到的消息
                print(f"【服务器】收到消息类型: {message.get('type')}")

                if message['type'] == 'register':
                    # 客户端注册
                    client_id = message['client_id']
                    with self.lock:
                        self.clients[client_id] = client_socket
                    print(f"客户端 {client_id} 已连接")
                    print(f"当前在线客户端: {list(self.clients.keys())}")

                elif message['type'] == 'request_key':
                    # 处理公钥请求
                    target_id = message['target_id']
                    requester_id = message['from_id']
                    print(f"客户端 {requester_id} 请求 {target_id} 的公钥")

                    with self.lock:
                        if target_id in self.clients:
                            # 向目标客户端转发请求
                            forward_msg = json.dumps({
                                'type': 'key_request',
                                'from_id': requester_id
                            })

                            print(f"【服务器】转发公钥请求给 {target_id}")
                            self.clients[target_id].send(forward_msg.encode())
                            print(f"【服务器】✓ 公钥请求已转发给 {target_id}")
                        else:
                            print(f"【服务器】✗ 目标客户端 {target_id} 不在线！当前在线: {list(self.clients.keys())}")

                elif message['type'] == 'public_key':
                    # 处理公钥转发（包括签名和身份密钥）
                    sender_id = message['from_id']
                    target_id = message['target_id']

                    print(f"【服务器】收到公钥 - 来自: {sender_id}, 目标: {target_id}")
                    if 'key' in message:
                        print(f"【服务器】公钥数据长度: {len(message['key'])} 字符")
                    else:
                        print(f"【服务器】✗ 错误：消息中没有 'key' 字段！")
                        continue

                    with self.lock:
                        if target_id in self.clients:
                            forward_msg = json.dumps({
                                'type': 'public_key',
                                'from_id': sender_id,
                                'key': message['key'],
                                'identity_key': message.get('identity_key'),
                                'signature': message.get('signature')
                            })

                            print(f"【服务器】转发公钥(及签名)给 {target_id}...")
                            self.clients[target_id].send(forward_msg.encode())
                            print(f"【服务器】✓ 公钥已转发给 {target_id}")
                        else:
                            print(f"【服务器】✗ 目标客户端 {target_id} 不在线！当前在线: {list(self.clients.keys())}")

                elif message['type'] == 'message':
                    # 转发加密消息
                    target_id = message['target_id']
                    sender_id = message.get('from_id', '未知')

                    print(f"【服务器】收到消息 - 来自: {sender_id}, 目标: {target_id}")

                    with self.lock:
                        if target_id in self.clients:
                            print(f"【服务器】转发消息给 {target_id}...")
                            self.clients[target_id].send(data)
                            print(f"【服务器】✓ 消息已转发给 {target_id}")
                        else:
                            print(f"【服务器】✗ 目标客户端 {target_id} 不在线！当前在线: {list(self.clients.keys())}")

                else:
                    print(f"【服务器】未知消息类型: {message}")

        except ConnectionError as e:
            print(f"【服务器】客户端 {client_id} 连接错误: {e}")
        except Exception as e:
            print(f"【服务器】处理客户端 {client_id} 时发生错误: {e}")
        finally:
            if client_id:
                with self.lock:
                    if client_id in self.clients:
                        del self.clients[client_id]
                print(f"客户端 {client_id} 已断开")
                print(f"剩余在线客户端: {list(self.clients.keys())}")
            client_socket.close()


if __name__ == "__main__":
    server = ChatServer()
    server.start()