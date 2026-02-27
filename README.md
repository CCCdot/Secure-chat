🔒 SecureChat: 终端端到端加密聊天系统 (E2EE)📖 项目简介SecureChat 是一个基于 端到端加密 (End-to-End Encryption, E2EE) 机制的轻量级命令行（CLI）聊天系统。本项目不仅实现了基础的消息加密，更重点针对真实网络环境中常见的中间人攻击 (MITM) 与 重放攻击 (Replay Attack) 进行了专门的安全架构设计。在整个通信生命周期中，服务器被降级为“盲路由（Blind Router）”。它既无法解密过境的聊天记录，也无法篡改或伪造通信双方的密钥。✨ 核心安全特性本项目参考了主流端到端加密协议（如 Signal Protocol）的底层密码学设计理念：🛡️ Ed25519 身份签名 (防 MITM)：系统引入长期有效的 Ed25519 身份密钥对。在交换临时 ECDH 公钥时，强制要求附加数字签名。这保证了即便是掌握了服务器控制权的黑客，也无法进行公钥掉包和中间人窃听。🔄 严格递增序列号 (防重放攻击)：在发送明文之前，将其与一个严格递增的 Sequence Number 打包后再进行 AES 整体加密。接收方解密后会校验序列号，自动丢弃黑客重复发送的过期或历史密文包。🔑 ECDH 密钥交换 (SECP256R1)：基于 NIST P-256 椭圆曲线的高效密钥交换，私钥绝对不出本地，提供安全基础保障。🎲 HKDF 密钥派生：将 ECDH 交换得出的高代数结构秘密，通过 Hash 运算安全地扩展为具有完美伪随机性的 256 位定长强密钥。🔒 AES-GCM 认证加密：对消息进行加密的同时提供 MAC (Message Authentication Code) 校验，保证数据的绝对机密性与防篡改完整性。⚙️ 环境依赖与安装本项目依赖 Python 官方推荐的现代密码学库 cryptography。克隆项目到本地git clone [https://github.com/yourusername/secure-chat.git](https://github.com/yourusername/secure-chat.git)
cd secure-chat
安装依赖库确保您的环境中已安装 Python 3.8 或以上版本，然后执行：pip install cryptography
🚀 快速开始本项目分为服务端和客户端两部分。测试时，您可以在本地开启多个终端窗口来模拟通信。1. 启动服务器 (盲路由)服务器默认在 127.0.0.1:5000 监听连接。python chat_server.py
(此时服务器处于等待连接状态，只负责盲转 JSON 数据包)2. 启动客户端 A (例如：Alice)新开一个终端窗口，启动 Alice 的客户端，并指定要聊天的对象为 Bob：# 用法: python chat_client.py <你的ID> <对方ID>
python chat_client.py Alice Bob
3. 启动客户端 B (例如：Bob)再新开一个终端窗口，启动 Bob 的客户端，并指定要聊天的对象为 Alice：python chat_client.py Bob Alice
连接成功后，双方将自动完成：生成 Ed25519 与 ECDH 密钥对。交换公钥并验证对方的数字签名。派生出只有双方知道的 AES-256 共享密钥。提示 ✓ 共享密钥已建立！现在可以安全通信了。 即可开始双向加密聊天。🔐 核心交互流程解析密钥生成：客户端启动后，crypto_utils.py 会生成长期身份密钥对 (Ed25519) 和 临时会话密钥对 (ECDH)。密钥交换与防篡改：Alice 将自己的 ECDH 公钥发送给 Bob 时，会附带使用自己 Ed25519 私钥生成的数字签名。Bob 收到后通过身份公钥验证签名，确保公钥未被中途替换。消息加密：发送消息时，消息体会被加上一个 seq 序列号（如 {"seq": 0, "msg": "你好"}），然后通过 AES-GCM 进行加密。消息解密与防重放：接收方解密出载荷后，会检查 seq 是否大于当前预期的序列号，如果是一个旧的序列号，则会直接抛弃（拦截重放攻击）。📂 项目文件结构SecureChat/
├── chat_server.py       # 服务端核心：负责维护 TCP 连接、盲转发加密消息与身份公钥
├── chat_client.py       # 客户端核心：实现身份核验、序列号追踪、消息缓冲与收发逻辑
├── crypto_utils.py      # 密码学引擎：封装 Ed25519, ECDH, HKDF, AES-GCM 等密码学原语
└── README.md            # 项目说明文档
📜 许可证本项目采用 MIT License 开源许可证。
