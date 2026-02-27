# SecureChat: 终端端到端加密聊天系统 (E2EE)

## 项目简介

SecureChat 是一个基于端到端加密（End-to-End Encryption, E2EE）机制的轻量级命令行（CLI）聊天系统。本项目不仅实现了基础的消息加密，更重点针对真实网络环境中常见的中间人攻击（MITM）与重放攻击（Replay Attack）进行了专门的安全架构设计。

在整个通信生命周期中，服务器被降级为“盲路由（Blind Router）”。它既无法解密过境的聊天记录，也无法篡改或伪造通信双方的密钥。

---

## 核心安全特性

本项目参考了主流端到端加密协议（如Signal Protocol）的底层密码学设计理念：

- **Ed25519 身份签名（防MITM）**：系统引入长期有效的 Ed25519 身份密钥对。在交换临时 ECDH 公钥时，强制要求附加数字签名。这保证了即便是掌握了服务器控制权的黑客，也无法进行公钥掉包和中间人窃听。
- **严格递增序列号（防重放攻击）**：在发送明文之前，将其与一个严格递增的 Sequence Number 打包后再进行 AES 整体加密。接收方解密后会校验序列号，自动丢弃黑客重复发送的过期或历史密文包。
- **ECDH 密钥交换（SECP256R1）**：基于 NIST P-256 椭圆曲线的高效密钥交换，私钥绝对不出本地，提供安全基础保障。
- **HKDF 密钥派生**：将 ECDH 交换得出的高代数结构秘密，通过 Hash 运算安全地扩展为具有完美伪随机性的 256 位定长强密钥。
- **AES-GCM 认证加密**：对消息进行加密的同时提供 MAC（Message Authentication Code）校验，保证数据的绝对机密性与防篡改完整性。

---

## 环境依赖与安装

本项目依赖 Python 官方推荐的现代密码学库 `cryptography`。

1. **克隆项目到本地**
   ```bash
   git clone https://github.com/yourusername/secure-chat.git
   cd secure-chat
2. **安装依赖库**
确保您的环境中已安装 Python 3.8 或以上版本，然后执行：

```bash
pip install cryptography
3. **启动客户端 B（例如：Bob）**
再新开一个终端窗口，启动 Bob 的客户端，并指定要聊天的对象为 Alice：

```bash
python chat_client.py Bob Alice
