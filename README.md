# 🔒 SecureChat: 终端端到端加密聊天系统 (E2EE)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Cryptography](https://img.shields.io/badge/cryptography-secure-success.svg)](https://cryptography.io/en/latest/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 📖 项目简介

**SecureChat** 是一个基于 **端到端加密 (End-to-End Encryption, E2EE)** 机制的轻量级命令行（CLI）聊天系统。本项目不仅实现了基础的消息加密，更重点针对真实网络环境中常见的**中间人攻击 (MITM)** 与 **重放攻击 (Replay Attack)** 进行了专门的安全架构设计。

在整个通信生命周期中，服务器被降级为“盲路由（Blind Router）”。它既无法解密过境的聊天记录，也无法篡改或伪造通信双方的密钥。

## ✨ 核心安全特性

本项目参考了主流端到端加密协议（如 Signal Protocol）的底层密码学设计理念：

* 🛡️ **Ed25519 身份签名 (防 MITM)**：系统引入长期有效的 Ed25519 身份密钥对。在交换临时 ECDH 公钥时，强制要求附加数字签名。这保证了即便是掌握了服务器控制权的黑客，也无法进行公钥掉包和中间人窃听。

* 🔄 **严格递增序列号 (防重放攻击)**：在发送明文之前，将其与一个严格递增的 Sequence Number 打包后再进行 AES 整体加密。接收方解密后会校验序列号，自动丢弃黑客重复发送的过期或历史密文包。

* 🔑 **ECDH 密钥交换 (SECP256R1)**：基于 NIST P-256 椭圆曲线的高效密钥交换，私钥绝对不出本地，提供安全基础保障。

* 🎲 **HKDF 密钥派生**：将 ECDH 交换得出的高代数结构秘密，通过 Hash 运算安全地扩展为具有完美伪随机性的 256 位定长强密钥。

* 🔒 **AES-GCM 认证加密**：对消息进行加密的同时提供 `MAC (Message Authentication Code)` 校验，保证数据的绝对机密性与防篡改完整性。

## 📂 项目文件结构

```text
SecureChat/
├── chat_server.py       # 服务端核心：负责维护 TCP 连接、盲转发加密消息与签名公钥
├── chat_client.py       # 客户端核心：实现身份核验、序列号追踪、消息缓冲与收发逻辑
├── crypto_utils.py      # 密码学引擎：封装 Ed25519, ECDH, HKDF, AES-GCM 等密码学原语
├── Technical_Details.md # 技术细节解析：包含协议设计与底层逻辑分析（可选附带）
└── README.md            # 项目说明文档
