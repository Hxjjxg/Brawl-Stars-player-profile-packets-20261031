# 独立 Python 查询（开发记录）

目标是在游戏关闭时，通过 Python 直接连接国服服务器查询玩家资料；可以复用用户自己的登录凭据，不借用后台游戏会话。

当前已完成：

- `crypto_cn.py` 复现 X25519 + HSalsa/Salsa 19 轮 + Poly1305 及 nonce 小端加 2。
- 标准 20 轮对照 PyNaCl 一致；19 轮与 63 个实机加密样本逐字节一致。
- `native-crypto-vectors.json` 保存 6 组非秘密固定输入的原生加密结果，覆盖 0/1/11/32/65/128 字节。
- 登录 10101、返回 20104 和后续 40 个接收记录均已离线认证解密成功，24113 完整解析。
- `query_player.py` 为不依赖 ADB/Frida 的 TCP 客户端原型。首次 PC 实测在 10100 后被断开，尚未完成独立查询；调查见 DEBUG.md。

`capture_session.py` 仅用于一次性获取本人的登录材料和验证握手。它需要手机上的 Frida；实际查询客户端不导入 Frida。捕获的密钥、原始登录包和凭据全部保存到 Git 忽略的 `private/`，不得提交或打印。

标准算法资料：[libsodium secretbox](https://doc.libsodium.org/secret-key_cryptography/secretbox)、[PyNaCl SecretBox](https://pynacl.readthedocs.io/en/latest/secret/)。本项目 19 轮差异来自当前设备原生代码及实际密文比对，不能直接套用标准 20 轮库。
