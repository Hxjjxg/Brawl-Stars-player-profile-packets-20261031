# Python 无头查询：国服 69.114.1

已经在**游戏关闭、没有游戏进程、没有加载 Frida**的条件下，完成 Python 自己建连接、握手、登录和查询。复用的是用户本人的登录材料；每次连接重新生成临时密钥和 nonce，并处理服务器的新 challenge，未重放旧会话密文。

**当前网络限制要区分清楚：** 这台电脑的校园网路径在 10100 Hello 后被重置；手机蜂窝网络能接收 20100。实际成功的查询用了手机作为纯 TCP 网络转发，手机上运行的只是系统 netcat，游戏保持关闭。**当前环境的完全脱离手机直连尚未成功。** Python 客户端本身支持直接 TCP 和 HTTP CONNECT；换到能够访问游戏端口的网络即可尝试直连，但这里不把未成功的路径写成已验证。

## 现在就能运行

在仓库根目录运行；这台机器已经装好 PyNaCl 1.6.2，并已在本机忽略目录中保存了可用的本人登录材料：

```powershell
python .\headless\query_player.py 88GLGUC2 --via-phone-network
python .\headless\query_player.py LUY2YJP --via-phone-network --output .\player.json
```

这条模式需要 ADB 连接正常、手机 root 可用以及系统 netcat；它会临时建立仅监听回环地址的转发，并在查询结束后关闭。无需打开游戏、点击页面或启动 Frida。多设备时加 `--serial PJ696HEY9DNRLFFQ`。

示例输出来自本次实际查询：

```json
{
  "tag": "#88GLGUC2",
  "name": "TIG丨初夏",
  "trophies": 234568,
  "highest_trophies": 234568,
  "heroes": 108,
  "transport": "standalone-python-tcp",
  "network": "phone-tcp-relay",
  "response_id": 24113
}
```

可达网络上的直接连接用法：

```powershell
python .\headless\query_player.py 88GLGUC2
python .\headless\query_player.py 88GLGUC2 --proxy http://127.0.0.1:10808
```

HTTP 代理需要允许 CONNECT 到游戏 9339 端口。当前电脑已有代理及一次隔离代理测试也未成功，不能仅凭本地代理端口处于监听就认定它可用。没有修改用户已有代理配置。

安装依赖：`python -m pip install -r .\headless\requirements.txt`。`--output` 保存完整解析树；`--evidence` 另存查询明文、资料查询/返回的实际加密 frame 和消息编号/长度等元数据，不保存登录包、session key 或 nonce。

## 已验证的数据

同一个新登录的 Python 会话连续查询三名玩家，前后都检查到游戏进程不存在；结果保存在 [live-verification.json](live-verification.json) 及其中指向的 `validation/` 子目录。

| 标签 | 玩家 | 当前/最高奖杯 | 英雄 | 请求明文/返回明文字节 |
|---|---|---:|---:|---:|
| #LUY2YJP | 胡须局锦绣谷 | 54278 / 54278 | 107 | 11 / 3166 |
| #88GLGUC2 | TIG丨初夏 | 234568 / 234568 | 108 | 11 / 4994 |
| #89V9YJ0RJ | 李星云 | 31247 / 31249 | 105 | 11 / 3316 |

三个返回均完整解析到末尾，逐字段追踪覆盖全部字节。初夏的杯数相比前次 234527 已更新，李星云也能区分当前和最高奖杯；这些是服务器新返回，不是读旧样本。

同会话第二次查询间隔 0.5 秒时曾未收到返回；间隔 2 秒则三次均成功。客户端现保守地在两次成功查询之间自动等待 2 秒。服务端具体阈值和策略尚未确认。

## 真正发上网的包

仍是 **15081 请求 / 24113 返回**，版本 0。原有 `protocol.py` 负责资料明文编解码；这里新增登录和传输加密。

一次连接依次完成：

| 消息 | 本次验证的结构 |
|---|---|
| 10100 | ClientHello；本次包体 76 字节，包含协议/密钥版本、版本参数、资源哈希等；复用同版本实际 Hello |
| 20100 | Int32BE 长度 24 + 24 字节服务器 challenge |
| 10101 | 32 字节客户端临时公钥 + 加密后的 challenge、24 字节客户端 nonce、本人登录包 |
| 20104 | 认证解密后，前 24 字节是服务端接收 nonce，再 32 字节是会话密钥，其后为 LoginOk 数据 |
| 15081 | 加密后的查询明文：16 字节认证标签 + 11 字节加密内容 |
| 24113 | 认证解密后得到原有 PlayerProfile 返回明文 |

每条消息仍有 7 字节头：ID UInt16BE + **加密后**包体长度 UInt24BE + 版本 UInt16BE。查询 #89V9YJ0RJ 的实际示例见 [89V9YJ0RJ-query-evidence.json](89V9YJ0RJ-query-evidence.json)：

```text
查询明文（11 字节）
00 00 00 00 00 68 00 c8 b8 84 00

实际请求头（7 字节）
3a e9 00 00 1b 00 00
      └── 27 字节加密包体 = 16 字节认证标签 + 11 字节内容

实际返回头（7 字节）
5e 31 00 0d 04 00 00
      └── 3332 字节加密包体 = 16 + 3316 字节资料明文
```

完整加密 frame 在 evidence 的 sent/received 数组里，仅对 15081/24113 保存 frame_hex；握手只保留编号、版本和长度。nonce 不随普通查询包发送，由双方会话分别维护，每条消息先按 192 位小端加 2，再加/解密。新连接必须重新握手，不能拿这条密文直接重放。

## 加密差异与验证

国服运行时代码 `libg.so+0xAD3EFC` 是 `mov w15, #0x13`，核心循环为 **19 个 Salsa 单轮**。这同时影响 HSalsa 子密钥派生和流加密，直接用标准 PyNaCl SecretBox 的 20 轮不匹配。`crypto_cn.py` 实现此变体；X25519 使用 PyNaCl，Blake2b 使用 Python 标准库。

- 登录前共享密钥：X25519 的结果经 HSalsa19（16 字节零输入）派生。
- 10101 nonce：Blake2b-24(clientPublic || serverPublic)。
- 20104 nonce：Blake2b-24(clientNonce || clientPublic || serverPublic)。
- 登录后用服务器返回的会话密钥，以及各自方向的 nonce。
- Poly1305 认证标签验证失败会中止，不继续解析不可信明文。

[capture-replay-verification.json](capture-replay-verification.json) 记录最终 **175 个原生加密样本逐字节匹配、88 条接收记录认证解密通过**。另外，[native-crypto-vectors.json](native-crypto-vectors.json) 使用公开固定输入，直接调用过实机原生函数，覆盖 0/1/11/32/65/128 字节，便于不接手机的回归测试。

```powershell
python -m unittest discover -s .\headless -p test_headless.py
python .\headless\verify_live.py --via-phone-network
```

前者有 8 项离线测试；后者会实际查询上述三名玩家，并保存独立时间戳目录，不覆盖旧抓包。

标准算法资料：[libsodium secretbox](https://doc.libsodium.org/secret-key_cryptography/secretbox)、[PyNaCl SecretBox](https://pynacl.readthedocs.io/en/latest/secret/)。19 轮差异以本机原生代码及实际密文为证据。

## 登录材料与刷新

`private/login-material.json` 含本人登录凭据，已被 Git 忽略。当前复用同版本实际登录包，未实现 QQ/微信的重新授权流程；材料失效或游戏版本变化时，需要重新采集，不能保证永久可用。特殊 type=2 页面模拟资料还依赖战报上下文，本脚本的按标签查询针对普通玩家。

刷新时先正常登录自己的游戏，再启动一次观察器：

```powershell
adb -s PJ696HEY9DNRLFFQ forward tcp:37043 tcp:27042
Remove-Item -LiteralPath .\headless\STOP.session -ErrorAction SilentlyContinue
$gamePid = (& adb -s PJ696HEY9DNRLFFQ shell pidof com.tencent.tmgp.supercell.brawlstars).Trim()
& 'F:\frida16\Scripts\python.exe' -u .\headless\capture_session.py --pid $gamePid --reconnect
```

观察器针对已核对的 69.114.1 ARM64 函数做指纹检查。它会让空闲连接断开一次；在手机出现重新登录按钮时点击，等登录完成。用另一个窗口创建 `headless/STOP.session` 并等观察器退出，然后提取它打印的本机 capture 文件名：

```powershell
New-Item -ItemType File -Path .\headless\STOP.session -Force
python .\headless\extract_login.py .\headless\private\session-实际编号.jsonl
```

提取器会验证 challenge、nonce 和登录返回的认证，再保存可复用的本人登录包；不会把内容打印到终端，也拒绝把材料输出到 private 目录以外。Frida 只在这一步采集材料时使用，普通查询不导入它。

## Python 中调用

在网络能够直接访问游戏服务器时，从仓库根目录调用：

```python
import json
from pathlib import Path
from headless.query_player import Client

credentials = json.loads(Path('headless/private/login-material.json').read_text(encoding='utf-8'))
with Client(credentials) as client:
    decoded, evidence = client.query('88GLGUC2')
    print(decoded['profile']['display']['name'])
```

`Client` 本身没有 ADB 或 Frida 依赖；`phone_network.py` 是当前网络环境需要时才启用的独立网络转发适配器。调查过程和未成功的路径保留在 [DEBUG.md](DEBUG.md)。
