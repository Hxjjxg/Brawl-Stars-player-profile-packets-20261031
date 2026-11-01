# 国服 69.114.1：按标签查询玩家资料

工作目录：`F:\cn-bs-lib_v69\player-profile-packets-20261031`。

本目录单独使用 Git 管理脚本、报告和抓包证据。接收令牌、临时运行状态与缓存由 `.gitignore` 排除；本地实际使用的采集 JS 保持原样，库内保存去除令牌的 `.template.js`。新检出仓库后，先执行 `python .\init_capture_config.py capture` 生成配套的本机 JS 和接收配置，再按下文启动；已有配置时该命令会拒绝覆盖。补测会话可用对应目录名代替 capture。原 ZIP 仅是解包来源，`original/arm64-socket` 的版本化脚本同样以模板保存。

**完整抓包细节与字节对照：[抓包细节.md](抓包细节.md)。** 字段结构速查见 [协议结构.md](协议结构.md)；每一帧的逐字段 CSV / JSON / Markdown 在 `details/`。运行 `python .\build_details.py` 可以从原始样本重新生成这些文件。

**新增实机补测：[88GLGUC2、队友与对手的补测结果](validation-88GLGUC2/补测结果.md)。** 追加 14 帧中已真实触发两次 context12 和 BattleLogEntry 分支（88 / 100 字节请求），并补齐返回中“无战队、无集合、无可选整数”的样本。原 9 帧与新增会话分别保存、分别复核。

**2026-11-01 新战绩补测：[5 名玩家、10 帧与非空 LogicLong](validation-real-20261101/补测结果.md)。** 新增 3 个附带战报的请求，其中 `optional_long_104` 两次非空，已按实际字节完整验证。累计 33 帧；各会话分别保存，采集均已停止。

实机验证时间：2026-10-31，设备 PJ696HEY9DNRLFFQ，游戏 69.114.1，ARM64。
原始 libg.so SHA256：`7b643e1c97a9a4a2778b46d0a2e0c3dfd3598f84e36f68f94abfa3dc6bce3aff`。

## 已验证结果

| 标签 | high | low | 返回玩家名 | 页面奖杯 | 已收集英雄 |
|---|---:|---:|---|---:|---:|
| #LUY2YJP | 108 | 202449 | 胡须局锦绣谷 | 54278 | 107 |
| #2V9UJL9QR | 103 | 11232845 | 🌧️清雨QINGYU💫 | 99116 | 107 |
| #88GLGUC2 | 107 | 900170 | TIG丨初夏 | 234527 | 108 |
| #2PP | 0 | 1 | 本次只捕获到请求，没有对应 24113 返回 | — | — |

**本国服版本查询请求是 15081，返回是 24113。** 参考仓库 packets.json 把查询请求标成 14113，不能把这个编号直接套到当前版本。

两份不同玩家的返回体分别为 3166 / 4765 字节，`protocol.py` 都能完整解析到包尾。英雄、统计、昵称、展示数据、可选集合、可选战队头和返回尾部均已覆盖。部分字段业务含义尚未命名，保留原生对象偏移作为字段标签；它们不是包体偏移。

## 普通标签查询请求结构

消息类型 15081，实抓版本号 0。普通查询的包体是 11 字节：

| 包体偏移 | 编码 | 字段 | 本次样本 |
|---:|---|---|---|
| 0 | Bool | 是否带额外上下文 | false，`00` |
| 1 | VInt | 查询参数；有战报时等于条目所载英雄奖杯之和，普通查询通常为 0 | 0，`00` |
| 2 | UInt32，大端 | 玩家 high | 108，`00 00 00 6c` |
| 6 | UInt32，大端 | 玩家 low | 202449，`00 03 16 d1` |
| 10 | Bool | 是否带 BattleLogPlayerEntry 类上下文 | false，`00` |

`#LUY2YJP` 实抓包体：

```text
00 00 00 00 00 6c 00 03 16 d1 00
```

这 11 字节不直接包含标签字符串。标签先转换成 high / low，再各写一个**固定 4 字节大端整数**。它们在请求里不是 VInt。

完整编码顺序为：Bool；若 true 则 12 个 VInt；VInt 查询参数；high UInt32BE；low UInt32BE；Bool；若 true 则编码 BattleLogPlayerEntry 类子结构。两个分支已按原生读写函数实现编解码，并在两次补测的 5 个对手请求中实际触发；全部逐字节重编码一致。子结构内部 optional_long_104 的非空情况已在 2026-11-01 请求 7 / 9 中实抓到，值分别为 high=103 / low=167892、high=111 / low=577840，业务含义仍未确认。

Bool 使用 ByteStream 的位打包；后续非 Bool 读取会重置位游标。普通查询的两个 Bool 各占一个字节。第一个可选分支不存在、查询参数为 0 时，表中固定偏移成立；其他分支或多字节 VInt 会改变后续偏移。

7 字节消息记录头：消息 ID UInt16BE、包体长度 UInt24BE、版本 UInt16BE。`protocol.py encode` 输出的 frame_hex 是据此重建的明文消息记录，不是从网卡直接抓到的加密 TCP 流。

## 返回结构

24113 的主体按顺序为：

1. PlayerProfile：玩家 ID（两个 **VInt**）、两个 DataReference、英雄条目数组、统计键值数组、PlayerDisplayData、其他资料和可选集合字段。
2. Bool：是否有战队头；若 true，解码 AllianceHeaderEntry。
3. DataReference。
4. VInt。

DataReference 编码是 VInt table；table 不为 0 时再跟 VInt instance。字符串是 Int32BE 字节数加 UTF-8 内容，-1 表示空指针。完整字段顺序见 `protocol.py`；两份 `samples/*-decoded.json` 保存了完整解析结果。

不要把请求的两个 UInt32BE 与返回开头的两个 VInt 混用。例如 #LUY2YJP 的返回 ID 开头是 `ac 01 91 db 18`，解码后同样是 high=108、low=202449。

## 单独的标签转换

独立文件：`tag_id.py` 和 `tag-id.js`，无第三方依赖。算法与用法见 `标签转换.md`。

```powershell
python .\tag_id.py to-id '#LUY2YJP'
python .\tag_id.py to-tag 108 202449
node .\tag-id.js to-id '#LUY2YJP'
node .\tag-id.js to-tag 108 202449
```

## 离线编解码

从本工作目录运行：

```powershell
python .\protocol.py encode LUY2YJP
python .\protocol.py decode 15081 .\samples\04-c2s-15081.body.bin
python .\protocol.py decode 24113 .\samples\05-s2c-24113.body.bin --output .\samples\LUY2YJP-decoded.json
python .\protocol.py decode 24113 .\samples\05-s2c-24113.body.bin --output .\decoded.json --trace .\fields.json
python .\build_details.py
python .\verify.py
```

这里的 encode 只生成明文包体和记录头，不建立游戏登录会话、不实现传输加密，也不会单独向服务器发送请求。

原接收器的 `*-c2s-15081.bin` 和 `*-s2c-24113.bin` 含多条串接的 7 字节头记录，使用 `protocol.py decode-stream 文件绝对路径 --output 输出.json`。`decode` 子命令接收的则是独立 `.body.bin`，不含头。

## 压缩包的用法与本次改动

原 ZIP 保持不变，解包在 `original/arm64-socket/`。它的工作方式是：电脑 Python TCP 接收器 → ADB reverse → 游戏内 Frida JS 编解码 Hook。电脑接收到 `capturing` 只代表 Hook 已安装，收到 frames 并确认 flush 才表示已有实际样本。

原脚本只采集 12 个指定消息，不含这次所需的资料请求和返回。本次 `capture/` 使用已修复的本机工作副本作为基础，改为**只采集 15081 和 24113**，单独用 28470 端口和独立随机 token。保留了进程名 NUL 字节读取修复和函数字节／虚表检查。

如果再次采集，在本工作目录依次运行：

```powershell
adb -s PJ696HEY9DNRLFFQ forward tcp:37043 tcp:27042
adb -s PJ696HEY9DNRLFFQ reverse tcp:28470 tcp:28470
Remove-Item -LiteralPath .\capture\STOP -ErrorAction SilentlyContinue
.\capture\start-receiver.ps1
$gamePid = (& adb -s PJ696HEY9DNRLFFQ shell pidof com.tencent.tmgp.supercell.brawlstars).Trim()
& 'F:\frida16\Scripts\python.exe' -u .\capture\attach_capture.py --pid $gamePid
```

以上连接依赖手机上运行的 Frida 16.7.19 服务。本次用的是 `/data/local/tmp/frida-server-16.7.19-android-arm64 -D`，没有关闭 SELinux。电脑使用独立的 37043 转发到手机 27042，避免 USB 自动探测改写同名端口映射。

保持采集进程运行；在手机打开玩家资料。另一窗口可运行 `python .\capture\receiver.py --status`。停止时先创建 `capture/STOP`，等采集进程退出，再 `python .\capture\receiver.py --stop`。

## 让游戏页面显示指定标签

```powershell
$gamePid = (& adb -s PJ696HEY9DNRLFFQ shell pidof com.tencent.tmgp.supercell.brawlstars).Trim()
& 'F:\frida16\Scripts\python.exe' -u .\show_profile.py LUY2YJP --pid $gamePid
```

出现 READY 后，在 45 秒内点击任意好友的“玩家信息”。脚本只修改这一次资料页新建、由该页面拥有的 LogicLong 值，让页面目标和出站查询目标保持一致；完成后自动撤销 Hook。它不发送好友邀请，也不循环查询。仅适配上述国服版本和已核实的资料页构造函数。

之前只改变出站请求时，页面仍等待原玩家 ID，因而无法显示新玩家；现在 `show_profile.py` 已解决这一点，并实机显示了 #LUY2YJP。

## IDA 证据与文件

| 用途 | libg.so 相对地址 |
|---|---|
| 资料页创建请求 | 0xC32850，调用点 0xC329FC |
| 查询请求构造 | 0x18D17F4 |
| 查询请求虚表 | 0x1D80ED8 |
| 请求 getMessageType，返回 15081 | 0x18D1B60 |
| 请求 encode | 0x18D1974 |
| LogicLong 固定大端写入 | 0x897848 → ByteStream 0x912868 / 0x9120D8 |
| 返回虚表 | 0x1D81358 |
| 返回 getMessageType，返回 24113 | 0x18EB094 |
| 返回 decode | 0x18EAFE8 |
| PlayerProfile decode | 0x18EA8D4 |
| 英雄条目 decode | 0x18D28E0 |
| 玩家展示数据 decode | 0x18BAF64 |
| 战队头 decode | 0x18ABE54 |

`ida-evidence.json` 保存了主要反编译结果。旧版 BinDiff 的类名匹配存在误配，本次使用调用链、虚表、原始指令、实机明文和页面共同确认。

参考来源：https://github.com/athemm/brawl-proxy/blob/main/packets.json ，下载副本在 `reference/packets.json`。该文件提供消息编号名称映射，不提供本版本字段结构。

原采集最终收集 9 帧，接收端确认落盘 9 帧，采集器错误数 0；该会话的临时 Hook 和接收器已停止，结束时手机保留 #LUY2YJP 的资料页。后续整理读取已保存抓包，并只读核对当前设备上三个可选结构代码范围共 1524 字节，与运行时代码副本一致；没有再次触发查询、操作界面、安装 Hook 或写目标内存。

随后按用户要求重新开启独立的 28471 接收会话，实际查询 #88GLGUC2、最新队友与对手，新增 14 帧（7 请求 / 7 返回），全部确认落盘且错误数为 0；这次的采集和观察 Hook 也已停止。详情与时间在补测目录。特殊 viewKind=7 页面会把 high 加 100 后显示标签，包内 ID 保持原值，见补测报告与标签转换说明。
