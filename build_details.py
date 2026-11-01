"""Regenerate byte-level evidence tables from the original nine packet samples."""
from pathlib import Path
from datetime import datetime,timedelta,timezone
import csv,hashlib,json
from protocol import decode_request,decode_response,frame

ROOT=Path(__file__).resolve().parent
DETAILS=ROOT/'details'
DETAILS.mkdir(exist_ok=True)
def save_json(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def cell(value):
    text=json.dumps(value,ensure_ascii=False) if not isinstance(value,str) else value
    return text.replace('|','\\|').replace('\n','\\n').replace('\r','\\r')
def table(rows):
    lines=['| 包体偏移 | 字节数 | 位 | 字段 | 编码 | 原始十六进制 | 解码值 |',
           '|---:|---:|---:|---|---|---|---|']
    for r in rows:
        lines.append(f"| {r['offset']} / 0x{r['offset']:X} | {r['length']} | {r.get('bit','—')} | `{r['path']}` | {r['encoding']} | `{r['hex']}` | {cell(r['value'])} |")
    return '\n'.join(lines)

index=[];traces={};decoded={}
for path in sorted((ROOT/'samples').glob('[0-9][0-9]-*.json')):
    record=json.loads(path.read_text(encoding='utf-8'));body=bytes.fromhex(record['bodyHex'])
    stem=path.stem;fields=[];spans=[]
    value=(decode_request if record['id']==15081 else decode_response)(body,fields,spans)
    covered=set()
    for f in fields:covered.update(range(f['offset'],f['end_offset']))
    if covered!=set(range(len(body))):raise AssertionError(f'Byte coverage mismatch for {stem}')
    save_json(DETAILS/f'{stem}-decoded.json',value)
    save_json(DETAILS/f'{stem}-fields.json',{'body_length':len(body),'offset_base':'message body, zero-based','fields':fields,'spans':spans})
    with (DETAILS/f'{stem}-fields.csv').open('w',encoding='utf-8-sig',newline='') as handle:
        writer=csv.DictWriter(handle,fieldnames=['path','encoding','offset','end_offset','length','bit','hex','value'])
        writer.writeheader()
        for f in fields:writer.writerow({**f,'value':json.dumps(f['value'],ensure_ascii=False)})
    (DETAILS/f'{stem}-fields.md').write_text(f'# {stem} 逐字段明文对照\n\n所有偏移从包体第一个字节开始，以 0 为起点。Bool 可能共享同一字节，bit 按低位起算；重复偏移不是重复读取字节。\n\n{table(fields)}\n',encoding='utf-8')
    (DETAILS/f'{stem}.frame.bin').write_bytes(frame(record['id'],body,record['version']))
    local=datetime.fromisoformat(record['time'].replace('Z','+00:00')).astimezone(timezone(timedelta(hours=8)))
    tag=value['tag'] if record['id']==15081 else value['profile']['tag']
    row={'sequence':record['sequence'],'id':record['id'],'direction':record['direction'],
         'tag':tag,'time_china':local.isoformat(timespec='milliseconds'),'length':len(body),'version':record['version'],
         'body_sha256':hashlib.sha256(body).hexdigest(),'field_reads':len(fields),'byte_coverage':len(covered),'source':str(path.relative_to(ROOT))}
    index.append(row);traces[record['sequence']]=fields;decoded[record['sequence']]=value
save_json(DETAILS/'capture-index.json',index)

rows=['# 抓包细节与字段结构\n',
'适配：国服 Android 69.114.1，ARM64。下文基于 2026-10-31 已保存的实机采集、IDA 分析和运行时代码。后续只读核对了手机上的可选结构函数，没有重新触发查询或操作界面。\n',
'**新增实机补测：** [88GLGUC2、队友与对手的补测结果](validation-88GLGUC2/补测结果.md) 追加 14 帧；[2026-11-01 新战绩补测](validation-real-20261101/补测结果.md) 再追加 10 帧，其中 optional_long_104 两次非空，已按实际出站字节验证。累计 33 帧；下文时间线和字节表仍对应原始 9 帧样本。\n',
'## 结论与证据范围\n',
'通过玩家标签查询资料的普通请求为 **15081 / version 0 / 11 字节包体**，返回为 **24113 / version 0**。5 个请求与 4 个返回均可从原始 JSONL、分方向 BIN 和独立样本三方核对。两个不同玩家的返回均解析到包尾，逐字节对照覆盖 100%。\n',
'`#LUY2YJP` = high 108 / low 202449，玩家“胡须局锦绣谷”，页面奖杯 54278、英雄 107；`#2V9UJL9QR` = high 103 / low 11232845，玩家“🌧️清雨QINGYU💫”，页面奖杯 99116、英雄 107。`#2PP` 仅记录到请求，没有对应资料返回；不能据此断言账号不存在。\n',
'## 原始采集时间线（北京时间）\n',
'| 序号 | 时间 | 方向 | 消息 | 包体字节 | 标签 |\n|---:|---|---|---:|---:|---|']
for r in index:rows.append(f"| {r['sequence']} | {r['time_china'][11:23]} | {r['direction']} | {r['id']} | {r['length']} | {r['tag']} |")
rows+=['\n同一资料查询的四组相邻记录间隔约 151ms、412ms、105ms、124ms；这是 Hook 处观察到的端到端间隔，不能当作纯网络 RTT。第 3 条没有观察到对应返回。重复的三次 LUY2YJP 返回不代表三个不同玩家。\n',
'## 15081 普通查询：11 字节全量解释\n',table(traces[4]),
'\n这里 high/low 各为固定 4 字节大端整数。完整明文记录头和包体为：\n\n```text\n3a e9 | 00 00 0b | 00 00 | 00 00 00 00 00 6c 00 03 16 d1 00\n ID      长度      版本                    包体\n```\n',
'7 字节头由接收端按逻辑消息重建，原始 TCP 中的加密流量没有被本次采集器保留。不能把这段明文直接当作一个独立登录客户端的发送实现。\n',
'## 24113 返回：LUY2YJP 的实际布局\n',
'所有偏移从明文包体首字节起算。DataReference 是 table VInt；table 非 0 才继续读 instance VInt。String 是有符号 Int32BE 的 UTF-8 字节数加内容，-1 为空指针。\n',
'| 包体字节范围（含两端） | 内容 |\n|---|---|',
'| 0–4 | high/low 两个 VInt：108 / 202449 |',
'| 5–8 | 两个 DataReference |',
'| 9–10 | 英雄条目数量 VInt：107 |',
'| 11–2847 | 107 个英雄条目，含位打包 Bool 与可选引用／数组 |',
'| 2848–2925 | 统计数组：数量 27，加 27 对 key/value VInt |',
'| 2926–3002 | PlayerDisplayData（含昵称） |',
'| 3003–3092 | PlayerProfile 的其他资料、引用、可选集合与两个尾部字符串 |',
'| 3093 | 战队头存在标记，bit 0 = true |',
'| 3094–3162 | 战队头（ID、名称、徽章引用、其他字段） |',
'| 3163–3164 | 战队角色 DataReference；由资料页 clan_role_txt 调用链确认用途 |',
'| 3165 | 尾部 VInt，值为 0，业务含义待定 |',
'\n上表的绝对偏移只适用于这一个 3166 字节样本；换玩家、英雄数量、引用或昵称长度都会移动偏移。解析必须按顺序读取，不能固定跳转到昵称或奖杯的偏移。\n',
'### 关键值的原始字节\n']
wanted={'profile.player_id.high','profile.player_id.low','profile.heroes.count','profile.stats.count','profile.stats[2].key','profile.stats[2].value','profile.display.name','has_alliance','alliance.id.high','alliance.id.low','alliance.name','data_160.table','data_160.instance','int_168'}
rows.append(table([f for f in traces[5] if f['path'] in wanted]))
rows+=['\n昵称的长度头 `00000012` 表示 18 个 UTF-8 字节，6 个汉字；String 总长度是 4+18=22 字节。返回 high `ac01`、low `91db18` 是 VInt，不能按请求的 UInt32BE 解码。\n',
'### 第一条英雄记录的全部字段\n',table([f for f in traces[5] if f['path'].startswith('profile.heroes[0].')]),
'\n如 `int_28`、`data_40` 的数字是**原生对象内存偏移（十进制）**，保留作稳定定位标签；它们不是网络包偏移。未取得业务语义证据的字段没有擅自命名。\n',
'### 两个玩家的统计键值对\n',
'| key | LUY2YJP | 清雨 | 语义证据 |\n|---:|---:|---:|---|']
a={r['key']:r['value'] for r in decoded[5]['profile']['stats']};b={r['key']:r['value'] for r in decoded[2]['profile']['stats']}
for key in a:
    meaning={3:'与页面当前奖杯一致',4:'最高奖杯；新增余念安 93313/93329 样本和原生 UI 消费点确认',5:'与英雄数量及页面 107 一致'}.get(key,'未命名，保留 key')
    rows.append(f'| {key} | {a[key]} | {b.get(key,"—")} | {meaning} |')
rows+=['\n## 请求的两个可选分支\n',
'完整读取顺序：`has_context12:Bool` → 可选 12×VInt → 查询参数 VInt → high UInt32BE → low UInt32BE → `has_battle_log:Bool` → 可选 BattleLogPlayerEntry。\n',
'本次补全了 BattleLogPlayerEntry 类子结构的编解码：VInt、LogicLong、VInt、Bool、成员数组（每项 DataReference+3×VInt）、VInt、PlayerDisplayData、可选 LogicLong、3×DataReference、VInt 数组。精确顺序见 protocol.py 的 battle_log/write_battle_log。证据为 native-optional-context.asm 的原生读取函数 0x18BDD9C 和写入函数 0x18BE0B0；额外 12 个 VInt 的读取在 0x18BE810。原始文件中的这些范围与运行时代码不同，不能把原文件的未识别区域硬当明文指令。本次已从当前手机只读核对三个范围共 1524 字节，与已有运行时代码副本完全一致，见 live-optional-context.json 和 native-optional-context-provenance.json；没有为此安装 Hook、调用游戏函数或写目标内存。\n',
'**两次补测已真实触发这两个分支各五次。** validation-88GLGUC2 的 88 / 100 字节请求及 validation-real-20261101 的 100 / 120 / 100 字节请求均完整解码并逐字节重编码一致。后者请求 7 / 9 的 optional_long_104 非空，分别为 high=103 / low=167892、high=111 / low=577840，已验证两个 UInt32BE 和后续字段边界。该 LogicLong、部分其他字段及返回尾部 VInt 的业务含义尚未确认。VInt 查询参数在扩展样本中等于条目成员英雄奖杯之和，不应再把 source 当作已确认来源枚举。\n',
'## Hook 采集在哪里、怎样判断可信\n',
'请求在 libg.so+0x18D1974 的 encode 返回后复制明文，返回在 +0x18EAFE8 的 decode 进入前复制明文。发送方向：保存 args[0]，onLeave 读取编码后的 ByteStream；接收方向：onEnter 读取尚未被解码消耗的 ByteStream。没有把密文套用明文解析器。\n',
'Message 对象的 ByteStream 位于 +8；在 Stream 内，+20 是编码长度／读取游标，+24 是接收体长度，+40 是容量，+56 是数据指针。Message+136 是消息版本。发送读取 +20，接收读取 +24 且要求游标 +20 为 0。每条消息校验虚表、数据可读范围、长度不超过容量和 4 MiB 上限。\n',
'请求虚表 +0x1D80ED8 的 type 函数 +0x18D1B60 返回 15081；返回虚表 +0x1D81358 的 type 函数 +0x18EB094 返回 24113。安装前检查 Hook 函数指纹、type 指纹、虚表槽和可执行权限。代理不在手机上重算完整库 SHA256；完整哈希是离线库身份记录，不能说每次安装都验过整库。\n',
'手机 Socket → ADB reverse tcp:28470 → 电脑 127.0.0.1:28470 接收器。配套随机 token 验证成功后才安装 Hook；BIN 与 JSONL 都成功写入并 flush 后 ACK。最后 stop 记录为 frames=9、sentFrames=9、receiverFlushedFrames=9、errors=0；summary.closed=true。flush 说明程序完成刷新，不等同断电持久性证明。\n',
'## 手机页面此前为什么等待\n',
'只更改请求构造函数的目标 ID，会使资料页仍拿原玩家 ID 校验返回，因此即使收到了新玩家的 24113，也不会展示。现在 show_profile.py 在整个资料页构造时修改其新建、由页面拥有的 LogicLong 数值，使请求与页面目标一致；不替换内存分配器、不循环查询。最后两次对应样本 6–9，已经显示 LUY2YJP 页面。\n',
'## 文件与复现\n',
'- capture-index.json：9 帧序号、北京时间、包长、标签及包体 SHA256。\n- *-fields.json / .csv / .md：每帧全部原子字段的路径、偏移、长度、Bool 位、原始字节及值。\n- *-decoded.json：完整解码树。\n- *.frame.bin：7 字节头加包体重建记录；原始分方向串接 BIN 仍在 capture/captures。\n- verification.json：从原采集日志、BIN、独立样本和字段解析复核的结果。\n',
'```powershell\n# 以下命令在工作目录运行\npython .\\build_details.py\npython .\\verify.py\npython .\\protocol.py decode 24113 .\\samples\\05-s2c-24113.body.bin --output .\\decoded.json --trace .\\fields.json\n# 原接收端 BIN 是多条消息串接，使用 decode-stream，不要直接当作单个包体\npython .\\protocol.py decode-stream "原接收端生成的-s2c-24113.bin绝对路径" --output .\\stream-decoded.json\n```\n']
(ROOT/'抓包细节.md').write_text('\n'.join(rows),encoding='utf-8')
print(json.dumps({'frames':len(index),'output':str(ROOT/'抓包细节.md'),'field_reads_LUY2YJP':len(traces[5]),'all_bytes_covered':True}))
