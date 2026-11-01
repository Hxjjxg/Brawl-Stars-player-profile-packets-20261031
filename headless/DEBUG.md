# 独立查询调查

## Observations

- 已验证的 15081 普通包体为 11 字节，24113 可完整解析；现有代码没有登录握手或传输加密实现。
- 客户端进程仍为 3705，libg.so 基址 0x7c854de000。
- 原生 sendto 调用点 0xB16C20，recvfrom 调用点 0xB14D44。实际心跳 10108 的包体长度为 16，7 字节头可直接识别；符合带认证标签的加密封装形状，但算法仍待核实。
- 运行时代码含 `expand 32-byte k` 常量，尚不能单凭常量确定协议算法。
- 第一次被动观察脚本遇到 `script has been destroyed`，期间 USB transport_id 从 5 变为 6；PID 不变。没有抓到资料请求调用栈，不能据此认定资料查询未发送。

## Hypotheses

### H1: USB/Frida transport was disconnected during the observation (primary)
- Supports: ADB transport ID changed, Frida script was destroyed, game PID stayed unchanged.
- Conflicts: no detach-reason event was recorded by the first probe.
- Test: record Frida detach reasons and keep the next capture short, then trigger one profile query immediately.

### H2: The game restarted or replaced libg.so
- Supports: destroyed scripts can accompany process exit.
- Conflicts: PID remained 3705 and the UI stayed in the same battle log.
- Test: compare PID and module identity on reattach; do not assume old pointers survive.

### H3: UI cache or request scheduling avoided the observed encoder
- Supports: the same teammate had previously been opened.
- Conflicts: the displayed trophy count changed, consistent with new data.
- Test: open a different profile after a verified fresh probe is ready; compare encoder and network events together.

## Experiments

1. Initial passive sendto/recvfrom metadata probe: observed readable message IDs and encrypted body lengths; profile observation inconclusive because the script was destroyed.
2. Longer capture observed native 15081 encode and its encrypted sendto record. A later deliberate shutdown of the idle game socket returned 0; clicking the observed reconnect button produced a complete 10100 / 20100 / 10101 / 20104 exchange without restarting the process.
3. Captured secretbox inputs do not reproduce with standard PyNaCl SecretBox. Runtime disassembly confirms `mov w15, #0x13` at 0xAD3EFC: this client's Salsa/HSalsa core performs 19 single rounds, rather than the usual 20. Both its stream generator and key derivation call this core. This is direct code evidence for a custom-round hypothesis; next experiment is byte-for-byte reproduction using 19 rounds, with captured private material remaining ignored.

### Crypto mismatch hypotheses

- C1 (primary): custom 19-round Salsa core changes both HSalsa subkeys and stream blocks. Supports: runtime instruction and decompiler agree; standard SecretBox fails. Test: compare a 19-round implementation with captured plaintext, nonce, key and ciphertext.
- C2: nonce snapshot is before the increment. Supports: nonce is incremented in the caller. Conflicts: hook is inside the called wrapper after the increment; copied snapshots are immutable strings. Test only if C1 fails: compare adjacent nonce counters.
- C3: ABI argument indices are wrong. Supports: stripped binaries can have misleading types. Conflicts: runtime instructions explicitly preserve x4/x5 and forward them as nonce/key, and observed lengths/overhead are sensible. Test: compare wrapper output to actual wire payload, then hook the inner primitive if needed.

### Crypto conclusion

19-round Python secretbox reproduced all 63 inputs in the first comparison. Six additional vectors with fixed, non-secret key/nonce and lengths 0/1/11/32/65/128 were evaluated directly by the live native primitive and also matched exactly. Login 10101 authenticates and decrypts using X25519 + HSalsa19, with Blake2b-24(clientPublic || serverPublic) as nonce. Login response 20104 authenticates with Blake2b-24(clientNonce || clientPublic || serverPublic); its plaintext starts with a 24-byte receive nonce and 32-byte session key. All 40 subsequent receive records in the captured snapshot authenticate, and the 24113 body parses completely.

## Standalone TCP attempt

The game was stopped after hooks were detached. First standalone attempt to the observed live endpoint 52.83.179.16:9339 was reset after sending the captured 76-byte 10100 hello. A diagnostic retry confirms no 20100 header was received. This failure precedes login token, public-key exchange and profile requests; crypto or profile encoding cannot yet explain it.

### N1: Network path or source-address policy rejects the PC connection (primary)
- Supports: immediate reset before any server hello; phone connection to this endpoint was established successfully.
- Conflicts: TCP connect succeeds.
- Test: connect and wait briefly without transmitting, then compare reset timing; inspect local proxy/routing without changing global settings.

### N2: Captured hello includes a connection-bound or time-bound field
- Supports: opaque hello is being reused.
- Conflicts: ordinary game hellos usually contain protocol/build identifiers; contents have not been decoded yet.
- Test: decode hello fields and compare native encoder; do not change fields speculatively.

### N3: Captured endpoint is not a stable public entry point
- Supports: the game endpoint changed across its reconnect; hostname-based routing may use other entry addresses.
- Conflicts: the observed IP:port was the exact active game socket.
- Test: inspect configured game host strings and DNS, then compare only verified alternative endpoints.

### Network conclusion and live result

Phone packet capture contains no extra preamble: the exact 83-byte Hello matches Python byte-for-byte and gets a 20100 response. An independent Android netcat process also gets 20100. PC is on WLAN/campus routing, while phone uses cellular. The user's existing system HTTP proxy routes Chinese destinations directly; a separate temporary proxy using its configured upstream also returned EOF. Its process was stopped and its temporary credential copy removed without modifying the existing proxy.

Through an optional loopback-only phone TCP relay, with the game force-stopped, standalone Python successfully performed fresh logins and queried #LUY2YJP and #88GLGUC2. This proves game/session independence, but successful phone-free PC transport on the current network has not been established. Direct TCP and HTTP CONNECT remain selectable transports.

## Multiple queries in one session

An additional API test got the first profile, then timed out waiting for the second, requested 0.5 seconds later. Separate fresh CLI sessions had both worked. No multi-query success is claimed yet.

- M1: the server applies a short per-session profile-query cooldown. Supports: second immediate request fails while independent logins work; natural UI actions are slower. Test: change only inter-query delay from 0.5 to 2 seconds.
- M2: idle sessions need heartbeats or a turn flush. Supports: normal game sends periodic heartbeats; current code sends one only after receiving other records. Conflicts: the first query succeeded before a heartbeat. Test if M1 fails: add one heartbeat before the next query, leaving delay unchanged.
- M3: a different tag response was received and filtered. Supports: the client waits for an exact target ID. Conflicts: both tested tags already worked in fresh sessions. Test: retain returned public profile tags alongside message metadata.

### Multi-query conclusion

Changing only the inter-query wait to 2 seconds made all three requests succeed in one new login, while the game stayed stopped. The client now conservatively waits 2 seconds after the previous successful profile response before sending another query. The exact server threshold and policy are not claimed. A regression test checks this wait; the live verification then removes its external sleep to test the client's own pacing.

## User-requested PC proxy 10809 test — 2026-11-01 17:39–17:44 China time

Observed: 10809 is a listening Xray mixed inbound. An actual HTTP-CONNECT Client login attempt sent only 10100 and got EOF, with no received game records. SOCKS5 negotiation returned 0500 and CONNECT succeeded for both the domain and each of the three previously verified production IPs, but all game Hello probes then got EOF. HTTPS through the same port works; its Cloudflare control reported loc=JP.

Hypotheses and experiments:

- P1: Chinese-target direct routing still selects the campus network. Supports: current configuration has geoip:cn/geosite:cn direct rules. Test: a separate loopback-only instance using the configured proxy outbound, allowing only the game domain/IPs and port. Result: also EOF after Hello; changing only this route is not a sufficient repair. The temporary process/config were removed and original config bytes verified unchanged.
- P2: proxy-side DNS selects a different server. Supports: the domain is resolved by the proxy. Test: SOCKS CONNECT to all three verified numeric IPs. Result: same EOF; DNS alone does not explain the failure.
- P3: the upstream/exit path or game endpoint rejects this connection. Supports: proxy negotiation and ordinary HTTPS succeed, game traffic fails before 20100 even with forced proxy routing. Conflicts: exact rejection origin is not observable in this test. Conclusion: this remains the network boundary; no unproven crypto/token fix was made.

All observations were recorded without using a phone. No 10101/token was sent. Detailed results: validation/pc10809-20261101T093941Z/测试结果.md.

## Scope

Target is a standalone Python client, with reuse of the user's own login token if necessary. A phone-backed bridge would not meet the preferred outcome. Any recovered session credentials must stay under ignored `headless/private/` and must not be printed or committed.
