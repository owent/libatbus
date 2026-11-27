# AUDP v1 连接层设计

AUDP 通过 `audp://host:port` 传输完整的 libatbus 消息。默认可靠、有序，FEC 比例为 1/8。实现只使用项目已有的 libuv、atframe_utils 和 protobuf。新增代码集中在私有 UDP 通道。握手直接使用 ATCP 的节点注册请求、响应和确认。一个 UDP socket 可同时承载多条连接。建连后只有 DATA、ACK、FEC、PROBE 四种包。

## 复用边界

发送路径为 `message_handler::send_message → connection_context::pack_message → AUDP 分片 → 逐包 AEAD → uv_udp_send`。接收路径为 `UDP → 逐包验真 → 重组 → connection::unpack → node::on_receive_message`。重传引用已编码块的字节范围。小消息一次编码、一次加密，大消息只压缩一次。

共用块仍是 `vint(head_size) | message_head | encoded_body | 算法填充`。长度取 `static_buffer_block::used()`。TCP 的 4 B MurmurHash 和块长 vint 是 `io_stream_send()` 在此后加入的流分帧，留在 ATCP 入口。AUDP 复用注册过程的 ECDH、压缩协商和消息编解码，协商所得的加密能力供包层使用。包级加解密直接使用同一套 `crypto::cipher` 原语。ATCP 的线格式、算法选择和老端互通路径均不需要变动。[消息发送](../src/atbus_message_handler.cpp) · [块编解码](../src/atbus_connection_context.cpp) · [TCP 分帧](../src/channel_io_stream.cpp) · [连接接收](../src/atbus_connection.cpp)

## 一个 UDP 通道，多条连接

一个 `audp_channel` 拥有一个绑定好的 `uv_udp_t` 和一张 `local_cid → connection` 表，收包、拨号都复用这个 socket。同一对本地和远端 IP、端口也可以同时建立多条连接。每条连接的客户端、服务端分别选择一个在本通道内唯一的非零 128 位 CID，以下简称 C、S。发包填写对端分配的 **目的 CID（DCID）**。查表范围是当前通道，源地址用于核对路径。v1 固定路径，地址变化时重新注册。

CID 在线上固定为 16 字节，原样收发和比较。默认用已有密码学随机源生成，也可使用 UUID 或其他算法生成的非零 16 字节值。全零保留给 INIT 的 DCID。通道表可用 `std::array<uint8_t, 16>` 作键，哈希覆盖全部字节，命中后按完整键判等。接收端无需识别生成算法。

使用 UUID 时按 RFC 9562 的网络字节序编码。例如 `00112233-4455-4677-8899-aabbccddeeff` 对应 `00 11 22 33 44 55 46 77 88 99 aa bb cc dd ee ff`。从 Windows GUID 转换时，前三个整数字段按大端写入，其余 8 字节按原序复制。[RFC 9562 §4](https://www.rfc-editor.org/rfc/rfc9562.html#section-4)

| 同一对 UDP 地址上的连接 | 客户端 → 服务端 | 服务端 → 客户端 |
| --- | --- | --- |
| 连接 A，各端的本地编号为 C1、S1 | DCID=S1 | DCID=C1 |
| 连接 B，各端的本地编号为 C2、S2 | DCID=S2 | DCID=C2 |

CID 标识一条传输连接，bus ID 标识 endpoint，PN 标识该连接一个方向上的一次发送。同一 bus ID 可以绑定多条 connection。每条连接独立持有密钥、PN/ACK、业务窗口、重组及 FEC 状态。路径的拥塞预算和 pacer 在相同本地/远端路径上共享，避免并开连接成倍放大发送速率。ACK 和丢失判断仍按所属连接记账。[现有 endpoint 连接集合](../src/atbus_endpoint.cpp)

分配 CID 时检查活动、半连接和短期保留表。碰撞就重新选择，不能覆盖已有项。相反方向同时拨号也分别建表。关闭单条连接只删除其映射、撤销其定时任务并回收其预算，其他连接及 socket 继续工作。通道关闭时才整体释放。过期 CID、未知 DCID、来源路径不符的常态包静默丢弃，不能据此创建会话。重连使用新 CID 和临时密钥。异步回调持有连接引用或 generation，防止串到后来的连接。

## 复用 ATCP 注册握手

**两种传输采用同一组三条消息**。客户端发送带 `access_data`、ECDH 公钥及压缩能力的 `node_register_req`，服务端返回 `node_register_rsp`，客户端用 `handshake_confirm` 确认相应的 `crypto_handshake_data.sequence`。沿用现有 protobuf 字段、公钥表示、access token 签名和完整消息块编码。三条消息无需增加 AUDP 字段。UDP 地址验证和包级保护由下面的外层负责。[注册协议定义](../include/libatbus_protocol.proto) · [消息构造、验签和注册](../src/atbus_message_handler.cpp) · [ECDH 与 HKDF](../src/atbus_connection_context.cpp)

```text
客户端（本地 CID=C）                                   服务端（本地 CID=S）
INIT              DCID=0, SCID=C  ──────────────────►  仅生成地址 cookie
RETRY             DCID=C, SCID=S  ◄──────────────────  返回 cookie
注册 DATA         DCID=S, SCID=C  ──────────────────►  node_register_req
注册 DATA         DCID=C, SCID=S  ◄──────────────────  node_register_rsp
会话 DATA         DCID=S          ──────────────────►  handshake_confirm
会话 ACK          DCID=C          ◄──────────────────  确认 confirm 已处理
```

### 地址验证和注册封装

长头使用 ASCII `ATBUSUDP`（8 B，无 NUL），整数字段使用网络字节序。只有发起连接的 INIT 可以使用全零 DCID。接收端先核对 magic、版本、类型和长度。客户端按 pending local CID 和预期对端匹配 RETRY，接受一次后固定 S 与 cookie。源 CID（SCID）仅在长头出现。

```text
long   = magic[8] | version:u8=1 | type:u8 | DCID[16] | SCID[16]
INIT   = long(type=0x80) | key_id:u32 | padding[12]
RETRY  = long(type=0x81) | cookie[16]
注册包 = long(type=0x01 DATA 或 0x02 ACK) | key_id:u32 | cookie[16] | PN:u32
       | AEAD(body) | tag[16]
```

1. INIT 和 RETRY 各 58 B。服务端按本地 CID 生成规则选 S，使用本地短期密钥计算截断至 16 B 的 HMAC-SHA256 cookie，覆盖版本、监听器标识、源 IP/端口、C、S、key ID 和短时桶。服务端在收到首个注册 DATA 前不分配连接。只有带有效 cookie 和有效 tag 的客户端注册 DATA 可新建半连接；未知 CID 上的注册 ACK 同样丢弃。cookie 验证当前/上一桶，恒定时间比较。地址验证、半连接数和尝试速率均设上限。
2. 注册包复用 DATA 的控制 MID、分片重组和 ACK 实现。两端注册块为 `settings[17] | pack_message(node_register_req/rsp)`，交付通用解包前剥去 settings。settings 按顺序为 `flags:u8 | max_udp:u16 | max_block:u32 | rx_bytes:u32 | rx_mids:u16 | idle_s:u32`，位 0 为 reliable，位 1 为 allow_out_of_order。模式须一致，且 `1200 <= max_udp <= 8972`、`0 < max_block <= rx_bytes`，rx_mids 和 idle_s 非零。注册阶段以 1200 B UDP 负载预算切片，固定预留一个最多 64 KiB 的控制块（含 settings），登记超限直接返回长度错误。始终可靠有序、禁用 FEC 与压缩。大注册表可跨包，丢失只需补缺片。
3. 注册开始时已有部署配置的高熵 access token。key ID 在本地选择稳定配置项。沿用已有 HKDF-SHA256 和 AES-256-GCM，按方向派生临时注册包密钥：salt 为 cookie，输入为选定 token，info 为 ASCII `atbus/audp/1/reg/c2s` 或 `atbus/audp/1/reg/s2c` 后依次拼接 C、S 各自的 16 个原始字节和大端 key ID，输出 32 B。长头至 PN 的原始字节全部作为 AAD。接收端先校验 cookie 和首片的 AEAD，再原子插入半连接并分配重组内存。启动时要求所选凭据为至少 32 B 的随机 token。此保护使未完成 ECDH 的分片也可先验真，注册中的地址和标签在线上保持加密。
4. 重发 INIT 不得替换已选的 CID。重复的首片按原连接处理，重复的注册块只触发原有确认或缓存响应。每个被使用的 cookie/CID 对在其有效期内只创建一次注册密钥和 PN 空间，失败或关闭后保留已用记录至 cookie 失效。已建立的 CID 不能重新进入注册。如果无状态选择的 S 恰与另一会话冲突，服务端丢弃此次申请，客户端在拨号超时后以新 C 重试。正在使用的 CID 映射保持原值。重启重新生成 cookie 密钥。这样即使首片被重复送达，也不会重新从 PN 0 使用同一把注册密钥。

### 注册确认与会话密钥

AUDP 复用 `send_register` 的构造、`check_access_hash` 的签名语义、`handshake_generate_self_key` 的临时密钥和 `handshake_read_peer_key` 中的公钥解析与共享秘密计算。v1 通过这组现有字段约束为 X25519、HKDF-SHA256 和 AES-256-GCM，校验所选算法、IV/tag 长度、非零序列及共享秘密。注册时核验 key ID 选中的同一份凭据对该消息的 access_data 签名，并检查其获准使用的 bus ID。不能把“配置中任一 token 匹配”的布尔结果当作该身份的授权，空 token 或空签名均拒绝。使用同一 token 的多个节点仅具有该组的身份粒度。

现有 `access_data` 签名覆盖身份、随机数和公钥摘要，其签名文本没有 CID 或传输参数。AUDP 在已有 ECDH 计算处增加私有的方向密钥派生分支。令 T 为 SHA256，按固定顺序输入 `magic | version | key_id | C[16] | S[16] | cookie | 长度:u32 | 请求原始注册块 | 长度:u32 | 响应原始注册块`，两个块均包含各自的 settings。对双方实际收发的字节取 hash，避免重序列化 protobuf。用 T 作 salt、ECDH 共享秘密作输入，HKDF 分别以 ASCII `atbus/audp/1/data/c2s`、`atbus/audp/1/data/s2c` 导出 32 B 会话密钥。服务端先暂存共享秘密，待响应编码完成即派生并清除。ATCP 继续走原有的 KEY/IV 派生分支。AUDP 将会话 cipher 安装在包层，消息层只保留编码与协商后的压缩。v1 到密钥使用期限时排空并重新注册，停用该连接的 ATCP 消息层定时换钥。

客户端验证成功响应、请求关联和协商结果后，用**会话密钥**发送已有 `handshake_confirm`（可靠控制 DATA）。服务端匹配 C/S、来源路径、阶段和 ECDH sequence，成功提交注册后才用会话密钥 ACK。客户端收到该 ACK 后提交并开放业务。注册长头和会话短头直接决定密钥与 PN/ACK 空间，长头 ACK 只能确认注册包。切换期间保留有界注册期账本以处理迟到包，不能重复提交或重置密钥。两方向都验证 1200 B 可达后开放常规 DATA。

当前 ATCP `on_recv_node_register_req/rsp` 会调用 `accept_node_registration`、更新拓扑并触发回调，`on_recv_handshake_confirm` 还检查已有 binding。实现应把已有注册处理拆为可复用的“校验/准备”和“提交”两个私有步骤。AUDP 在 pending connection 上保存结果，完成密钥确认后再绑定 endpoint、触发上线/注册事件，提交时重检节点冲突。重复 confirm 仅回 ACK。并发失败只清理本连接。ATCP 维持现有提交时机。握手阶段仅接受注册、确认以及为其服务的传输控制，自定义命令与用户转发在连接就绪后开放。

## 四种常态包

每个 UDP 数据报携带一个包。会话短头为 **21 B**，认证标签为 **16 B**。根据本通道的 DCID 索引找到连接，核对来源，再以整段短头作为 AEAD 的 AAD 验真。每组方向密钥的 PN 从 0 开始。nonce 为 `0x0000000000000000 | PN:u32be`。每次 AEAD 加密先消耗新 PN，包括副本、重传、ACK 和 PROBE，即使系统发送失败也不回收。接收端仅在认证成功后推进防重放窗口。每方向达到密钥使用期限或保守上限 2²³ 包前排空并重连，未排空须报告失败。

```text
+---------+----------+--------+----------------------+---------+
| kind 1B | DCID 16B | PN 4B  | 加密的 body          | tag 16B |
+---------+----------+--------+----------------------+---------+

01 DATA   = sid:u32 | symbol
02 ACK    = base_pn:u32 | received:u64 | data_retired:u32 | recovered_sid:u32
03 FEC    = first_sid:u32 | count:u8 | xor_symbols[剩余字节]
04 PROBE  = udp_size:u16 | zero_padding[剩余字节]

symbol    = mid:u32 | total:u32 | offset:u32 | len:u16 | bytes[len]
```

- **PN 标识物理发送，MID 标识完整消息，SID 标识参与 XOR 的原始分片。** MID 低 31 位在每方向从 1 连续递增，高位区分业务（0）和控制（1）。控制消息与业务共享格式、重组器和发送账本，独立编号。SID 从 1 连续分配，副本沿用原 SID。控制、重新切小的重传片及未参与 FEC 的数据可用 0。所有编号在溢出前结束会话。
- **ACK** 的位 i 表示 `base_pn - i` 真实收到，位 0 必须为 1，低于 0 的位置为零。迟到超过 63 个位置的包可以另发以该 PN 为 base 的 ACK。这个 64 位字段只限制一包覆盖范围。接收可靠片须先保留有效字节再 ACK，已确认的数据保留至交付或连接失败。纯 ACK 不触发 ACK。建议每收 2 个引发确认的包或最多等待 10 ms 发送一次 ACK，出现缺口、控制完成或收到 PROBE 时立即确认。
- **接收信用**直接搭载在 ACK 中。`data_retired` 是已连续交付并释放的业务 MID 前缀，初始为 0。发送方按 MID 顺序接纳整块，可靠模式只允许此前缀之后至多 `rx_mids` 条未退休消息，其 total 合计不超过 `rx_bytes`。例如 64 条小消息可共享一个字节预算，无须为每条预留最大消息。收到更新后释放相应信用，并停止这些 MID 的逻辑补发。这个反馈不能代替物理 PN 的 ACK 或 RTT 样本。旧值忽略，越过已发送范围的值拒绝。乱序交付的消息在此前缀追上时返还信用。信用更新丢失时，发送方可发小 PROBE 取得当前 ACK。非可靠业务使用本地有界队列和 TTL，整条丢失也不会卡住发包信用。
- 控制序列逐条发送，每方向独立预留一个最多 64 KiB 的控制块。注册期与会话期分开记可靠状态，confirm 使用会话期的首个控制 MID。发送端等当前块全部字节确认后才送下一条。接收端在最后一片触发控制状态处理成功后再确认，按消息类型、角色与当前注册阶段校验。注册期间禁用压缩，先校验有界消息头再进入通用解包。若首批业务早于 confirm 的 ACK 到达，已校验对端身份的客户端可在配额内暂存，待本地注册提交后再分发。注册后的包通过 AEAD 仅证明它属于该会话，节点授权和消息校验继续执行。主动关闭走本地断开及对端 idle 超时，v1 不承诺对端立即获知关闭。

## 投递与丢包恢复

| 模式 | 完整消息的交付条件 | 缺片处理 |
| --- | --- | --- |
| 可靠、有序（默认） | 所有前置 MID 已交付 | FEC 优先修复，仍未确认的范围选择重传 |
| 可靠、允许乱序 | 一旦完整立即交付一次 | 早先缺失的消息独立修复 |
| 非可靠、有序 | 前置 MID 已交付或已到期 | 保留主动冗余，超时跳过整段缺口，不补发 DATA |
| 非可靠、允许乱序 | 一旦完整立即交付一次 | 保留主动冗余，超时丢弃未完成消息，不补发 DATA |

非可靠重组时间建议从 250 ms 起配。首次见到残片或更高 MID 暴露一个缺口时，以本地单调时钟起算。重复包不续期。这样前一条消息连首片都没到也能释放后继。窗口内保留已交付及已过期位图，连续退休的前缀压成一个下界。迟到的原件、副本和修复包都不能触发二次分发。

可靠和非可靠共用按线上字节计的 NewReno 窗口、在途账本和 pacer。DATA、FEC、主动副本、重传和引发确认的控制包都占预算。ACK 只对实际物理 PN 更新 RTT 和拥塞状态。初始 RTT 可取 333 ms，初始窗口 `min(10D, max(2D, 14720))`。采用 3 个包或 `9/8 × max(latest_rtt, srtt)` 的丢失阈值，须先观察到更大的已确认 PN。没有新 ACK 时以 PTO 指数退避发探测。可靠模式才重排仍缺的字节范围，非可靠模式仅回收在途记账。为简化 ACK 不编码延迟，RTT 采样含接收端最多 10 ms 的合并等待。可靠数据长期没有进展时明确报错。仅收到保活响应不能延长可靠发送期限。[RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html)

### XOR 和冗余比例

比例 `r = n + f`。每个**首发**业务分片发送一个原件和 n 个副本，小数 f 按方向用定点数累计，满 1 发一份 XOR 并扣 1。副本、ACK、重传和修复包不参与累计。`1/8` 即 8 个原件加 1 个修复包，`1.25` 即 4 个原件加 4 个副本和 1 个修复包。1/8 是 AUDP 的缺省值，QUIC v1 没有规定 FEC 比例。[QUIC v1 帧定义](https://www.rfc-editor.org/rfc/rfc9000.html#section-19)

一组保护最多 64 个连续 SID，可跨业务消息。发送端将 **symbol 全部字段及内容**按最长源符号右侧补零后异或。FEC 声明首 SID 和成员数，DATA 无须携带组号或槽号。接收端短期保存最近的已认证源符号（或持有其不可变引用），收到 FEC 时按区间查找。parity 先到也可有界暂存。恰缺一个成员时恢复并重新校验 MID、total、offset 和 len，可在 ACK 的 `recovered_sid` 中报告该 SID，0 表示无报告。发送端按 SID 取消逻辑补发，原包的物理丢失仍计入拥塞。丢了两个成员时一份 XOR 无法恢复。

数据立即发，组满、路径尺寸变化或组龄到达约 10 ms 时封组。未满 1 的信用留给下一组，低流量残组可以没有 parity。关闭或变更 FEC 时封组，限制缓存组数、符号数和字节数。主动副本按 pacer 错开发送，非可靠 TTL 到期即撤销未发冗余。比例可大于 1，建议本地配置上限 4。

首版使用固定比例。可选自适应只改变本地发送策略，线格式不变。以首发 DATA 的物理丢失率做 EWMA，配合 FEC 修复数、残余重传、RTT 膨胀和冗余字节评估。多个 RTT 且有足够样本才调一档。出现拥塞先降速，持续随机丢包才增加冗余。实际默认档位以尾延迟和每个有效字节的传输成本决定。

## 路径 MTU 和报文预算

**AUDP 从 1200 B UDP 负载起步，公网默认按 1500 B IP MTU 封顶，两端按方向探测。** RFC 8200 要求每条 IPv6 链路向 IP 层提供至少 1280 B，底层单帧放不下时由链路层适配。2026 年的 RIPE Atlas 研究覆盖约 76,700 条 IPv4/IPv6 路径。在其 IPv6 样本中，1.5% 的 PMTU 恰为 1280 B，低于 1280 B 的三个结果均为 1232 B，来自同一个探针。对正常工作的 IPv6 路径，1280 B 是有规范和实测依据的基线。具体地址、UDP 端口和方向仍须用 AUDP 实包确认。若应用发送 1280 B UDP 负载，无扩展头的 IPv6 路径也至少需要 1328 B IP MTU。IPv4 也可能遇到小于该基线的路径，两方向不能确认 1200 B 时，v1 在期限内报告路径不可用。[RFC 8200 §5](https://www.rfc-editor.org/rfc/rfc8200.html#section-5) · [IMC 2026 测量论文 §5.2](https://repositum.tuwien.at/handle/20.500.12708/232108)

### 哪些头部占用 MTU

取 M 为承载 AUDP 的**内层 IP 包**可用的 MTU。若操作系统给出 PPP 或隧道接口的有效 IP MTU，直接用它。只有从物理链路或 underlay 反推 M 时，才减去相应的接入或外层隧道开销。令 E 为该内层 IP 包的 IPv4 options 或 IPv6 扩展头字节数，则 UDP 负载上限在 IPv4 为 `M − 20 − E − 8`，在 IPv6 为 `M − 40 − E − 8`。UDP 负载包含 AUDP 头和 tag。探测的尺寸已经是 UDP 负载，不能再扣一次 IP 或 UDP 头。[IPv4 首部](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1) · [IPv6 扩展头](https://www.rfc-editor.org/rfc/rfc8200.html#section-4) · [UDP 首部](https://www.rfc-editor.org/rfc/rfc768.html)

| 场景 | 应计入的字节与位置 |
| --- | --- |
| 以太网、VLAN 与 QinQ | IP MTU 1500 通常已经排除了 Ethernet 头和 FCS。一个 802.1Q 标签在线上占 4 B，两个占 8 B。能承载 1522/1526 B 帧（含 FCS）的链路仍能给 IP 留满 1500 B。若某段帧长硬限 1518 B，单标签/双标签才会把可用 IP MTU 降到 1496/1492 B。按实际帧长与接口 MTU 计算。 |
| PPPoE | 标准以太网负载 1500 B 中，PPPoE 头 6 B、PPP 协议字段 2 B，常规 IP MTU 为 1492 B。叠加一个 VLAN 且全程支持标签帧长时，仍为 1492 B。若协商 RFC 4638 且二层能承载额外 8 B，可保留 1500 B IP MTU。 |
| IP 选项与扩展头 | IPv4 基本头 20 B，选项及填充最多再占 40 B。IPv6 基本头 40 B，Hop-by-Hop 或 Destination Options 头各自至少 8 B，按实际链长度扣减。在 IPv6 最小 MTU 上，`1280 − 40 − 8 − 1200 = 32 B`，即基线已经留出 32 B 扩展空间。更长的扩展链需更大 M。 |
| VXLAN、VPN 和云网络 | 无内层 VLAN 的 VXLAN 在外层 IPv4/IPv6 上分别占用 underlay IP MTU 的 50/70 B，即外 IP 20/40、外 UDP 8、VXLAN 8、内 Ethernet 14。underlay 1500 时内 IP MTU 为 1450/1430 B。若 VXLAN 实际携带内 VLAN，再计其标签。IPsec 等 VPN 的变长开销采用隧道接口 MTU 或实际配置。Google Cloud VPC 的常规默认 IP MTU 为 1460 B。 |

上述算例以协议定义和设备可承载的帧长为依据。[VLAN 帧长](https://www.cisco.com/c/en/us/support/docs/lan-switching/8021q/17056-741-4.html) · [双标签帧长](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-4000-series-switches/29805-175.html) · [PPPoE 与 RFC 4638](https://www.rfc-editor.org/rfc/rfc4638.html#section-3) · [VXLAN 帧格式](https://www.rfc-editor.org/rfc/rfc7348.html#section-5) · [Google Cloud VPC MTU](https://docs.cloud.google.com/vpc/docs/mtu)

作为接入方式未知时的探测参考，先给标准以太网预留 PPPoE 的 8 B，再按 IPv4 满选项 40 B 或 IPv6 扩展 32 B 估算，得到 `1500 − 8 − 20 − 40 − 8 = 1424 B` 或 `1500 − 8 − 40 − 32 − 8 = 1412 B`。**1400 B** 可作为两种地址族共同的向上探测档，启用 FEC 后刚好装下 **1344 B** 的对齐分片。它仍须探测成功才能用于业务。若实际 PPP/隧道 MTU 或扩展头长度已知，直接使用实际值。探测与 DATA 应使用相同路径、封装和 IP 选项；若 DATA 可能比探测多带扩展头，按最大额外差值给 DATA 留余量，或用同样的最长头重新探测。[QUIC 对 IPv6 基线余量的核算](https://www.rfc-editor.org/rfc/rfc9000.html#section-14)

### atbus 消息实际能装多少

设 D 是该方向允许使用的 UDP 负载。短头 DATA 有 21 B 公共头、16 B tag、4 B SID 和 14 B symbol 描述，共占 **55 B**。启用 FEC 时，修复包的 `first_sid + count` 比 DATA 的 SID 多 1 B，还需能容纳 XOR 后的整个 symbol，按 **56 B** 预算。单片/尾片最多装 `D − 55` 或 `D − 56` 字节已编码 atbus 块。非尾片再向下对齐到 32 B。以下表中 v4/v6 指**内层地址族**，E 为 0，只有首行显式保留扩展空间。

| 路径或策略 | 内层 IP MTU（B） | UDP 负载 D（v4 / v6，B） | 启用 FEC 的非尾片（v4 / v6，B） |
| --- | ---: | ---: | ---: |
| AUDP 建连基线 | IPv6 1280，余 32 B | 1200 / 1200 | 1120 / 1120 |
| 内层 IP MTU 1280 | 1280 | 1252 / 1232 | 1184 / 1152 |
| VXLAN，外层 IPv6、underlay 1500 | 1430 | 1402 / 1382 | 1344 / 1312 |
| VXLAN，外层 IPv4、underlay 1500 | 1450 | 1422 / 1402 | 1344 / 1344 |
| 默认 1460 的云 VPC | 1460 | 1432 / 1412 | 1376 / 1344 |
| 传统 PPPoE | 1492 | 1464 / 1444 | 1408 / 1376 |
| 以太网，含支持标签帧长的 VLAN | 1500 | 1472 / 1452 | 1408 / 1376 |
| 显式启用 Jumbo 的内网 | 9000 | 8972 / 8952 | 8896 / 8896 |

握手与业务预算不同。INIT/RETRY 各 58 B。注册 DATA 的长头 42 B，加 key ID 4、cookie 16、PN 4，认证头共 66 B。再扣 tag 16、SID 4、symbol 描述 14，注册分片开销为 **100 B**。D=1200 时，注册块单片容量为 1100 B，非尾片为 1088 B。settings 的 17 B 只在整个注册块开头出现一次，单片注册可留给 `pack_message()` 结果 1083 B。

普通业务同理。D=1200 且启用 FEC 时单片可装 1144 B 编码块，多片消息的非尾片最多装 1120 B。若 `vint(head_size)` 占 1 B、protobuf 消息头实际为 48 B，单片可装 **1095 B 编码正文**。头长、压缩后的正文和可能的内层填充以 `pack_message().used()` 对应的实际块为准。TCP 的 MurmurHash 和长度 vint 不进入 AUDP 预算。[消息编码](../src/atbus_connection_context.cpp) · [TCP 外层分帧](../src/channel_io_stream.cpp)

### 按方向探测与回退

- **范围。** 公网默认按 IP MTU 1500 的本地策略限制，IPv4/IPv6 通常通告 1472/1452 B UDP 接收上限。受管内网可显式用现有 `max_udp` 允许按 IP MTU 9000 探测，v1 线字段接受 1200..8972 B。IPv6 在该策略下最多发送 8952 B。对端通告仅表示能接收的完整 UDP 负载，发送端取本地策略、对端上限和已知出口有效 MTU 换算值的最小值作为搜索上界。收到正向确认前只用已验证的尺寸。例如 AWS 部分路径支持 9001 B，而经 Internet Gateway 的上限为 1500 B。本设计将 Jumbo 作为显式策略，默认沿用公网范围。[AWS EC2 路径 MTU](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html)
- **候选。** 先双向确认 1200。之后从小到大试公共档 `1232、1400`，IPv4 再试 `1464、1472`，IPv6 再试 `1432、1444、1452`。插入按当前出口 MTU 和真实 IP 头换算的上界，去重并滤掉越界值。1464/1432 分别已装得下公网 IPv4/IPv6 最大常规对齐分片，继续升档主要利于更大的单包或尾片。Jumbo 仅在双方允许时追加 `2048、4096、8192、有效上界`，接收缓冲按通告值配置。若一档持续失败，在最后成功与失败尺寸之间收窄，优先验证能多装一个 32 B 分片单元的 `56 + 32 × n`，可在窄区间停止搜索。
- **确认与黑洞。** 一个发送方向同时只测一个尺寸，PROBE 独立填充到目标 UDP 负载，不参与 FEC，IPv4 设置 DF，IPv6 禁止源端分片。仅在未截断、认证成功且声明长度等于实收长度时 ACK 此 PN。小 PROBE 的回包不能证明大包可达。探测失败不影响已验证 DATA，独立计时器初值 `max(16 s, PTO)`，同一候选最多 3 次并退避。稳定连接约每 600 秒加抖动复探。本地消息过大错误或经验证的 ICMP Packet Too Big 先收紧搜索上界。若其低于在用尺寸，或在用大包持续失败而 1200 B 成功，则立即降低数据预算、封存旧 FEC 组并重切未确认的可靠字节。基线也失败则按连接期限报错。无法保证禁止源端分片时保持保守基线，并报告探测能力受限。探测验证可交付的 UDP 大小，隧道外层有无分片须结合隧道配置或外层抓包判断。[RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.html) · [IPv6 PMTUD](https://www.rfc-editor.org/rfc/rfc8201.html)
- **共享 socket。** 与现有路径拥塞状态一起按本地出口、对端地址/端口、地址族和影响路由的封装参数缓存探测状态。同路径多条 CID 可共用探测证据，发送仍受各自的 `max_udp` 和预算约束。路由、接口或隧道变化时回到基线。收发方向分别验证。

## Linux 默认值与缓存

| Linux 启动时读取 | 默认用途 |
| --- | --- |
| `/proc/sys/net/ipv4/udp_mem`、`udp_rmem_min`、`udp_wmem_min` | 第一项为所有 UDP socket 的页数预算，按运行时页大小换算。第二项为每 socket 在压力下的接收保障，单位字节。当前内核文档注明第三项对 UDP 发送记账无效。 |
| `/proc/sys/net/core/{rmem,wmem}_{default,max}` | 配置 socket 队列，显式值优先。一个监听 socket 的所有会话共享内核缓冲。用 `getsockopt` 读回实际值，考虑 Linux 双倍记账。 |
| `/proc/sys/net/netfilter/nf_conntrack_udp_timeout`、`nf_conntrack_udp_timeout_stream` | 单位秒。前者作握手期限参考并受现有确认超时限制，后者初始化会话 idle。可选保活间隔取 `min(udp_timeout, negotiated_idle)/3`。本地 conntrack 值无法保证远端 NAT 的存活时间。 |

配置取 socket 所在网络命名空间的值，文件缺失或无效时 socket 使用系统默认，两个超时回退到 30/120 s，可显式覆盖。用户态按会话独立预算。取 M 为本地最大编码块，B 为监听器可授予的额度，接收数据预算默认 `min(B, max(2×M, udp_rmem_min))`，再把通告的 max_block 限制到预算内。建议初始 rx_mids 为 64。控制、FEC 和解压临时内存另计并受监听器总上限约束。node 的发送缓存上限沿用已有配置。M 还受 `message_size + ATBUS_MACRO_MAX_FRAME_HEADER` 限制。[内核 UDP 参数](https://docs.kernel.org/networking/ip-sysctl.html#udp-variables) · [socket 缓冲](https://docs.kernel.org/admin-guide/sysctl/net.html) · [conntrack 超时](https://docs.kernel.org/networking/nf_conntrack-sysctl.html)

**接收热路径。** 先收进 MTU 大小的池化缓冲，验证 tag，再更新 PN 位图或索引 MID。单包可直接从已认证明文同步解包。多片只向最终缓冲的 `buffer + offset` 拷贝，用 32 B 粒度位图记录覆盖。先检查 `offset < total`，再计算 `total - offset` 并检查 `0 < len <= total - offset`。各片起点和非尾片长度均须 32 B 对齐，同一 MID 的 total 和重叠字节须一致。通过预算检查后才能分配。发送 PN 环只放编号、时间、长度和逻辑字节范围，消息缓冲单独持有。环槽带完整编号以区分覆盖。现有 `push(used_span())` 为借用接口，异步发送须复制到有界队列或在私有入口移动块所有权，libuv 发送完成前保证底层缓冲存活。

## 接入与验收

1. 在地址解析、scheme 通告和 node 的 listen/connect 中接入共享 UDP 通道。`node::connect(addr)` 及其 endpoint 重载目前会通过 `connecting_list_by_channel` 合并同地址在途拨号。保留普通重试的幂等行为，提供显式新建 AUDP 连接的入口（或 connect 选项），返回独立 connection，按本通道 local CID 登记和清理。带 endpoint 的拨号先记录预期身份，确认后才加入 endpoint 的控制/数据连接集合。按连接关闭时通过 connection 句柄操作。地址与 bus ID 都不能作为批量删除同址连接的依据。[当前拨号入口](../src/atbus_node.cpp)
2. 先打通共用 socket、cookie、原有注册三消息和单片 DATA，再复用同一份分片/ACK/拥塞状态机。可靠开关决定业务是否补发，顺序开关决定完整消息何时分发。最后接上 XOR、路径探测并评估自适应 FEC。
3. 验收从一对真实 UDP socket 同时建立两条连接开始。验证同地址同 bus ID 的两套 CID 均能注册，各自从 PN 0 发送，交错投递、丢包、重放及关闭其中一条时另一条仍能正常收发。对照 UUID 示例核验线序，以仅前半或仅后半 8 字节不同的 CID 验证独立查表。覆盖两端同时拨号、完整 CID 碰撞与延迟旧包、超长注册块分片、丢失/重复 req、rsp、confirm、ACK，以及错误 token、篡改 DCID/settings 的拒收和注册回调次数。针对 MTU，用不同方向分别模拟 IPv6 1280 加 32 B 扩展头、PPPoE 1492、VLAN 仍为 1500、VXLAN 内层 1450 及 Jumbo 突降到 1500。断言真实 UDP 长度、禁分片、认证确认后升档、过大反馈与黑洞回退、重切后业务可交付。对照 ATCP 老端与既有向量核对注册块内容及 KEY/IV，随后验证四种模式、XOR、路径回退、共享路径拥塞与资源回收。C++ 互操作、真实网络及性能留待原型验收。[现有编解码用例](../test/case/atbus_connection_context_test.cpp) · [签名用例](../test/case/atbus_message_handler_test.cpp) · [TCP 通道用例](../test/case/channel_io_stream_tcp_test.cpp)
