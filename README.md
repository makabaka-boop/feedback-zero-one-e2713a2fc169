# pgcap — PostgreSQL 17 扩展查询双向字节流采集解析器

从零实现（仅用 Python 标准库）的后端，输入认证完成后、无 COPY 连接的
client/server 双向原始字节文件，自写分帧与请求/应答关联，按执行原序输出
JSON 数组。协议依据：

- [PostgreSQL 17 协议 §53.2.3 扩展查询](https://www.postgresql.org/docs/17/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY)
- [§53.2.4 函数调用](https://www.postgresql.org/docs/17/protocol-flow.html#id-1.10.6.7.5)
- [§53.7 消息格式](https://www.postgresql.org/docs/17/protocol-message-formats.html)

## 目录与入口

```
pgcap/
  framing.py     # §53.7 分帧、长度/残包校验、payload 顺序读取器
  protocol.py    # §53.2.3 状态机：对象生命周期 + 双向消息关联
  __main__.py    # CLI：读字节 -> 解析 -> 原子写 JSON
pgcap_cli.py     # 可执行入口（等价 python -m pgcap）
tests/
  pgmsg.py             # 手写 PG17 消息字节构造器
  test_acceptance.py   # 46 项独立字节级验收
run_acceptance.sh      # 一键验收
```

运行方式（两种等价）：

```bash
# 推荐：脚本入口自带路径注入，可在 Python 隔离模式（-I）下直接运行
python3 -I pgcap_cli.py client.bin server.bin output.json

# 模块入口（注意：-I 不把当前目录加入 sys.path，故此处不带 -I）
python3 -m pgcap client.bin server.bin output.json
```

- 成功：退出码 0，`output.json` 通过临时文件 + `os.replace` 原子替换。
- 失败：退出码 1，stderr 输出一行 JSON，含错误方向 `direction`
  （`client`/`server`）、违规消息起点的零基字节偏移 `offset` 与原因；
  旧输出文件原样保留。
- 双空流（两个输入文件均为空字节）合法，输出 `[]`。

## 接收与拒绝的消息

| 方向 | 接收的消息类型 |
|---|---|
| client→server | Parse `P`、Bind `B`、门户 Describe `D(P)`、Execute `E`、Close `C`、Flush `H`、Sync `S` |
| server→client | ParseComplete `1`、BindComplete `2`、CloseComplete `3`、RowDescription `T`、DataRow `D`、CommandComplete `C`、PortalSuspended `s`、ErrorResponse `E`、ReadyForQuery `Z` |

其余消息（SimpleQuery `Q`、NoData `n` 作为门户应答、EmptyQueryResponse
`I`、通知/通知响应/参数状态、启动/认证消息等）一律整次拒绝。语句 Describe
（`D(S)`）按需求拒绝；ErrorResponse 只允许出现在 Execute 的应答序列中，
其他位置出现即拒绝。

## 关联与生命周期规则

1. 无显式事务。非空输入必须以 Sync 结束，服务器对该 Sync 的
   ReadyForQuery 状态字节必须为 `I`（idle），否则拒绝。
2. SQL 为 Parse 携带的非空 UTF-8 字符串，只校验非空与编码，不做语义解释；
   所有协议字符串按 UTF-8 解码校验，参数/行值**永不解码**。
3. 支持命名与未命名对象：
   - 同名再 Parse / 再 Bind 即替换原对象；Bind 时把当时语句的 SQL 与参数
     快照固定到门户，门户存活期内不随后续重名绑定改变。
   - Bind 必须引用现存语句；门户 Describe / Execute 必须引用现存门户，且
     未跳过的 Execute 只能引用已成功描述（收到 RowDescription）的门户。
   - 每次 Sync（含错误恢复的 Sync）释放全部门户与未命名语句；命名语句保留。
   - Close 只能关闭现存对象，成功后按协议释放。
4. 流水线：客户端可在 Sync 前连续排队多组消息，服务端应答严格按请求次序
   消费；Flush 本身无应答，仅促使已排队应答被交付。
5. 暂停续取：`max_rows > 0` 且收到 PortalSuspended 记 `paused`，门户保持
   存活可再次 Execute；`max_rows=0` 时收到 `s` 为次序非法。每个 Execute
   输出项只记录本次收到的行。
6. 错误恢复（仅 Execute 允许错误应答）：
   - 错误归到当前执行项，状态 `error`，出错前已收到的行**保留**。
   - 其后到下一个 Sync 为止的客户端请求全部跳过：不创建/替换任何对象、
     不消费任何普通应答；其中被跳过的 Execute 仍占用一个连续 id 的输出
     槽，状态 `skipped`。
   - 跳过期内若服务器在 ReadyForQuery 前多发任何普通应答，整次拒绝。
   - Sync 的 ReadyForQuery 正常消费，之后可开始新一轮正常消息。

## 输出格式

JSON 数组，按 Execute 原序排列，`id` 从 0 连续（跳过的执行也占号）：

```json
{
  "id": 0,
  "sql": "SELECT $1::text AS note",
  "params": ["aGk="],
  "columns": [["note", 25, 0]],
  "rows": [["QQ=="]],
  "status": "paused"
}
```

- `columns`：每项为 `[列名, 类型 OID, 格式码(0 文本/1 二进制)]`，取自
  RowDescription。
- `params` 与行值：SQL NULL → JSON `null`；空字节串 `b""` → 空串 `""`；
  其余为带填充的标准 Base64 字符串。
- `status`：`completed`（完成）、`paused`（暂停）、`error`（错误）、
  `skipped`（跳过）。跳过项的 `sql`/`params`/`columns` 为 `null`、
  `rows` 为 `[]`。
- 续取示例：门户 `p` 两次执行，先取得 A 后暂停、再取得 B 后完成，两项
  `rows` 分别为 `[["QQ=="]]` 与 `[["Qg=="]]`（验收用例
  `test_spec_example_qq_qg` 固化该行为）。

## 整次拒绝（任一条件触发即不写输出）

- 分帧：长度字段 < 4、声明长度超出流尾（残包）、头部截断、流尾有残余字节。
- 编码：协议字符串不是合法 UTF-8；NUL 串无终止符；payload 与声明字段不符。
- 次序：应答与请求不匹配、缺失应答、无请求的多余应答、DataRow 列数与
  RowDescription 不符、暂停/完成/错误出现在非法位置、流未以 Sync + idle
  结束、单侧为空另一侧非空。
- 引用：Bind/Describe/Execute/Close 引用不存在的对象，或执行未成功描述的
  门户。

报错示例（零基偏移，定位到消息类型字节；缺失应答定位到最后一个客户端
消息的起点）：

```json
{"error": "protocol violation, run rejected", "direction": "client",
 "offset": 5, "reason": "message type 'Q' is not allowed in this flow"}
```

## 验收

```bash
./run_acceptance.sh
# 或
python3 -I tests/test_acceptance.py -v
```

46 个用例覆盖：双空流、未命名/命名对象、流水线、暂停续取（含题目 A/B
示例）、NULL/空字节/二进制 Base64、多 Sync 生命周期、重名替换、错误恢复
（保留行、跳过占号、Sync 后恢复）、全部拒绝类（残包、长度非法、未知类型、
UTF-8 非法、次序错乱、缺应答、残余字节、非 idle 状态等）以及 CLI 的原子
替换与失败保留旧文件。
