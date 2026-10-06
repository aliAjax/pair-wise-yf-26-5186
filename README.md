# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限和访问控制。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

服务地址为 <http://127.0.0.1:8102>，默认数据库 `preservation.db`。测试：

```bash
python3 -m unittest -v
```

演示用户：`owner`、`archivist`、`auditor`、`outsider`；内置保管机构：`inst-alpha`、`inst-beta`、`inst-gamma`。API 使用 `X-User-Id`。文件通过 Base64 提交，单文件上限 10 MiB；这是为了保持示例自包含，生产部署应换成对象存储和流式上传。

## 主要接口

- `POST /api/archives`：创建受限档案，可选 `protection_min`（确认副本保护阈值，默认 2）。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单、副本状态与当前保护快照。
- `POST /api/versions/{id}/copies`：创建独立副本内容，可带 `custodian_id` 绑定保管机构。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态和审计记录。
- `GET/POST /api/custodians`：列出/登记保管机构。

### 保管机构轮值交接

轮值原则：**先核对、后撤旧**，保护状态中途不掉线。

- `POST /api/versions/{id}/handovers`：登记轮值（body：`outgoing_copy_id`、`incoming_custodian_id`、`incoming_location`）。新副本先预拷贝为 `staged`，**核对通过前旧副本留在原位**，staged 副本不计入保护。同一版本已有进行中交接时返回 `409 handover_conflict`——先登记的继续，后到的看到冲突。
- `POST /api/handovers/{id}/verify`：新机构逐份核对原文件的 SHA-256 摘要与大小（可传 `corrupt_paths` 模拟介质问题）。全部通过后新副本变 `healthy`，与旧机构及第三方的已确认副本合并计入保护；任一份不符则交接转 `failed`，新副本标 `corrupt`、不计保护，旧副本继续保留。
- `POST /api/handovers/{id}/complete`：仅在 `verified` 后可完成；系统先模拟旧机构退出后的保护数，若低于 `protection_min` 返回 `409 protection_below_minimum` 并拒绝撤旧。通过后旧副本转 `retired`，审计记录谁接手、谁退出。
- `POST /api/handovers/{id}/abort`：放弃交接，新机构副本退役、旧副本保留。
- `GET /api/handovers/{id}`：交接状态、核对尝试次数、失败明细与实时保护快照。

交接中断（进程重启后仍是 `staging`）或核对失败（`failed`）都可再次调用 verify 接着重试；failed 重试会先按权威原文件重新拉取一份再逐份核对。交接状态机为 `staging → verified → completed`，旁路 `failed`（可重试）与 `aborted`。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一、同一保管机构在同一版本只能持有一份有效副本；退役副本不计保护也不能再校验；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
