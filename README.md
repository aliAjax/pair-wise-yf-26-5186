# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限、访问控制，以及保管机构之间的安全轮值交接。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

服务地址为 <http://127.0.0.1:8102>，默认数据库 `preservation.db`。测试：

```bash
python3 -m unittest -v
```

演示用户：`owner`、`archivist`、`auditor`、`outsider`。API 使用 `X-User-Id`。文件通过 Base64 提交，单文件上限 10 MiB；这是为了保持示例自包含，生产部署应换成对象存储和流式上传。

## 保管机构轮值交接

几家机构各存副本。轮值时**先撤旧副本再拷新**会让保护状态中途掉到不够，因此交接按下面的安全协议进行，旧副本在新机构核对通过前始终留在原位：

1. 登记轮值 `POST /api/versions/{id}/handovers`（`to_institution_id` / `from_institution_id`）。同一档案同时只允许一个未完成的交接：两家机构同时提交时，先登记的继续，后到的看到 `handover_conflict`。
2. 新机构逐份核对原文件的摘要与大小 `POST /api/handovers/{id}/verify`（提交每份文件的 `path`/`sha256`/`size`）。核对通过前旧副本留在原位；核对失败会记录 `mismatches` 并置为 `failed`，可直接重新提交清单重试，旧副本不撤。
3. 在任保管机构确认交接 `POST /api/handovers/{id}/confirm`。两边都确认过的副本合起来才算保护。
4. 完成交接 `POST /api/handovers/{id}/complete`：新机构接手（`took_over_institution_id`），旧机构退出（`exited_institution_id`），但旧副本留住、不删除；健康副本数全程不低于法定份数（`required_copies`）。
5. 中断交接 `POST /api/handovers/{id}/abort`：旧副本留住，已登记的交接作废，之后可重新登记。

保护状态可通过 `GET /api/versions/{id}/protection` 查看（健康副本数、在任保管机构、未完成交接）。所有接手、退出动作写入审计日志。

## 主要接口

- `POST /api/archives`：创建受限档案。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单和副本状态。
- `POST /api/versions/{id}/copies`：创建独立副本内容。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态和审计记录。
- `POST /api/institutions` / `GET /api/institutions`：登记/列出保管机构。
- `POST /api/versions/{id}/custodians`：把保管机构接到档案版本上。
- `POST /api/versions/{id}/handovers` / `GET /api/archives/{id}/handovers`：登记/列出轮值交接。
- `POST /api/handovers/{id}/verify|confirm|complete|abort`：核对、确认、完成、中断交接。
- `GET /api/handovers/{id}`：查看交接详情。
- `GET /api/versions/{id}/protection`：查看版本保护状态。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
