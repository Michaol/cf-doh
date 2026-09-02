# GeoIP 数据管线运维手册（Runbook）

> 适用架构：单一长生命周期 D1 库 `geoip_live_weur` + 合并主键表（migrations/0002）+
> 每日状态收敛作业（geoip_sync.py，cron `45 10 * * *` UTC）。
> 本手册取代旧的「每周建新库全量重灌」模式（该模式单次写入 ≈195 万行 = 免费日额度
> 100k 的 19.5 倍，自 Cloudflare 2026-09-01 硬失败执法起每周必然失败）。

## 1. 每日作业如何工作

`GeoIP Daily Sync` 工作流每天 10:45 UTC 运行 `geoip_sync.py --db geoip_live_weur`，
状态机以库内 `meta` 表为准（不信任任何外部假设）：

| 状态 | 判定 | 动作 | 写入量 |
|---|---|---|---|
| 引导（bootstrap） | `meta.source_tag` 不存在 | 应用下一个未标记 chunk（每天 1 块，块尾自带标记；D1 `--file` 整文件原子） | ≈72.6k 行/天 × 7 天 |
| 校验（verify-only） | tag+sha 与最新 release 一致 | COUNT + 200 探针比对 | **0** |
| 收敛（converge） | tag 或 sha 不一致 | keyset 导出线上表（读）→ 本地 diff → 闸门 → 应用 delta → 校验，失败自动 time-travel 回滚 | 实测 ≈11.8k，典型 24–34k |
| 升级（escalate） | delta > 80k 行或 churn > 25% | **拒绝应用**，exit 3，自动开 issue，转人工涓流重建（见 §3.4） | 0 |

退出码：`0` 正常；`1` 失败（次日自动重试，幂等）；`3` 闸门升级（需人工）。

## 2. 配额预算（D1 免费计划，账户级/天）

| 项 | 额度 | 本管线占用 |
|---|---|---|
| rows_written | 100,000/天 | 稳态 0（多数天）；release 周一天 ≈12–34k；引导期每天 ≈72.6k |
| rows_read | 5,000,000/天 | 收敛日导出+校验 ≈1.1M；校验日 ≈0.5M |
| 数据库数量 | 10 | 稳态 1（live）+ 过渡期旧库 ≤3 |

计费事实（2026-09-02 于本账户实测，探针 M1–M7）：
INSERT / UPSERT(ON CONFLICT DO UPDATE) / DELETE 在两种主键布局
（IPv4 `INTEGER PRIMARY KEY`、IPv6 `TEXT PRIMARY KEY WITHOUT ROWID`）下均为
**1 行写入/行**；`INSERT OR IGNORE` 冲突跳过计 **0**；`--file` 导入失败**整文件回滚**；
导入期间该库读阻塞（时长秒级，Worker 已有 try/catch 降级）。
**任何二级索引都会使写入翻倍——0002 模式禁止 CREATE INDEX。**

## 3. 恢复手册

### 3.1 某天运行失败（exit 1）
无需操作：次日 cron 自动重试（delta 幂等、块自标记）。失败会自动开 `ci-failure` 标签
issue（去重）。手动重放：Actions → GeoIP Daily Sync → Run workflow。

### 3.2 数据需要回滚（应用了坏 delta）
收敛作业在校验失败时已自动回滚；若需人工回滚（7 天窗口内）：
```bash
npx wrangler d1 time-travel info geoip_live_weur            # 查看可恢复点
npx wrangler d1 time-travel restore geoip_live_weur --bookmark=<BOOKMARK> -y
```
恢复后删除 `meta` 中的 `source_tag`/`mmdb_sha256` 两行（或改为回滚点对应值），
次日作业会重新收敛。

### 3.3 强制同步到指定 tag（如上游最新 release 有问题）
```bash
python3 geoip_sync.py --db geoip_live_weur --tag 202608270741
```
（`fetch_mmdb.sh` 按 tag 下载不可变 release 资产并校验 sha256。）

### 3.4 闸门升级（exit 3）后的涓流重建
1. `python3 merge_mmdb.py tmp/mm/Country-<tag>.mmdb tmp/rebuild`
2. `python3 build_chunks.py --v4-csv tmp/rebuild/blocks_ipv4_merged.csv --v6-csv tmp/rebuild/blocks_ipv6_merged.csv --tag <tag> --sha256 <sha> --out-dir tmp/rebuild/chunks`
3. 对**新建库** `geoip_rebuild_<tag>`（`wrangler d1 create` + 应用 0002）每天应用一个
   chunk（`wrangler d1 execute <db> -y --remote --file=chunk_NNN.sql`），7 天完成；
4. 全量对账通过后，把 wrangler.toml 的 `database_id` 指向新库并 `npm run deploy`
   （原子切换），旧库保留一个周期作冷回滚，随后按名删除。
   或：升级 Workers Paid（$5/月，50M 行写入/月）后单次完成。

### 3.5 定时任务被 GitHub 自动停用（60 天无活动规则）
Settings → Actions → General → 重新启用 workflow。检测手段是 dead-man 告警
（healthchecks.io，secret `HEALTHCHECK_PING_URL`，26h 静默即报警）——**不要依赖
GitHub 的任何失败通知**：schedule 丢失/停用不会触发 `if: failure()`。

### 3.6 孤儿库清理
```bash
npx wrangler d1 list                       # 人工核对
npx wrangler d1 delete <name> -y           # 逐个按名显式删除
```
**绝不**按位置/管道 tail 批量删（旧脚本的 off-by-one 曾可能删掉线上库）。
删除前用 `wrangler deployments status doh` 或 wrangler.toml 确认线上绑定的 uuid。

### 3.7 /debug/ip 调试端点
默认关闭（一律 404）。启用：Dashboard → Workers & Pages → doh → Settings →
Variables and Secrets 添加 Secret `DEBUG_TOKEN`（或 `wrangler secret put DEBUG_TOKEN`），
请求时携带 `x-debug-token: <值>` 头。未认证时该端点可被用作地理查询预言机，
消耗账户级 5M rows_read/天 配额，请勿公开令牌。

## 4. 变更数据管线的守则

- DDL 只有一处：`migrations/0002_merged_pk_schema.sql`。改表 = 新 migration + 更新
  本手册 + 用 `verify_merge.py` 对真实 mmdb 重跑等价性探针（40 万探针零误差才算无损）。
- 数据构建链：`fetch_mmdb.sh`（tag 锚定）→ `merge_mmdb.py`（无损合并+断言）→
  `build_chunks.py`（引导）/ `build_delta.py`(收敛，双闸门)。
- 任何新写入路径先对照 §2 配额预算；单日 >78k 行的操作必须分天或走 Paid。
- Worker 端查询（`WHERE network_start <= ? ORDER BY network_start DESC LIMIT 1`）
  与 schema 的等价性由 240k+ 探针验证保障，改任一侧都要重跑。

## 5. 未决事项（详见审查报告，2026-09-02）

- time-travel 的确切 JSON envelope 与 restore 是否计 rows_written：未在本账户实测
  （收敛正确性不依赖它——delta 幂等，仅影响自动回滚的便利性）。
- Loyalsoldier 历史 release 资产的长期可用性：仅验证近 4 个 tag；`meta` 已记录全部
  应用过的 tag+sha，资产 404 时以线上导出为基线恢复。
- 安全待办（独立立项）：未认证 `/debug/ip` 与 client-ip/alternative-ip 参数面可消耗
  5M rows_read/天 配额（2026-09-01 起读超限同样硬失败）；建议限流或加鉴权。
