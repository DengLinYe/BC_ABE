# BC-ABE

区块链 + 多权威 CP-ABE 数据安全共享 Demo。

## 启动

```bash
cp .env.example .env   # 配置 MYSQL_DSN
sudo service mysql start
mysqladmin -h127.0.0.1 -uroot -p ping

go run .                              # 根目录：Fabric 主控
cd auth_admin && ORG_NAME=org1 go run .
cd auth_admin && ORG_NAME=org2 go run .
cd user_client && go run .
```

MySQL 库表由 `db.Init` 自动创建（`CREATE DATABASE IF NOT EXISTS` + GORM AutoMigrate）。

## 测试

Plan V1.2 全量实验（单元测试 + 四流程/变长/变策略/多 authority + AES/GPSW 对照 + 链上 + 并发压测），一条命令：

```bash
# 在项目根目录执行；链上/压测需 Fabric、user_client、auth_admin 均已启动
go run ./benchmark -out temp/bench
```

已在 `benchmark/` 目录时：

```bash
go run . -out ../temp/bench
```

原始数据输出：`temp/bench/*.csv`（含 `load_test.csv` 并发 QPS/P95/P99）。

可选：`-skip-test` / `-skip-chain` / `-skip-load` 跳过部分；`-c 10 -n 50` 调整压测并发与每接口请求数。
