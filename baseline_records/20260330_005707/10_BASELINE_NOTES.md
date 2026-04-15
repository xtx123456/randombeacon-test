HashRand 本地运行与 Fabric 本地启动说明
1. 文档目的

记录当前项目在本地环境中的两类运行方式：

HashRand 本地 4 节点手工启动与终止
Fabric 本地 benchmark 启动与终止
2. 适用范围

适用于当前本地工作目录中的 HashRand 仓库与其 benchmark 目录。

3. 本地 4 节点手工启动

在仓库根目录执行以下操作：

启动前清理
cd "/home/xietianxiu/random beacon/hashrand/hashrand-rs"
pkill -f target/release/node || true
pkill -f target/debug/node || true
rm -f logs/*.log
mkdir -p logs
启动命令
cd "/home/xietianxiu/random beacon/hashrand/hashrand-rs"
TESTDIR=testdata/cc_4 TYPE=release bash ./scripts/beacon-test.sh testdata/cc_4/syncer bea 20 10
4. 本地 4 节点运行检查

启动后可查看以下日志：

syncer 日志
tail -f logs/syncer.log
节点日志
tail -f logs/0.log
tail -f logs/1.log
tail -f logs/2.log
tail -f logs/3.log
5. 本地 4 节点终止
cd "/home/xietianxiu/random beacon/hashrand/hashrand-rs"
pkill -f target/release/node || true
pkill -f target/debug/node || true

如需同时清理日志：

rm -f logs/*.log
6. Fabric 本地启动

进入 benchmark 目录后执行：

启动前清理
cd "/home/xietianxiu/random beacon/hashrand/hashrand-rs/benchmark"
pkill -f target/release/node || true
pkill -f target/debug/node || true
tmux kill-server 2>/dev/null || true
rm -f *.log
启动命令
cd "/home/xietianxiu/random beacon/hashrand/hashrand-rs/benchmark"
fab local
7. Fabric 本地运行检查

启动后可查看：

syncer 日志
tail -f syncer.log
各节点日志
tail -f 0.log
tail -f 1.log
tail -f 2.log
tail -f 3.log
8. Fabric 本地终止
cd "/home/xietianxiu/random beacon/hashrand/hashrand-rs/benchmark"
pkill -f target/release/node || true
pkill -f target/debug/node || true
tmux kill-server 2>/dev/null || true

如需清理日志：

rm -f *.log
9. 补充说明
本地运行主协议使用 bea
syncer 负责观测与统计
本地终止不要使用 fab kill
若日志中出现大量 ERROR，需要结合正文判断是否为真实错误