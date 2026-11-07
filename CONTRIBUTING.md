# Contributing

感谢参与 EvidenceWall。项目优先保证证据可复核、部署边界清楚和人工处置优先；不接受把它改成自动封禁或主动反制工具的方向。

## 开始之前

- 大功能、协议支持、数据模型或安全边界变更，请先开 issue 说明动机、影响范围和验证方式。
- 安全漏洞不要走公开 issue，按 [SECURITY.md](SECURITY.md) 私密报告。
- 不允许提交真实 token、私钥、Cookie、Authorization、案件数据、未脱敏证据包或他人的网络日志。

## 开发环境

要求 Python 3.10 或更高版本。

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m compileall -q src tests
```

Linux/macOS 将虚拟环境路径替换为 `.venv/bin/python`。

## 提交要求

- 行为变更需要测试；安全边界变更还需要同步 README、规格和相关 docstring。
- 保持改动聚焦，不顺手重排无关代码，不引入未讨论的框架或服务依赖。
- 默认维持“只报告、人工复核、不自动封禁”的产品约束。
- 不把数据目录、构建产物、虚拟环境或本地配置提交到仓库。
- 提交信息使用清晰的祈使句即可，不强制语言。

## Pull Request

PR 描述至少说明：

1. 改了什么；
2. 为什么改；
3. 对现有部署、证据格式或安全边界的影响；
4. 实际执行过的测试和结果。

维护者可能要求补充真实 socket、API、证据包或跨平台测试。CI 覆盖 Windows/Linux 和 Python 3.10–3.13；未通过的检查需要解释，不能静默跳过。

## 许可证

提交贡献即表示你同意该贡献按 Apache License 2.0 授权，并确认你有权提交相关内容。项目不要求 CLA。

