# AI 服务适配

本目录与 `semantic/` 同级，集中维护 Rust 引擎对 Python AI 服务的接入。Python NLP/OCR 推理和 LLM 调用由 `python/vigilyx_ai/` 执行，界面的配置 API 保持原路径。在线训练已移除，模型在服务外离线训练，暂存产物需经明确审批后才能热加载。引擎进程内的 CPU ONNX 意图模型由 `semantic/intent_model.rs` 单独维护，不经本目录的 Python 接口。

| 文件 | 职责 |
| --- | --- |
| `mod.rs` | AI 模块入口 |
| `service.rs` | 读取服务配置、解密密钥、校验服务地址、建立连接及后台健康探测 |
| `remote.rs` | NLP、LLM 配置和 OCR 的 HTTP 请求、响应、超时及退避 |
| `nlp.rs` | 有界正文采样、异步请求调度、模型结果一致性检查、辅助贡献及失败状态 |
| `tests.rs` | 原有采样和模型一致性用例，以及请求停用、退避状态用例 |

`semantic/scan.rs` 通过接口启动和收取 AI 请求，继续承担既有管线中的模块调度与结果组装。此次为模块归属重构，AI 尚未拆成单独注册的检测模块；模型结果沿用现有的本地证据约束、计分上限、分类和覆盖语义。

AI 层不引用 `crate::semantic`。声明归属、引用、否定、原文坐标及输入采样是否包含合格声明，由语义调用方检查；AI 层接收检查结果并执行既有的模型结果准入。

HTTP 客户端的唯一源码位于 `ai/remote.rs`。`crate::external::remote` 与公开的 `vigilyx_engine::remote` 保留为兼容导出，已有 API 和其他调用方使用同一类型及实现。

原有 AI 采样与模型一致性用例已移入本目录，AI 与语义交互的集成用例仍在 `semantic/tests.rs`。按当前要求未运行编译或测试；后续应在远程构建容器中同时执行 `ai::`、`semantic::` 测试及 Clippy。
