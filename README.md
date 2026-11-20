# network-policy-path-simulator

逐跳（hop-by-hop）模拟一条业务流量在 Kubernetes 集群里经过
**源 Pod → ClusterIP Service（含 DNAT/端口转换）→ 后端端点 Pod** 时，
入口（Ingress）和出口（Egress）网络策略分别如何判定，解决“排查工具只看
一条策略、无法还原中间服务和端口转换后实际结果”的问题。

## 这是离线判定模型

- **不连接 API Server、不调用 kube-proxy/CNI，也不发起任何真实网络请求。**
- 全部输入（命名空间标签、Pod 标签与 IP、Service/Endpoints 映射、NetworkPolicy）
  都由调用方以普通 JSON 提供，模拟器只在内存里做纯函数计算。
- 输出是“按 Kubernetes 文档语义推导出的判定结果”，用于代码评审、策略调试和
  回归测试，不能替代真实集群中的连通性验证（CNI 实现差异、节点安全组、
  kube-proxy 模式等不在模型范围内）。

## 运行环境

- Node.js `24.16.0`（`package.json` 的 `engines` 已声明）。
- 零第三方依赖，仅使用 Node 内置模块（`node:test`、`node:fs` 等）。

```bash
node --test
```

## 模拟语义

严格遵循 Kubernetes NetworkPolicy 的官方语义：

- **策略取并集**：同一 Pod、同一方向上被多条策略选中时，任意一条策略的规则
  放行即放行；每条未命中的策略仍会记录在 `blockingPolicies` 中。
- **没有允许即拒绝**：一旦某方向上至少有一条策略选中该 Pod，该方向即被隔离，
  只有显式命中 allow 规则才放行。
- **无策略默认放行**：没有任何策略在该方向上选中该 Pod 时，该方向全部放行
  （结果里 `policyApplies: false`）。
- `policyTypes` 缺省时，Ingress 默认启用；Egress 仅在策略包含 `egress` 规则时启用。
- 规则内 `from`/`to` 与 `ports` 是“与”关系；规则之间、peer 之间是“或”关系。
- 空选择器 `{}` 与省略选择器都表示“匹配全部”；空规则数组表示隔离且拒绝一切；
  空的 `from: []`/`to: []` 不匹配任何对端。
- `podSelector` 单独出现时只在**策略所在命名空间内**匹配；配合
  `namespaceSelector` 才能跨命名空间匹配。
- `ipBlock` 支持 `cidr` 与 `except` 排除，IPv4/IPv6 不同地址族互不命中。
- 端口支持数字、命名端口（按目标 Pod 的 `containerPort` 名称解析）和
  `endPort` 端口范围。

### 逐跳模型

Service 流量按每个后端端点拆成独立分支，每个分支评估两跳：

1. **Egress 跳**：在源 Pod 上，按 **DNAT 之后的端点身份与转换后的目标端口**
   评估出口策略。主流 CNI（Calico、Cilium 等）在连接跟踪/DNAT 后按工作负载
   身份执行策略，因此这里使用端点而非 ClusterIP 虚拟 IP 作为对端；原始
   ClusterIP 与 Service 端口仍保留在 `route` 中。
2. **Ingress 跳**：在端点 Pod 上，以源 Pod 为对端、转换后的目标端口评估入口策略。

Egress 被拒绝时不再评估 Ingress。直连 Pod IP（无 Service）同样走这两跳；
若 IP 不属于拓扑中的任何 Pod，则只评估 Egress。

## 输入

调用 `simulatePath(scenario, request)`，`scenario` 包含：

- `namespaces`：`{ name, labels }`
- `pods`：`{ namespace, name, labels, ip, ipv6, ports[] }`
- `services`：`{ namespace, name, selector, clusterIP, clusterIPv6, ports[], endpoints? }`
  - 提供 `endpoints` 时按显式 Endpoints 子集处理；否则用 `selector` 在同命名空间
    的 Pod 中自动派生端点。
  - Service 端口的 `targetPort` 可以是数字或命名端口。
- `policies`：包含 `podSelector`、`policyTypes`、`ingress`/`egress`，规则 peer
  支持 `podSelector`、`namespaceSelector`、`ipBlock`。

`request` 描述一次连接：源 Pod、目的（`destinationService` / `destinationPod` /
`destinationIp` 三选一）、端口（数字或 Service 端口名）、协议与可选 `ipFamily`。

完整示例见 [`examples/cross-namespace.json`](examples/cross-namespace.json)。

## 输出

- 顶层 `status`：`allow` / `deny` / `partial` / `error`
  - `partial`：多端点中一部分放行、另一部分拒绝或解析失败。
  - `error`：所有分支都因配置问题无法评估。
- `route`：Service 名、ClusterIP、Service 端口、目标端口与 DNAT 描述。
- `branches[]`：每个端点一条，含 `result`、最终 `endpoint`（IP、地址族、归属
  Pod、转换后的端口）和 `hops[]`。
- 每个 hop 给出 `decision`、`policyApplies`、命中的 `matchedRules`（策略名、
  规则下标、peer 下标、peer 类型）以及 `blockingPolicies`（哪组策略阻止了它）。
- `warnings` / 分支级 `error`：非致命或致命的配置问题。

### 配置错误 vs 正常拒绝

两者在输出层面严格区分：

- **正常拒绝**：`status: "deny"`，无 `error` 字段，拒绝原因体现在 hop 的
  `blockingPolicies` 与空的 `matchedRules` 上。
- **配置错误**：抛出 `SimulationError`（拓扑级致命问题，如未知 Pod/Service、
  无可用端点、服务端口不存在、非法 CIDR/IP/选择器），或在分支上以
  `result: "error"` + `error.code` 呈现（如某端点的命名端口无法解析，
  此时其他端点仍可成功）。错误码定义在 `src/errors.js`。

## 编程用法

```js
import { simulatePath } from "./src/index.js";

const result = simulatePath(scenario, {
  sourceNamespace: "frontend",
  sourcePod: "web",
  destinationService: { namespace: "backend", name: "api" },
  destinationPort: 80,
  protocol: "TCP",
});

console.log(result.status); // allow | deny | partial | error
```

## CLI

```bash
# 单文件（{ scenario, request }）
node bin/netpol-sim.js examples/cross-namespace.json

# 或场景与请求两个文件
node bin/netpol-sim.js scenario.json request.json
```

退出码：`0` 全允许，`1` 拒绝/部分，`2` 配置错误。

## 测试覆盖

`node --test` 运行 34 个用例，覆盖：

- 同命名空间放行、空选择器、无策略默认放行、`policyTypes` 缺省行为
- 跨命名空间拒绝、podSelector 不能跨命名空间、默认拒绝、策略并集
- Egress 允许但 Ingress 拒绝、Egress 默认拒绝时短路
- `ipBlock` 放行/`except` 排除、Ingress 按源 IP 判定、IPv6 双栈
- Service 多端点、一端失败另一端成功（`partial`）、命名端口解析、端口范围
- 配置错误（未知 Pod/命名空间/Service、端口缺失、非法 CIDR/选择器）与正常拒绝的区分

## 模型边界

- 不模拟 TCP 握手、连接跟踪超时、重试与客户端负载均衡策略，仅按端点逐个判定。
- 不建模节点安全组、外部 LB、NetworkPolicy 之外的 AdmissionWebhook 或 CNI 自定义 CRD。
- Egress 按 DNAT 后身份评估是主流 CNI 的常见行为；个别 CNI 若在 DNAT 前按
  ClusterIP 评估，结果可能不同，需以真实集群为准。
