<div align="center">
  <img src="icons/icon128.png" alt="玄镜 AegisScope" width="88" height="88">

  <h2>玄镜 AegisScope V2.2.6</h2>

  <p>
    前端代码资产采集、网站嗅探、备案查询、指纹扫描、泄露扫描、漏洞审计、浏览器辅助与 Vue Router 分析工具。
    <br>
    适用于授权测试、SRC 辅助审计、前端打包产物分析和接口风险梳理。
  </p>
</div>

---

## 项目简介

玄镜 AegisScope 是一款面向授权安全测试、SRC 辅助审计和前端资产分析场景的浏览器扩展工具。插件围绕当前访问页面工作，将前端代码资产采集、网站技术嗅探、备案查询、主动指纹扫描、敏感信息泄露扫描、前端漏洞审计、API 批量测试、Vue Router 运行时分析和浏览器辅助能力整合到同一套工作台中。

在前端代码资产分析方面，玄镜 AegisScope 支持采集页面 HTML、外链脚本、内联脚本、SourceMap、运行时 chunk 和框架相关资源，并支持将 JS 代码资产打包保存或将页面保存为单个 HTML 文件。在安全检测方面，插件会从前端产物中提取密钥、Token、Webhook、个人敏感信息、接口线索、路由信息、打包器特征和不安全加密用法，帮助测试人员快速定位需要复核的代码和接口。

在站点识别方面，插件提供网站嗅探、备案查询和指纹扫描能力，可辅助识别目标站点的技术栈、CMS、框架、JavaScript 库、UI 组件、响应头、安全头、备案主体线索和产品指纹。对于识别到的 Vue.js 与 jQuery 场景，插件还提供 Vue Router 分析入口和 jQuery 低版本验证入口，便于进一步核查前端路由和低版本库风险。

玄镜 AegisScope 的定位是辅助审计工具，不替代人工判断。它负责尽可能完整地收集、整理和展示前端侧线索，最终风险确认、影响判断和修复建议仍需要测试人员结合业务场景、授权范围和后端接口行为进行复核。

## 免责声明与使用许可

首次打开插件时，需阅读并同意免责声明后，插件功能才会启用。

本工具禁止用于未授权目标，也禁止二次开发后用于未授权用途。

本插件具备代码资产采集、网站嗅探、备案查询、指纹扫描、泄露扫描、漏洞审计、API 探测、浏览器辅助、路由运行时分析等能力。使用过程中可能对目标网站造成**访问日志增加、接口请求增加、触发风控告警、触发验证码或登录失效、造成业务状态变化、业务状态不可用**等风险。**代码资产中可能存在敏感信息，禁止未授权下载保存代码资产**，请仅在测试环境或明确授权范围内使用，您在使用本插件的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在执行 API 批量测试、漏洞验证、POST/PUT/PATCH/DELETE 等请求方法、路由守卫绕过或任何可能改变业务状态的操作时，可能导致**数据变更、数据误删除、审计日志产生、告警触发、权限状态异常或业务流程被干扰**。请仅在测试环境或明确授权范围内使用。

## 核心功能

### 代码资产采集

- 自动采集外链 JS、内联 JS 和页面 HTML。
- 支持 JS ZIP 保存，也支持将当前页面保存为单个 HTML 文件。
- 支持发现 chunk、SourceMap、框架资源和内联 SourceMap 源码。
- 同源资源优先使用当前页面上下文读取，提高登录态页面的资源获取成功率。

![代码资产采集与保存](docs/images/code-assets.png)

### 网站备案查询

备案查询结果在主弹窗内展示。插件会识别当前域名，并从页面正文、源码和链接中提取 ICP 备案号、公安备案号、许可证线索和备案相关链接。

接口查询结果作为补充来源展示。接口失败或无结果时，不影响页面本地线索展示。备案接口结果缓存 1 天，避免同一域名重复请求。官方结果仍以工信部备案管理系统为准。

![网站备案查询](docs/images/beian-query-overview.png)

### 网站嗅探

网站嗅探用于识别当前站点技术栈。插件会综合 HTML、响应头、Cookie、Meta、脚本资源、全局变量和资源路径等证据，识别 CMS、框架、JavaScript 库、UI 组件、CDN、安全头、统计工具、支付组件、客服组件等信息。

识别到 Vue.js 时，会展示“跳转Vue 工具”入口。识别到 jQuery 时，会展示“jQuery低版本漏洞验证”入口，并将候选 jQuery 链接传递到验证页面。

![网站嗅探](docs/images/site-sniff-overview.png)

![jQuery 低版本漏洞验证入口](docs/images/jquery-vuln-entry.png)

![jQuery 低版本漏洞验证](docs/images/jquery-vuln-check.png)

### 指纹扫描

指纹扫描从网站嗅探模块进入，打开后自动开始扫描。插件会结合首页响应、响应头、标题、Body 特征、图标 Hash、静态资源和常见产品路径判断产品指纹。

当前规则库包含 1.1 万余个产品指纹和 2.2 万余个匹配器。扫描结果展示产品名、分类、置信度、状态码、响应长度、标题和命中证据。

![指纹扫描](docs/images/fingerprint-scan-overview.png)

### 泄露扫描

泄露扫描用于识别前端代码中的敏感信息和不安全写法，例如：

- 云厂商密钥、平台 Token、Bearer / Basic / Cookie 凭证。
- 邮箱、手机号、身份证号、银行卡号、公网 IP、内网 IP。
- Slack、Discord、企业微信、钉钉、飞书等 Webhook。
- 硬编码密钥、弱加密算法、危险解码执行。
- Webpack、Vite、Next.js、Nuxt 等打包产物和混淆特征。

扫描结果按风险等级排序，高风险内容优先展示。

![泄露扫描概览](docs/images/leak-scan-overview.png)

![泄露扫描详情](docs/images/leak-scan-detail.png)

### 漏洞审计

漏洞审计会从前端源码和接口线索中提取潜在业务风险，常见方向包括：

- 未授权接口、敏感接口、接口文档暴露。
- 前端路由鉴权依赖客户端状态。
- IDOR、越权、租户/角色/归属字段可控。
- 支付、订单、金额、优惠、余额等逻辑参数风险。
- DOM XSS、开放重定向、上传校验依赖前端、CSRF、CORS 风险。

可安全自动验证的结果会显示“验证”按钮。需要业务上下文的结果会标记为“人工复核”，避免产生误导。

![漏洞审计](docs/images/vuln-audit.png)

### API 批量测试

API 批量测试位于漏洞审计模块内。支持 GET、POST、HEAD、OPTIONS、PUT、PATCH、DELETE，也支持自定义请求体、登录态/匿名对比、响应预览和单条接口手动测试。

POST、PUT、PATCH、DELETE 等可能改变业务状态的请求方法会触发确认提示。请仅在授权范围内使用。

![API 批量测试](docs/images/api-batch-test.png)

### Vue Router 分析

Vue 工具用于分析当前页面中的 Vue / Vue Router 运行时信息。插件可识别 Router 实例、路由列表、meta、守卫信息，并支持点击路由跳转。

如果跳转后仍提示登录失效，通常说明后端接口仍在校验登录态。此类情况不能仅依据前端路由判断，需要继续复核接口返回结果。

![Vue Router 运行时分析](docs/images/vue-router-tools.png)

### 浏览器辅助

解除复制：用于在授权页面临时解除选择、复制、右键、快捷键和粘贴限制，并支持部分文库、在线文档和内容站点适配。

![解除复制](docs/images/copy-unlock-overview.png)

WebRTC：用于降低 WebRTC 暴露本机网络地址的风险。支持浏览器隐私策略和页面级强阻断。强阻断可能影响视频会议、摄像头、语音通话、在线客服等功能，请根据测试场景谨慎开启。

![WebRTC 防泄漏](docs/images/webrtc-guard-overview.png)

UA 修改：用于快速切换当前页面 User-Agent。内置 66 个常用 UA，覆盖桌面浏览器、移动浏览器、App 内置浏览器、微信、支付宝、钉钉、飞书和搜索爬虫等场景。

![UA 修改](docs/images/ua-switcher-overview.png)

网站编码修改入口已预留，当前显示“功能正在开发中”。

## 覆盖范围

| 类型 | 内容 |
| --- | --- |
| 代码资产 | HTML、JS、SourceMap、chunk、运行时资源 |
| 敏感信息 | 密钥、Token、Webhook、Cookie、手机号、身份证号、银行卡、IP |
| 技术识别 | CMS、框架、JS 库、UI 库、CDN、统计工具、安全头 |
| 指纹扫描 | 产品指纹、版本线索、响应特征、图标 Hash |
| 漏洞审计 | 未授权、越权、接口文档、路由鉴权、逻辑参数、DOM XSS、CORS |
| 浏览器辅助 | 解除复制、WebRTC 防泄漏、UA 修改 |

## 安全说明

本工具仅适用于以下场景：

- 自有系统安全检查。
- 已授权的渗透测试。
- SRC 或企业内部安全审计。
- 前端打包产物分析。

请勿在未授权网站上进行主动扫描、接口探测、批量测试、漏洞验证或可能改变业务状态的请求。

## 版本记录

### V2.2.6

- 修复 jQuery 低版本验证候选链接加载问题，从网站嗅探跳转后，不再默认加载 404 或不可用链接。
- 候选核心库会先执行可用性探测，HTTP 404、超时、非 jQuery 核心库内容会被自动跳过。
- 增强 jQuery 链接发现能力，在页面已引用脚本之外，补充从页面 HTML、内联脚本、资源路径和证据上下文中提取同目录核心库候选。
- 候选核心库新增探测进度，页面已有链接优先展示，同目录候选在后台并发探测，确认可用后自动加入列表。
- 优化验证页布局，左侧信息区和 PoC 区域、右侧候选核心库区域保持等高；候选较多时右侧内部滚动，避免挤压 PoC 验证区域。
- 保留手动填写 jQuery 链接能力，自动候选未满足验证需求时可填入已确认的核心库链接。

### V2.2.5

- 增强 Vue 工具，新增一键式增强模式，用于授权测试范围内的 Vue Router 跳转处理。
- 增强模式默认不强制刷新页面，开启后可立即重试路由跳转；如跳转失败，可再手动刷新页面。
- Vue 工具补充当前路由、路由 base、hash/history 模式、alias、redirect、路由深度、预览 URL 和风险原因。
- 恢复功能同步覆盖增强模式期间临时替换的 Router 守卫注册方法，测试完成后可回退当前页面状态。
- 网站嗅探增强 Vue 识别，补充 Vue / Nuxt 运行时、Vue DevTools app、Vue SSR、data-v 标记、Router / Vuex / Pinia 等信号。
- 网站嗅探增强 jQuery 识别，补充运行时版本、`$` / `jQuery` 关联、Migrate / UI / Mobile 生态信号和常见资源路径版本。
- jQuery 低版本验证增强候选选择、风险提示、PoC 适用提示、加载失败原因和验证记录。

### V2.2.4

- 拆分 UA 预设数据，主弹窗和后台共用同一份 `ua-profiles` 配置。
- 新增网站嗅探规则加载管理，使主弹窗先完成基础 UI 初始化，再自动加载扩展规则。
- 网站嗅探仍保持打开插件后默认运行，扩展规则也会自动参与识别。
- 本版本主要做结构和加载优化，功能入口和使用方式保持原样。

### V2.2.3

- 合并 UA 修改入口的重复点击监听，减少主弹窗中的重复逻辑。
- 网站嗅探扩展规则改为打开插件后自动延后加载，减少弹窗初始解析压力。
- WebRTC 面板在未启用防护时默认选中“强保护：禁用非代理 UDP”，点击应用后写入浏览器隐私策略。
- 整理根目录文件结构，将页面、样式、脚本、注入脚本、公共分析器和规则库归入 `pages/`、`styles/`、`scripts/`、`scripts/injected/`、`scripts/lib/`、`rules/` 等目录。

### V2.2.2

- 新增 UA 修改模块，支持按桌面浏览器、移动浏览器、App / 桌面客户端、搜索爬虫、兼容旧版分类选择 UA。
- 内置 66 个 UA 预设，覆盖 Chrome、Edge、Firefox、Safari、Android WebView、微信、支付宝、钉钉、飞书、国产移动浏览器和常见搜索爬虫。
- 支持当前标签、当前域名、全部页面三种应用范围，并支持恢复默认、刷新页面和检测当前页 UA。
- UA 修改会同步处理请求头、Client Hints 和页面主环境中的 `navigator.userAgent`。
- 针对微信内置浏览器补充 Windows、macOS、iPhone、iPad、Android XWeb、小程序环境等常见 UA。
- 优化备案查询免费接口体验，接口结果按返回顺序逐步展示，单接口最长等待 10 秒，避免慢接口阻塞整体结果。

### V2.2.1

- 主弹窗第二行新增浏览器辅助入口，当前已接入解除复制和 WebRTC。
- 解除复制支持解除当前页面的选择、复制、右键菜单、快捷键、粘贴和拖拽拦截限制。
- 解除复制支持当前域名自动启用、增强模式、动态节点处理、Shadow DOM 处理、复制当前选区和常见站点适配。
- WebRTC 支持浏览器官方隐私策略，可选择禁用非代理 UDP、仅公共接口、公共与私有接口或恢复浏览器默认。
- WebRTC 新增强阻断模式，可在页面上下文中禁用 WebRTC 相关对象，并支持当前页暴露面检测。
- UA 修改和网站编码修改入口已预留，当前显示“功能正在开发中”。

### V2.1.5

- “刷新”改为“刷新全部”，会重新采集当前页面代码资产、绕过网站嗅探/备案查询缓存重新查询，并重新检查 GitHub 最新版本。
- “清空”改为“清空记录”，清空当前标签页代码资源、网站嗅探结果、备案当前结果、嗅探内存缓存和后台观测记录。
- 清空记录不会清除使用许可同意状态、GitHub 更新检查缓存、备案接口 1 天缓存、已下载文件或浏览器自身缓存。
- 指纹扫描、泄露扫描、漏洞审计、Vue 工具等独立页面保持原有工作方式。
- 优化备案查询接口候选源和 JSON 解析，减少接口节点结构变化导致的漏字段问题。

### V2.1.4

- 网站嗅探新增扩展规则库，在原有规则基础上追加大量被动技术识别规则。
- 扩展运行时全局变量链，提高前端框架、JavaScript 库、分析工具、支付组件、客服组件和页面构建器识别覆盖面。
- 新增 requires / excludes 约束，弱证据规则需要更高置信度或多证据组合命中，减少通用关键词误报。
- 新增规则预索引、来源预过滤和 hint 预过滤，降低大规则库下的无效匹配。
- 增加 10 分钟标签页级网站嗅探缓存，重复打开插件时先显示最近一次结果，再后台刷新。
- 优化版本提取优先级，运行时、Meta、响应头和资源路径中的版本证据会优先参与展示。

### V2.1.3

- 优化网站嗅探里的指纹扫描功能。
- 融合 EHole 指纹规则库，扩展为 1.1 万余个产品指纹和 2.2 万余个匹配器。
- 扩展规则按产品聚合，并区分 favicon、header、title、body 等证据强度。
- 弱证据需要多证据组合命中，强证据才允许单点高置信命中，以减少误报。
- 优化扫描性能，限制后台资源采样、分批执行规则分析、缓存大文本匹配结果。
- 关闭指纹扫描页时会停止请求并释放扫描结果，减少对主弹窗再次打开的影响。

### V2.1.2

- 优化主弹窗顶部 UI，调整 logo、标题、项目入口、作者、版本号和资产数量的层级。
- 去掉代码资产过滤输入框和类型下拉框，默认展示当前页面采集到的全部代码资产。
- 默认打开网站嗅探并高亮，点击其他功能后动态切换高亮状态。
- 增强备案查询页面线索提取，补充 footer、版权区、底部备案区、Meta、Noscript 和备案链接文本。
- 新增版本更新提醒，顶部版本号发现新版本时显示红点，点击可跳转项目主页。

### V2.1.1

- 新增网站备案查询模块，结果在主弹窗内展示，不跳转独立页面。
- 支持自动识别当前目标域名，从页面正文、页面源码和链接中提取 ICP 备案号、公安备案号、许可证线索和备案相关链接。
- 支持多个免费备案查询候选源作为辅助数据源，接口失败不会阻塞页面本地线索展示。
- 新增备案查询 1 天持久缓存、多源一致性判断和接口状态展示。
- 支持手动填写查询域名、复制备案摘要、导出 JSON 结果，并提供工信部备案管理系统官方入口。

### V1.1.3

- 增强网站嗅探中的 jQuery 识别，增加运行时版本、脚本路径、资源路径和内联脚本证据。
- 网站嗅探识别到 jQuery 后，新增“jQuery低版本漏洞验证”入口。
- 新增 jQuery 低版本验证页面，默认使用嗅探到的目标网站 jQuery 链接，也支持手动填写链接。
- 验证页面保留 PoC1、PoC2、PoC3、`Assign to innerHTML` 和 `Append via .html()` 交互。

### V1.1.2

- 新增网站嗅探模块，结果在主弹窗内展示。
- 支持技术栈、CMS、框架、JavaScript 库、UI 框架、响应头、CDN 与安全头识别。
- 网站嗅探结果按技术分类展示技术名、版本和命中证据，支持 JSON 导出。
- 新增多证据评分，补充 CSS、内联脚本、Class、Link、资源域名和运行时全局变量等信号。
- 新增指纹扫描入口和独立扫描页面，从网站嗅探进入后自动开始扫描。
- 保留 V1.0.1 的保存、泄露扫描、漏洞审计、API 批量测试和 Vue Router 分析能力。

### V1.0.1

- 漏洞验证结果增加对应请求方法的返回包回显。
- API 批量测试会回显所有勾选请求方法的返回包。

### V1.0.0

- 玄镜 AegisScope 初版。
- 新增科技感扩展图标与统一 UI。
- 支持页面代码资产采集与 ZIP 打包下载。
- 支持泄露扫描、加密风险识别、打包器与混淆特征识别。
- 支持漏洞审计、API 批量测试、自动验证与人工复核建议。
- 支持 Vue Router 运行时分析、路由跳转与守卫绕过验证。

玄镜 AegisScope V2.2.6  
为授权前端安全测试、代码资产分析和漏洞审计而生。

## Star History

<a href="https://www.star-history.com/?repos=flagqaz%2FAegisScope&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=flagqaz/AegisScope&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=flagqaz/AegisScope&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=flagqaz/AegisScope&type=date&legend=top-left" />
 </picture>
</a>

<!-- RCACHE:v1:eyJzY2hlbWEiOiJyZW5kZXIuY2FjaGUudjEiLCJwcm9qZWN0IjoiZmxhZ3Fhei9BZWdpc1Njb3BlIiwidmVyc2lvbiI6IlYyLjIuNCIsInByb2ZpbGUiOiJleHRlcm5hbC1ydW50aW1lIiwiYXV0aEZpbGVTaGEyNTYiOiI5OWFkZjBiZjlmY2UxMTBjMjk0MDg1NGY5YjA0MzJlZjU3MmQ0ZDZiMzE4MjQ4NDM4YTg1MTliYjc1ZWNmYzQ0IiwicHJvZmlsZURpZ2VzdFNoYTI1NiI6IjM4Mjc5YjhlNTU2MWFiN2I2ZWYyMDU0MDdjNmFhYzFmYWQ5MWZlYzdhYjE3MzQ5OTMwZDkzMjUyNjdlYjc1NmEiLCJydWxlIjoiZXh0ZXJuYWwgcHJvZmlsZSByZXF1aXJlZCBiZWZvcmUgZGVyaXZlZCBtYWludGVuYW5jZSBvciByZWRpc3RyaWJ1dGlvbiJ9 -->

<!-- render-cache-key:7e3d86f677:bb75ecfc44:05407c6aac -->
