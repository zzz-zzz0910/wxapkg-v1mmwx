# wxapkg-v1mmwx

[![CI](https://github.com/zzz-zzz0910/wxapkg-v1mmwx/actions/workflows/ci.yml/badge.svg)](https://github.com/zzz-zzz0910/wxapkg-v1mmwx/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

微信 PC 端 **4.x** 小程序包（`V1MMWX` 加密容器）的解密、解包与 JS 模块提取工具。

单文件、无框架、纯 Python。

---

## 背景

微信 PC 客户端从 4.0 起改变了小程序的落盘方式，两处变化让老工具集体失效：

1. **包体加密**：`__APP__.wxapkg` 不再是以 `0xBE` 开头的明文包，而是以 ASCII
   `V1MMWX` 开头的加密容器。`unveilr` 等工具直接跑会报头错误。
2. **分包拆分**：业务代码按 `subPackages` 拆到独立文件，命名规则为
   `_pages_<模块名>_.wxapkg`，**按需下载** —— 只有在小程序里真正跳转到该分包页面
   时才会落盘，所以默认只能看到主包。

本工具处理第二点之外的完整链路：定位到包之后，解密 → 解包 → 切模块。

---

## 特性

- **自适应解密**：自动枚举 AES 头部 / XOR 体的偏移组合，用索引能否完整解析作为判定依据，
  兼容主包与分包之间的结构差异
- **索引容错**：索引里存在差分压缩的标记字节（如 `0x01`），不计入 `nameLen`；
  部分包索引残缺，工具会明确告知并建议改用 `extract`
- **模块级切割**：按 webpack 的 `define("模块路径", ...)` 边界切分，
  即使索引坏掉也能拿到全部 JS 模块
- **批处理**：一条命令处理一整个 `packages` 目录
- **零配置**：只依赖 `pycryptodome`

---

## 安装

```bash
pip install pycryptodome
```

Python 3.10+（3.9 已于 2025-10 EOL，CI 不再覆盖）。

## 用法

```bash
# 查看包信息（文件数、模块数、前几个文件名）
python wxapkg_v1mmwx.py info __APP__.wxapkg --appid wx1234567890abcdef

# 仅解密
python wxapkg_v1mmwx.py decrypt __APP__.wxapkg --appid wx... -o app.dec.wxapkg

# 解密 + 按索引解包
python wxapkg_v1mmwx.py unpack __APP__.wxapkg --appid wx... -o out/

# 解密 + 切出全部 JS 模块（定位业务逻辑用这个）
python wxapkg_v1mmwx.py extract _pages_deviceModule_.wxapkg --appid wx... -o mods/

# 批量处理整个 packages 目录
python wxapkg_v1mmwx.py batch ./packages --appid wx... -o ./output
```

`--appid` 就是小程序自己的 appid（`wx` + 16 位十六进制），通常是缓存目录名。

---

## 包在哪里

微信 PC 4.x（Windows）：

```
%APPDATA%\Tencent\xwechat\radium\users\<userhash>\applet\packages\<appid>\<version>\
    __APP__.wxapkg                        主包
    _pages_authModule_.wxapkg             分包，命名 = _pages_ + 分包路径(斜杠换下划线) + _
    _pages_deviceModule_.wxapkg
    ...
```

> 网上大量教程还写着 `xwechat_files\<wxid>\msg\applet\`，那是 4.x 早期或特定版本，
> 在当前版本上通常不存在。以 `radium\users\` 这条为准。

**怎么把分包弄下来**：分包按需下载，需要在小程序里真正跳转到对应页面。
即使跳转后因为没有登录态被踢回登录页，包也已经落盘了 —— 登录成功不是前提。

macOS 对应位置在 `~/Library/Containers/com.tencent.xinWeChat/...`，结构类似。

---

## 解密原理

```python
key  = PBKDF2-HMAC-SHA1(appid, salt=b"saltiest", iterations=1000, dkLen=32)
head = AES-128-CBC(key, IV=b"the iv: 16 bytes").decrypt(data[6 : 6+1024])
body = data[6+1024 :]  XOR  ord(appid[-2])
plain = head + body
```

- 只有前 **1024 字节**走 AES，其余部分是单字节 XOR
- XOR 的密钥是 **appid 倒数第二个字符的 ASCII 值**
- 解出来的明文以 `0xBE` 开头，即标准 wxapkg

明文包结构：

```
0        : 0xBE 魔数
4..8     : fileCount (u32 BE)
8..18    : 元信息
18..     : 索引项 { nameLen u32 BE | name | offset u32 BE | size u32 BE }
```

`offset` 是**相对文件开头的绝对偏移**，可直接用于切分数据区。

---

## 兼容性

已在微信 PC 4.x 的多款小程序上验证：主包 60 文件 / 234 模块、若干分包
（5–16 文件、10–62 模块）均能正确还原。

如果遇到解析失败，优先尝试 `extract`（不依赖索引），再考虑提 issue 附上
`info` 命令的输出。

---

## 免责声明

本工具仅用于**自有程序的安全审计、逆向工程学习与方法研究**。

微信小程序代码的著作权归其开发者所有。使用者应确保对目标程序拥有合法授权，
并遵守所在地法律法规及微信平台规则。作者不对任何滥用行为负责。

---

## License

MIT
