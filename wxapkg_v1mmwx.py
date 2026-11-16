#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wxapkg-v1mmwx — 微信 PC 端 4.x 小程序包 (V1MMWX) 解密 / 解包 / 模块提取工具

微信 PC 客户端从 4.x 起，把小程序包 `__APP__.wxapkg` 由明文 (0xBE 头) 改为
加密容器 (V1MMWX 头)，同时分包以 `_pages_xxxModule_.wxapkg` 的形式按需下载。
本工具处理的就是这层格式。

用法见 README.md 或 `python wxapkg_v1mmwx.py -h`。
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    sys.stderr.write("缺少依赖: pip install pycryptodome\n")
    raise SystemExit(1)

from hashlib import pbkdf2_hmac

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

V1MMWX_MAGIC = b"V1MMWX"
WXAPKG_MAGIC = 0xBE
PBKDF2_SALT = b"saltiest"
AES_IV = b"the iv: 16 bytes"
HEAD_BLOCK = 1024          # AES 只加密前 1024 字节
PBKDF2_ROUNDS = 1000
AES_KEY_LEN = 32

MAX_NAME_LEN = 400         # 索引里单个文件名长度上限（防御异常数据）
MAX_FILE_COUNT = 20000


@dataclass
class Entry:
    name: str
    offset: int
    size: int


# ---------------------------------------------------------------------------
# 解密
# ---------------------------------------------------------------------------

def derive_key(appid: str) -> bytes:
    """PBKDF2-HMAC-SHA1(appid, "saltiest", 1000) -> 32 字节 AES key"""
    return pbkdf2_hmac("sha1", appid.encode("utf-8"), PBKDF2_SALT,
                       PBKDF2_ROUNDS, AES_KEY_LEN)


def _aes_head(data: bytes, appid: str, skip: int) -> bytes:
    """解密前 1024 字节头部。skip 用于补偿个别包的 1 字节偏移。"""
    head = AES.new(derive_key(appid), AES.MODE_CBC, AES_IV).decrypt(
        data[len(V1MMWX_MAGIC):len(V1MMWX_MAGIC) + HEAD_BLOCK]
    )
    return head[skip:]


def _xor_body(data: bytes, appid: str, skip: int) -> bytes:
    """剩余数据按 appid 倒数第二个字符做单字节 XOR。"""
    if len(appid) < 2:
        raise ValueError("appid 太短，无法推导 XOR key")
    key = ord(appid[-2])
    body = data[len(V1MMWX_MAGIC) + HEAD_BLOCK + skip:]
    return bytes(b ^ key for b in body)


def decrypt_v1mmwx(data: bytes, appid: str) -> tuple[bytes, str]:
    """
    解密 V1MMWX 容器，返回 (明文包数据, 命中的偏移组合说明)。

    实测发现不同包（主包 / 分包）的偏移不一致，因此这里枚举 4 种组合，
    用"索引能否被完整解析"作为判定依据，选第一个通过的。
    """
    if data[:len(V1MMWX_MAGIC)] != V1MMWX_MAGIC:
        raise ValueError(f"不是 V1MMWX 包，文件头为 {data[:8]!r}")

    for head_skip in (0, 1):
        for body_skip in (0, 1):
            try:
                plain = _aes_head(data, appid, head_skip) + _xor_body(data, appid, body_skip)
            except Exception:
                continue
            if parse_index(plain) is not None:
                return plain, f"head_skip={head_skip} body_skip={body_skip}"
    # 全部失败也返回一种结果，交给上层判断
    plain = _aes_head(data, appid, 0) + _xor_body(data, appid, 0)
    return plain, "head_skip=0 body_skip=0 (索引校验未通过)"


# ---------------------------------------------------------------------------
# 解析
# ---------------------------------------------------------------------------

def _u32(buf: bytes, pos: int) -> int:
    return int.from_bytes(buf[pos:pos + 4], "big")


def parse_index(buf: bytes) -> list[Entry] | None:
    """
    解析明文 wxapkg 的文件索引。

    布局：
        0        : 0xBE
        4..8     : fileCount (u32 BE)
        8..18    : 元信息
        18..     : 索引项 { nameLen u32 BE | name | offset u32 BE | size u32 BE }

    注意：name 区内可能夹带差分压缩的标记字节（如 0x01），它们不计入
    nameLen，解析时需跳过非可打印字节。函数用 offset 连续性做校验，
    任何一项不满足即认为整体不可信，返回 None。
    """
    if len(buf) < 32 or buf[0] != WXAPKG_MAGIC:
        return None

    count = _u32(buf, 4)
    if not (0 < count < MAX_FILE_COUNT):
        return None

    pos = 18
    prev_end: int | None = None
    entries: list[Entry] = []

    for _ in range(count):
        if pos + 4 > len(buf):
            return None
        name_len = _u32(buf, pos)
        pos += 4
        if not (1 <= name_len <= MAX_NAME_LEN):
            return None

        chars = bytearray()
        while len(chars) < name_len and pos < len(buf):
            c = buf[pos]
            pos += 1
            if 0x20 <= c <= 0x7E:          # 只累积可打印 ASCII，跳过标记字节
                chars.append(c)
        name = chars.decode("ascii", "replace")

        if not name.startswith("/"):
            return None
        if pos + 8 > len(buf):
            return None

        offset = _u32(buf, pos)
        pos += 4
        size = _u32(buf, pos)
        pos += 4

        if offset + size > len(buf):
            return None
        if prev_end is not None and offset != prev_end:
            return None

        entries.append(Entry(name, offset, size))
        prev_end = offset + size

    return entries


MODULE_RE = re.compile(rb'define\("([^"]+)"')


def find_modules(buf: bytes) -> list[tuple[str, int, int]]:
    """
    按 webpack 的 define("模块路径", ...) 边界切分 JS 模块。

    小程序把全部页面代码打进一个 app-service bundle，按模块切分比整包
    还原更适合定位逻辑。返回 [(模块名, 起始, 结束)]。
    """
    marks = [(m.start(), m.group(1).decode("utf-8", "replace"))
             for m in MODULE_RE.finditer(buf)]
    out = []
    for i, (start, name) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(buf)
        out.append((name, start, end))
    return out


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

def _safe_join(root: str, name: str) -> str | None:
    """把包内路径安全地拼到输出目录，拒绝目录穿越。"""
    rel = os.path.normpath(name.lstrip("/").replace("/", os.sep))
    if rel.startswith("..") or os.path.isabs(rel):
        return None
    return os.path.join(root, rel)


def write_files(buf: bytes, entries: list[Entry], outdir: str) -> int:
    written = 0
    for e in entries:
        path = _safe_join(outdir, e.name)
        if not path:
            continue
        os.makedirs(os.path.dirname(path) or outdir, exist_ok=True)
        with open(path, "wb") as f:
            f.write(buf[e.offset:e.offset + e.size])
        written += 1
    return written


def write_modules(buf: bytes, outdir: str) -> int:
    mods = find_modules(buf)
    for name, start, end in mods:
        path = _safe_join(outdir, name)
        if not path:
            continue
        os.makedirs(os.path.dirname(path) or outdir, exist_ok=True)
        with open(path, "wb") as f:
            f.write(buf[start:end])
    return len(mods)


# ---------------------------------------------------------------------------
# 命令
# ---------------------------------------------------------------------------

def load_plain(path: str, appid: str) -> tuple[bytes, str]:
    data = open(path, "rb").read()
    if data[:len(V1MMWX_MAGIC)] == V1MMWX_MAGIC:
        return decrypt_v1mmwx(data, appid)
    return data, "已是明文包"


def cmd_info(args) -> int:
    buf, how = load_plain(args.file, args.appid)
    entries = parse_index(buf) or []
    print(f"文件      : {args.file}")
    print(f"处理方式  : {how}")
    print(f"明文大小  : {len(buf):,} bytes")
    print(f"魔数      : 0x{buf[0]:02x}")
    print(f"文件数    : {len(entries)}")
    print(f"JS 模块数 : {len(find_modules(buf))}")
    if entries:
        print("前 10 个文件:")
        for e in entries[:10]:
            print(f"  {e.size:>9}  {e.name}")
    return 0


def cmd_decrypt(args) -> int:
    buf, how = load_plain(args.file, args.appid)
    out = args.output or (os.path.splitext(args.file)[0] + ".decrypted.wxapkg")
    with open(out, "wb") as f:
        f.write(buf)
    print(f"[+] {args.file} -> {out}  ({len(buf):,} bytes, {how})")
    return 0


def cmd_unpack(args) -> int:
    buf, how = load_plain(args.file, args.appid)
    entries = parse_index(buf)
    if not entries:
        print("[!] 索引解析失败，无法按文件解包。可尝试 extract 命令直接提模块。",
              file=sys.stderr)
        return 2
    outdir = args.output or (os.path.splitext(os.path.basename(args.file))[0] + "_files")
    n = write_files(buf, entries, outdir)
    print(f"[+] 解出 {n}/{len(entries)} 个文件 -> {outdir}  ({how})")
    return 0


def cmd_extract(args) -> int:
    buf, how = load_plain(args.file, args.appid)
    outdir = args.output or (os.path.splitext(os.path.basename(args.file))[0] + "_modules")
    n = write_modules(buf, outdir)
    print(f"[+] 切出 {n} 个 JS 模块 -> {outdir}  ({how})")
    return 0


def cmd_batch(args) -> int:
    files = []
    for root, _, names in os.walk(args.dir):
        for n in names:
            if n.endswith(".wxapkg"):
                files.append(os.path.join(root, n))
    if not files:
        print("[!] 目录下没有 .wxapkg 文件", file=sys.stderr)
        return 2

    ok = 0
    for path in sorted(files):
        tag = os.path.splitext(os.path.basename(path))[0]
        outdir = os.path.join(args.output, tag)
        try:
            buf, how = load_plain(path, args.appid)
            entries = parse_index(buf)
            if entries:
                write_files(buf, entries, os.path.join(outdir, "files"))
            n = write_modules(buf, os.path.join(outdir, "modules"))
            print(f"[+] {tag:40s} 文件={len(entries) if entries else 0:>3} 模块={n:>3}  {how}")
            ok += 1
        except Exception as exc:
            print(f"[!] {tag}: {exc}", file=sys.stderr)
    print(f"\n[+] 完成 {ok}/{len(files)}")
    return 0


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wxapkg_v1mmwx",
        description="微信 PC 4.x 小程序包 (V1MMWX) 解密 / 解包 / 模块提取",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python wxapkg_v1mmwx.py info    __APP__.wxapkg --appid wx1234567890abcdef\n"
            "  python wxapkg_v1mmwx.py unpack  __APP__.wxapkg --appid wx1234567890abcdef -o out\n"
            "  python wxapkg_v1mmwx.py extract _pages_indexModule_.wxapkg --appid wx... -o mods\n"
            "  python wxapkg_v1mmwx.py batch   ./packages --appid wx... -o ./out\n"
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_text):
        sp = sub.add_parser(name, help=help_text)
        if name == "batch":
            sp.add_argument("dir", help="包含 wxapkg 的目录")
        else:
            sp.add_argument("file", help="wxapkg 文件")
        sp.add_argument("--appid", required=True, help="小程序 appid，形如 wx1234567890abcdef")
        sp.add_argument("-o", "--output", help="输出路径")
        sp.set_defaults(func=fn)

    add("info", cmd_info, "显示包信息")
    add("decrypt", cmd_decrypt, "仅解密，输出明文 wxapkg")
    add("unpack", cmd_unpack, "解密并按索引解包")
    add("extract", cmd_extract, "解密并切出 define() JS 模块")
    add("batch", cmd_batch, "批量处理目录下所有 wxapkg")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "batch" and not args.dir:
        print("[!] batch 需要目录参数", file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
