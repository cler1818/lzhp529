#!/usr/bin/env python3
"""
自动订阅生成器 - 极简版
仅保留提取节点、合并节点、创建策略组功能
"""

import os
import re
import base64
import json
import requests
import yaml
from urllib.parse import unquote


def safe_decode_base64(data):
    if not data:
        return None
    data = data.strip().replace('\n', '').replace('\r', '')
    data += '=' * (-len(data) % 4)
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        try:
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        except:
            return None


# =========================
# 解析代理链接
# =========================

def parse_ss(url, remark=None):
    try:
        body = url[5:]
        name = ''
        if '#' in body:
            body, name = body.split('#', 1)
            name = unquote(name)

        decoded = safe_decode_base64(body.split('@')[0])
        if not decoded or ':' not in decoded:
            return None

        method, password = decoded.split(':', 1)
        server, port = body.split('@')[1].split(':', 1)

        return {
            'name': f'{remark}-{name}' if remark else name or f'SS-{server}',
            'type': 'ss',
            'server': server,
            'port': int(port),
            'cipher': method,
            'password': password,
            'udp': True
        }
    except:
        return None


def parse_vmess(url, remark=None):
    try:
        cfg = json.loads(safe_decode_base64(url[8:]))
        name = cfg.get('ps', 'VMess')
        return {
            'name': f'{remark}-{name}' if remark else name,
            'type': 'vmess',
            'server': cfg.get('add'),
            'port': int(cfg.get('port', 443)),
            'uuid': cfg.get('id'),
            'alterId': int(cfg.get('aid', 0)),
            'cipher': 'auto',
            'udp': True,
            'tls': cfg.get('tls') == 'tls'
        }
    except:
        return None


def parse_trojan(url, remark=None):
    try:
        body = url[9:]
        name = ''
        if '#' in body:
            body, name = body.split('#', 1)
            name = unquote(name)

        password, rest = body.split('@', 1)
        server, port = rest.split(':', 1)

        return {
            'name': f'{remark}-{name}' if remark else name or f'Trojan-{server}',
            'type': 'trojan',
            'server': server,
            'port': int(port),
            'password': password,
            'udp': True
        }
    except:
        return None


def parse_proxy(line, remark):
    if line.startswith('ss://'):
        return parse_ss(line, remark)
    if line.startswith('vmess://'):
        return parse_vmess(line, remark)
    if line.startswith('trojan://'):
        return parse_trojan(line, remark)
    return None


# =========================
# 核心流程
# =========================

def fetch(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        text = r.text.strip()
        return safe_decode_base64(text) or text
    except:
        return None


def build_proxy_groups(nodes):
    names = [n['name'] for n in nodes]
    return [
        {
            'name': '节点选择',
            'type': 'select',
            'proxies': ['负载均衡', '自动选择']
        },
        {
            'name': '负载均衡',
            'type': 'load-balance',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'strategy': 'consistent-hashing',
            'proxies': names
        },
        {
            'name': '自动选择',
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'tolerance': 50,
            'proxies': names
        }
    ]


def main():
    os.makedirs('订阅链接', exist_ok=True)
    nodes = []

    with open('输入源/example.txt', 'r', encoding='utf-8') as f:
        lines = f.readlines()

    remark = None
    for line in lines:
        line = line.strip()
        if not line:
            remark = None
            continue
        if line.startswith('#'):
            remark = line.lstrip('#').strip()
            continue
        content = fetch(line)
        if not content:
            continue
        for l in content.splitlines():
            p = parse_proxy(l.strip(), remark)
            if p:
                nodes.append(p)

    groups = build_proxy_groups(nodes)

    config = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'proxies': nodes,
        'proxy-groups': groups
    }

    with open('订阅链接/output.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f'生成完成，共 {len(nodes)} 个节点')


if __name__ == '__main__':
    main()
