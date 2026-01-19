#!/usr/bin/env python3
"""
自动订阅生成器 - 终极简化版
支持从备注中提取分组信息，为每个订阅链接创建独立策略组
统一使用混合端口7890，策略组极度简化
支持解析Clash YAML格式节点
优化了请求超时处理和重试机制
"""

import os
import re
import base64
import json
import requests
import yaml
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote
import time
import shutil
import concurrent.futures

def get_beijing_time():
    """获取东八区北京时间"""
    utc_now = datetime.utcnow()
    beijing_tz = timezone(timedelta(hours=8))
    beijing_time = utc_now.replace(tzinfo=timezone.utc).astimezone(beijing_tz)
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')

def extract_remark_from_comment(comment_line):
    """从注释行中提取备注信息"""
    if not comment_line or not isinstance(comment_line, str):
        return None
    
    # 移除注释符号和空格
    comment_line = comment_line.strip()
    if comment_line.startswith('#'):
        comment_line = comment_line[1:].strip()
    
    # 如果为空或只有#，返回None
    if not comment_line:
        return None
    
    # 找到第一个标点符号、空格或特殊字符作为断点
    # 支持的断点字符：空格、逗号、句号、分号、冒号、感叹号、问号、中文标点
    break_pattern = r'[\s,.;:!?。，；：！？、\u3000]'
    
    match = re.search(break_pattern, comment_line)
    if match:
        # 获取断点前的文本
        remark = comment_line[:match.start()].strip()
    else:
        # 如果没有断点字符，使用整个注释
        remark = comment_line.strip()
    
    # 清理备注：移除可能的额外符号
    remark = remark.strip(' -_')
    
    # 如果备注长度超过20个字符，截断
    if len(remark) > 20:
        remark = remark[:20]
    
    return remark if remark else None

def parse_source_file(filepath):
    """解析源文件，提取带备注的链接"""
    results = []
    current_remark = None
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            
            if not line:
                current_remark = None
                continue
            
            if line.startswith('#'):
                # 提取备注
                remark = extract_remark_from_comment(line)
                if remark:
                    current_remark = remark
                continue
            
            # 非注释行，且是URL
            if line and not line.startswith('#') and re.match(r'^https?://', line):
                results.append({
                    'url': line,
                    'remark': current_remark
                })
                current_remark = None
    
    except Exception as e:
        print(f"解析源文件失败: {e}")
    
    return results

def safe_decode_base64(data):
    """安全解码Base64数据"""
    if not data:
        return None
    
    data = str(data).strip()
    data = data.replace('\n', '').replace('\r', '')
    
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        try:
            return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        except:
            return None

def clean_config(config):
    """清理配置，移除空值和无效字段"""
    if not isinstance(config, dict):
        return config
    
    cleaned = {}
    for key, value in config.items():
        if value is None or value == '':
            continue
        
        if isinstance(value, (list, dict)) and len(value) == 0:
            continue
        
        if isinstance(value, dict):
            cleaned_value = clean_config(value)
            if cleaned_value:
                cleaned[key] = cleaned_value
        elif isinstance(value, list):
            cleaned_list = [clean_config(item) for item in value if clean_config(item) is not None]
            if cleaned_list:
                cleaned[key] = cleaned_list
        else:
            cleaned[key] = value
    
    return cleaned

def parse_hysteria2(url, remark=None):
    """解析Hysteria2链接"""
    try:
        url = url[11:]  # 移除 hysteria2://
        
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        if '@' in url:
            auth_part, server_part = url.split('@', 1)
            password = auth_part
        else:
            return None
        
        server = ""
        port = 443
        query_params = {}
        
        if '?' in server_part:
            server_port_part, query_str = server_part.split('?', 1)
            query_params = parse_qs(query_str)
        else:
            server_port_part = server_part
        
        if ':' in server_port_part:
            server, port_str = server_port_part.split(':', 1)
            port = int(port_str)
        else:
            server = server_port_part
        
        # 添加备注前缀
        if remark and name:
            name = f"{remark}-{name}"
        elif remark:
            name = f"{remark}-Hysteria2-{server}:{port}"
        elif name:
            name = name
        else:
            name = f"Hysteria2-{server}:{port}"
        
        config = {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
        }
        
        if query_params.get('sni'):
            config['sni'] = query_params['sni'][0]
        
        insecure = query_params.get('insecure', ['0'])[0] == '1' or query_params.get('allowInsecure', ['0'])[0] == '1'
        if insecure:
            config['skip-cert-verify'] = True
        
        if query_params.get('alpn'):
            config['alpn'] = query_params['alpn'][0].split(',')
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  Hysteria2解析失败: {e}")
        return None

def parse_ss(url, remark=None):
    """解析Shadowsocks链接"""
    try:
        url = url[5:]  # 移除 ss://
        
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        decoded = safe_decode_base64(url.split('@')[0] if '@' in url else url)
        
        if decoded and ':' in decoded:
            method, password = decoded.split(':', 1)
        else:
            if '@' in url:
                encoded_auth, server_part = url.split('@', 1)
                decoded_auth = safe_decode_base64(encoded_auth)
                if decoded_auth and ':' in decoded_auth:
                    method, password = decoded_auth.split(':', 1)
                else:
                    return None
            else:
                return None
        
        if '@' in url:
            _, server_part = url.split('@', 1)
        else:
            server_part = url
        
        if '?' in server_part:
            server_part, _ = server_part.split('?', 1)
        
        if ':' in server_part:
            server, port = server_part.split(':', 1)
            port = int(port)
        else:
            return None
        
        # 添加备注前缀
        if remark and name:
            name = f"{remark}-{name}"
        elif remark:
            name = f"{remark}-SS-{server}:{port}"
        elif name:
            name = name
        else:
            name = f"SS-{server}:{port}"
        
        config = {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
            'udp': True
        }
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  SS解析失败: {e}")
        return None

def parse_vmess(url, remark=None):
    """解析VMess链接"""
    try:
        encoded = url[8:]  # 移除 vmess://
        decoded = safe_decode_base64(encoded)
        
        if not decoded:
            return None
        
        vmess_config = json.loads(decoded)
        
        original_name = vmess_config.get('ps', f"VMess-{vmess_config.get('add', 'unknown')}")
        
        # 添加备注前缀
        if remark:
            name = f"{remark}-{original_name}"
        else:
            name = original_name
        
        config = {
            'name': name,
            'type': 'vmess',
            'server': vmess_config.get('add', ''),
            'port': int(vmess_config.get('port', 443)),
            'uuid': vmess_config.get('id', ''),
            'alterId': int(vmess_config.get('aid', 0)),
            'cipher': vmess_config.get('scy', 'auto'),
            'udp': True,
        }
        
        if vmess_config.get('tls') == 'tls':
            config['tls'] = True
            config['skip-cert-verify'] = vmess_config.get('allowInsecure') in [True, 'true', '1']
        
        sni = vmess_config.get('sni') or vmess_config.get('host')
        if sni:
            config['servername'] = sni
        
        network = vmess_config.get('net', 'tcp')
        if network != 'tcp':
            config['network'] = network
            
            if network == 'ws':
                ws_opts = {}
                if vmess_config.get('path'):
                    ws_opts['path'] = vmess_config['path']
                if vmess_config.get('host'):
                    ws_opts['headers'] = {'Host': vmess_config['host']}
                if ws_opts:
                    config['ws-opts'] = ws_opts
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  VMess解析失败: {e}")
        return None

def parse_trojan(url, remark=None):
    """解析Trojan链接"""
    try:
        url = url[9:]  # 移除 trojan://
        
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        if '@' in url:
            password_part, server_part = url.split('@', 1)
            password = password_part
        else:
            return None
        
        server = ""
        port = 443
        query_params = {}
        
        if '?' in server_part:
            server_port_part, query_str = server_part.split('?', 1)
            query_params = parse_qs(query_str)
        else:
            server_port_part = server_part
        
        if ':' in server_port_part:
            server, port_str = server_port_part.split(':', 1)
            port = int(port_str)
        else:
            server = server_port_part
        
        # 添加备注前缀
        if remark and name:
            name = f"{remark}-{name}"
        elif remark:
            name = f"{remark}-Trojan-{server}:{port}"
        elif name:
            name = name
        else:
            name = f"Trojan-{server}:{port}"
        
        config = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'sni': query_params.get('sni', [''])[0] or server,
            'skip-cert-verify': query_params.get('allowInsecure', ['0'])[0] == '1',
            'udp': True
        }
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  Trojan解析失败: {e}")
        return None

def parse_vless(url, remark=None):
    """解析VLESS链接"""
    try:
        url = url[8:]  # 移除 vless://
        
        name = ""
        if '#' in url:
            url, fragment = url.split('#', 1)
            name = unquote(fragment)
        
        if '@' in url:
            uuid_part, server_part = url.split('@', 1)
            uuid = uuid_part
        else:
            return None
        
        server = ""
        port = 443
        query_params = {}
        
        if '?' in server_part:
            server_port_part, query_str = server_part.split('?', 1)
            query_params = parse_qs(query_str)
        else:
            server_port_part = server_part
        
        if ':' in server_port_part:
            server, port_str = server_port_part.split(':', 1)
            port = int(port_str)
        else:
            server = server_port_part
        
        # 添加备注前缀
        if remark and name:
            name = f"{remark}-{name}"
        elif remark:
            name = f"{remark}-VLESS-{server}:{port}"
        elif name:
            name = name
        else:
            name = f"VLESS-{server}:{port}"
        
        config = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'udp': True,
        }
        
        security = query_params.get('security', [''])[0]
        if security in ['tls', 'xtls']:
            config['tls'] = True
            config['skip-cert-verify'] = query_params.get('allowInsecure', ['0'])[0] == '1'
        
        sni = query_params.get('sni', [''])[0] or server
        config['servername'] = sni
        
        return clean_config(config)
        
    except Exception as e:
        print(f"  VLESS解析失败: {e}")
        return None

def parse_proxy_url(url, remark=None):
    """解析代理URL"""
    if not url or not isinstance(url, str):
        return None
    
    url = url.strip()
    
    if url.startswith('hysteria2://'):
        return parse_hysteria2(url, remark)
    elif url.startswith('ss://'):
        return parse_ss(url, remark)
    elif url.startswith('vmess://'):
        return parse_vmess(url, remark)
    elif url.startswith('trojan://'):
        return parse_trojan(url, remark)
    elif url.startswith('vless://'):
        return parse_vless(url, remark)
    
    return None

def parse_clash_yaml_node(line, remark=None):
    """解析Clash YAML格式节点"""
    try:
        # 移除开头的"- "和空格
        line = line.strip()
        if line.startswith('- '):
            line = line[2:].strip()
        elif line.startswith('-'):
            line = line[1:].strip()
        
        # 解析YAML格式的节点
        node_data = yaml.safe_load(line)
        
        if not isinstance(node_data, dict):
            return None
        
        # 确保必要的字段存在
        if 'name' not in node_data or 'server' not in node_data or 'type' not in node_data:
            return None
        
        # 添加备注前缀
        original_name = node_data.get('name', '')
        if remark and original_name:
            node_data['name'] = f"{remark}-{original_name}"
        elif remark:
            # 生成默认名称
            server = node_data.get('server', 'unknown')
            port = node_data.get('port', '')
            proxy_type = node_data.get('type', '').upper()
            node_data['name'] = f"{remark}-{proxy_type}-{server}:{port}"
        
        # 确保udp字段存在
        if 'udp' not in node_data:
            node_data['udp'] = True
        
        return clean_config(node_data)
        
    except Exception as e:
        print(f"  Clash YAML节点解析失败: {e}")
        return None

def parse_clash_yaml_content(content, remark=None):
    """解析完整的Clash YAML配置文件"""
    proxies = []
    
    try:
        config = yaml.safe_load(content)
        
        if not isinstance(config, dict):
            return proxies
        
        # 从配置文件的proxies部分提取节点
        if 'proxies' in config and isinstance(config['proxies'], list):
            for proxy in config['proxies']:
                if isinstance(proxy, dict):
                    # 克隆代理配置以避免修改原始数据
                    proxy_config = dict(proxy)
                    
                    # 添加备注前缀
                    if remark and 'name' in proxy_config:
                        proxy_config['name'] = f"{remark}-{proxy_config['name']}"
                    
                    # 确保udp字段存在
                    if 'udp' not in proxy_config:
                        proxy_config['udp'] = True
                    
                    proxies.append(clean_config(proxy_config))
        
        print(f"    从Clash配置解析到 {len(proxies)} 个节点")
        
    except Exception as e:
        print(f"  Clash配置解析失败: {e}")
    
    return proxies

def fetch_subscription(url, timeout=30):
    """获取订阅内容 - 带重试机制"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/plain, */*',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    
    # 重试机制，最多重试3次
    for attempt in range(3):
        try:
            if attempt > 0:
                print(f"    第{attempt+1}次重试...")
                time.sleep(2 ** attempt)  # 指数退避
            
            # 尝试请求
            response = requests.get(
                url, 
                headers=headers, 
                timeout=timeout,
                verify=False  # 不验证SSL证书，避免证书问题导致的失败
            )
            
            # 检查响应状态
            if response.status_code == 200:
                content = response.text.strip()
                
                # 尝试自动检测编码
                try:
                    response.encoding = response.apparent_encoding
                    content = response.text.strip()
                except:
                    pass
                
                decoded = safe_decode_base64(content)
                
                if decoded:
                    return decoded, True, None
                
                return content, True, None
            else:
                # 非200状态码，如果是500系列错误可以重试
                if 500 <= response.status_code < 600 and attempt < 2:
                    continue
                return None, False, f"HTTP错误: {response.status_code}"
                
        except requests.exceptions.Timeout:
            if attempt == 2:  # 最后一次尝试也超时
                return None, False, "请求超时"
            continue
            
        except requests.exceptions.ConnectionError:
            if attempt == 2:
                return None, False, "连接错误"
            continue
            
        except requests.exceptions.SSLError:
            # SSL错误，尝试不验证证书
            try:
                response = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if response.status_code == 200:
                    content = response.text.strip()
                    decoded = safe_decode_base64(content)
                    
                    if decoded:
                        return decoded, True, None
                    
                    return content, True, None
                else:
                    return None, False, f"HTTP错误: {response.status_code}"
            except Exception as e:
                if attempt == 2:
                    return None, False, f"SSL错误: {str(e)}"
                continue
                
        except Exception as e:
            if attempt == 2:
                return None, False, f"错误: {str(e)}"
            continue
    
    return None, False, "多次尝试后失败"

def fetch_subscription_parallel(args):
    """并行获取订阅内容 - 用于线程池"""
    url, remark = args
    content, success, error_msg = fetch_subscription(url)
    
    entry_info = {
        'url': url,
        'remark': remark,
        'node_count': 0,
        'error': ''
    }
    
    if success and content:
        proxies = process_subscription_content(content, remark)
        if proxies:
            entry_info['node_count'] = len(proxies)
            return {
                'success': True,
                'proxies': proxies,
                'remark': remark,
                'entry_info': entry_info
            }
        else:
            entry_info['error'] = "无有效节点"
            return {
                'success': False,
                'proxies': [],
                'remark': remark,
                'error_msg': "无有效节点",
                'entry_info': entry_info
            }
    else:
        entry_info['error'] = error_msg
        return {
            'success': False,
            'proxies': [],
            'remark': remark,
            'error_msg': error_msg,
            'entry_info': entry_info
        }

def is_clash_yaml_content(content):
    """判断内容是否为Clash YAML格式"""
    if not content:
        return False
    
    # 检查是否包含Clash关键字
    clash_keywords = ['proxies:', 'proxy-groups:', 'rules:', 'mixed-port:', 'port:']
    
    # 检查前几行
    first_lines = content.strip().split('\n')[:5]
    for line in first_lines:
        line_lower = line.lower().strip()
        for keyword in clash_keywords:
            if keyword in line_lower:
                return True
    
    # 检查是否包含YAML格式的节点行
    yaml_node_pattern = r'^\s*-\s*{.*?}\s*$'
    lines = content.strip().split('\n')
    yaml_node_count = 0
    
    for line in lines[:20]:  # 只检查前20行
        if re.match(yaml_node_pattern, line):
            yaml_node_count += 1
    
    # 如果有多个YAML格式节点行，认为是Clash YAML
    if yaml_node_count >= 2:
        return True
    
    # 检查是否包含标准的Clash proxies部分（带缩进的多行格式）
    if 'proxies:' in content:
        # 检查proxies后面的内容
        lines = content.strip().split('\n')
        in_proxies = False
        dash_count = 0
        
        for line in lines:
            line_stripped = line.strip()
            if line_stripped == 'proxies:':
                in_proxies = True
                continue
            
            if in_proxies:
                if line_stripped.startswith('- '):
                    dash_count += 1
                elif line_stripped.startswith('-'):
                    dash_count += 1
                elif line_stripped and not line_stripped.startswith('#'):
                    # 非空非注释行，检查是否有缩进
                    if line.startswith('  ') and ':' in line:
                        dash_count += 0.5  # 多行格式
        
        if dash_count >= 2:
            return True
    
    return False

def extract_yaml_proxies_from_content(content, remark=None):
    """从内容中提取YAML格式的节点"""
    proxies = []
    
    try:
        # 尝试解析完整YAML
        config = yaml.safe_load(content)
        
        if isinstance(config, dict) and 'proxies' in config:
            return parse_clash_yaml_content(content, remark)
        elif isinstance(config, list):
            # 直接是节点列表
            for node in config:
                if isinstance(node, dict) and 'name' in node and 'server' in node and 'type' in node:
                    proxy_config = dict(node)
                    
                    # 添加备注前缀
                    if remark and 'name' in proxy_config:
                        proxy_config['name'] = f"{remark}-{proxy_config['name']}"
                    
                    # 确保udp字段存在
                    if 'udp' not in proxy_config:
                        proxy_config['udp'] = True
                    
                    proxies.append(clean_config(proxy_config))
            
            if proxies:
                print(f"    从YAML列表解析到 {len(proxies)} 个节点")
    
    except Exception as e:
        # 如果不是有效的YAML，尝试逐行解析
        lines = content.split('\n')
        current_node = {}
        in_node = False
        indent_level = 0
        
        for line in lines:
            line = line.rstrip()
            
            # 跳过空行和注释
            if not line.strip() or line.strip().startswith('#'):
                continue
            
            # 检查是否是节点开始
            if line.strip().startswith('- ') or line.strip().startswith('-'):
                # 保存上一个节点
                if current_node:
                    # 添加备注前缀
                    if remark and 'name' in current_node:
                        current_node['name'] = f"{remark}-{current_node['name']}"
                    
                    # 确保udp字段存在
                    if 'udp' not in current_node:
                        current_node['udp'] = True
                    
                    proxies.append(clean_config(current_node))
                
                # 开始新节点
                current_node = {}
                in_node = True
                indent_level = len(line) - len(line.lstrip())
                line = line.strip()
                
                # 如果是紧凑格式：- {name: xxx, server: xxx}
                if line.startswith('- {') and '}' in line:
                    node_str = line[line.find('{'):line.rfind('}')+1]
                    try:
                        node_data = yaml.safe_load(node_str)
                        if isinstance(node_data, dict):
                            current_node = node_data
                    except:
                        pass
                
            elif in_node and line.strip():
                # 处理节点属性
                current_indent = len(line) - len(line.lstrip())
                if current_indent > indent_level:
                    # 这是节点属性的行
                    line_stripped = line.strip()
                    if ':' in line_stripped:
                        key, value = line_stripped.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # 处理YAML值
                        if value.lower() == 'true':
                            value = True
                        elif value.lower() == 'false':
                            value = False
                        elif value.isdigit():
                            value = int(value)
                        
                        current_node[key] = value
        
        # 处理最后一个节点
        if current_node:
            # 添加备注前缀
            if remark and 'name' in current_node:
                current_node['name'] = f"{remark}-{current_node['name']}"
            
            # 确保udp字段存在
            if 'udp' not in current_node:
                current_node['udp'] = True
            
            proxies.append(clean_config(current_node))
        
        if proxies:
            print(f"    从多行YAML解析到 {len(proxies)} 个节点")
    
    return proxies

def process_subscription_content(content, remark=None):
    """处理订阅内容"""
    if not content:
        return []
    
    proxies = []
    
    # 首先尝试解析为完整的Clash YAML配置
    if is_clash_yaml_content(content):
        print(f"    检测到Clash YAML格式，尝试解析...")
        # 尝试完整解析
        clash_proxies = parse_clash_yaml_content(content, remark)
        if clash_proxies:
            proxies.extend(clash_proxies)
            return proxies
        
        # 如果完整解析失败，尝试提取YAML节点
        yaml_proxies = extract_yaml_proxies_from_content(content, remark)
        if yaml_proxies:
            proxies.extend(yaml_proxies)
            return proxies
    
    # 如果不是完整Clash配置，则按行处理
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # 尝试解析为代理URL
        proxy = parse_proxy_url(line, remark)
        if proxy:
            proxies.append(proxy)
            continue
        
        # 尝试解析为紧凑格式的Clash YAML节点
        if line.startswith('- ') and '{' in line and '}' in line:
            proxy = parse_clash_yaml_node(line, remark)
            if proxy:
                proxies.append(proxy)
                continue
    
    return proxies

def generate_clash_config_with_groups(all_nodes, proxy_groups, filename, source_content, 
                                     success_count, total_count, failed_urls, combined_stats):
    """生成带分组功能的Clash配置 - 终极简化版"""
    
    # 获取当前时间
    update_time = get_beijing_time()
    
    # 生成分割线
    divider = "# " + "-" * 50 + "\n"
    
    # 生成备注
    comments = f"""# ========================================
# Clash 配置文件 - 终极简化版
# ========================================
# 
# 更新时间（东八区北京时间）: {update_time}
# 仓库名称: lzhp529
# 输入源文件: {filename}
# 订阅链接获取情况: {success_count}/{total_count}
{divider}
# 分组统计:
{combined_stats}
{divider}
# 失败的链接:
{failed_urls}
{divider}
# 输入源文件内容:
{source_content}
# 
# ========================================
# 配置说明:
# 1. 统一代理端口: 7890 (HTTP/SOCKS混合)
# 2. 节点选择: 仅包含负载均衡、自动选择、DIRECT
# 3. 负载均衡: 默认策略，自动分配流量
# 4. 自动选择: 选择最低延迟节点
# 5. 分组策略: 按订阅源分组，方便切换
# ========================================
# 配置开始
# ========================================
"""
    
    # 如果没有任何节点，创建测试配置
    if not all_nodes:
        print("  没有有效节点，创建测试配置")
        all_nodes = [{
            'name': '测试节点',
            'type': 'ss',
            'server': 'example.com',
            'port': 443,
            'cipher': 'aes-256-gcm',
            'password': 'password',
            'udp': True
        }]
    
    # Clash配置 - 终极简化版
    config = {
        'mixed-port': 7890,  # 统一使用混合端口
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        
        # DNS设置
        'dns': {
            'enable': True,
            'ipv6': False,
            'listen': '127.0.0.1:53',
            'default-nameserver': ['223.5.5.5', '119.29.29.29'],
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'nameserver': [
                'https://doh.pub/dns-query',
                'https://dns.alidns.com/dns-query'
            ]
        },
        
        # 代理节点
        'proxies': all_nodes[:200],  # 最多200个节点
        
        # 策略组 - 极度简化版
        'proxy-groups': proxy_groups,
        
        # 规则 - 简化路由
        'rules': [
            # 国内域名直连
            'DOMAIN-SUFFIX,cn,DIRECT',
            'DOMAIN-SUFFIX,baidu.com,DIRECT',
            'DOMAIN-SUFFIX,qq.com,DIRECT',
            'DOMAIN-SUFFIX,taobao.com,DIRECT',
            'DOMAIN-SUFFIX,jd.com,DIRECT',
            'DOMAIN-SUFFIX,weibo.com,DIRECT',
            'DOMAIN-SUFFIX,sina.com,DIRECT',
            'DOMAIN-SUFFIX,163.com,DIRECT',
            'DOMAIN-SUFFIX,alibaba.com,DIRECT',
            'DOMAIN-SUFFIX,alipay.com,DIRECT',
            'DOMAIN-SUFFIX,tencent.com,DIRECT',
            'DOMAIN-SUFFIX,bilibili.com,DIRECT',
            'DOMAIN-SUFFIX,zhihu.com,DIRECT',
            
            # GEOIP中国直连
            'GEOIP,CN,DIRECT',
            
            # 最终规则 - 使用节点选择（默认负载均衡）
            'MATCH,节点选择'
        ]
    }
    
    config = clean_config(config)
    
    # 写入文件
    output_dir = '订阅链接'
    os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(output_dir, f'{filename}.yaml')
    
    with open(output_path, 'w', encoding='utf-8') as f:
        # 写入备注
        f.write(comments)
        # 写入配置
        yaml.dump(config, f, 
                 allow_unicode=True, 
                 default_flow_style=False, 
                 sort_keys=False,
                 width=float("inf"))
    
    print(f"  生成配置文件: {output_path}")
    print(f"  包含 {len(all_nodes[:200])} 个节点")
    print(f"  包含 {len(proxy_groups)} 个策略组")
    print(f"  代理端口: 7890 (HTTP/SOCKS混合)")
    
    return len(all_nodes[:200])

def build_proxy_groups(all_nodes, remark_nodes_map):
    """构建策略组配置 - 极度简化版"""
    # 获取所有节点名称
    all_node_names = [node.get('name', f'节点{i+1}') for i, node in enumerate(all_nodes[:200])]
    
    # 基础策略组 - 极度简化版
    proxy_groups = [
        {
            'name': '节点选择',
            'type': 'select',
            'proxies': ['负载均衡', '自动选择', 'DIRECT']  # 只保留这3个选项
        },
        {
            'name': '负载均衡',
            'type': 'load-balance',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'strategy': 'consistent-hashing',
            'proxies': all_node_names
        },
        {
            'name': '自动选择',
            'type': 'url-test',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'tolerance': 50,
            'proxies': all_node_names
        }
    ]
    
    # 为每个有备注的链接创建独立策略组
    for remark, nodes in remark_nodes_map.items():
        if remark and nodes:
            node_names = [node.get('name') for node in nodes if node.get('name')]
            if node_names:
                proxy_groups.append({
                    'name': remark,
                    'type': 'url-test',
                    'url': 'http://www.gstatic.com/generate_204',
                    'interval': 300,
                    'tolerance': 50,
                    'proxies': node_names[:50]  # 最多50个节点
                })
    
    return proxy_groups

def clear_output_directory():
    """清空输出目录"""
    output_dir = '订阅链接'
    
    if os.path.exists(output_dir):
        print(f"清空输出目录: {output_dir}")
        try:
            for filename in os.listdir(output_dir):
                file_path = os.path.join(output_dir, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f"删除文件 {file_path} 失败: {e}")
            print("输出目录已清空")
        except Exception as e:
            print(f"清空目录失败: {e}")
    else:
        os.makedirs(output_dir, exist_ok=True)
        print("创建输出目录")

def read_source_file_content(filepath, url_results):
    """读取源文件内容并添加节点数量"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 创建一个映射，便于查找备注和节点数量
        url_to_remark = {}
        url_to_node_count = {}
        url_to_error = {}
        
        for result in url_results:
            url = result.get('url', '')
            remark = result.get('remark', '')
            node_count = result.get('node_count', 0)
            error_msg = result.get('error', '')
            
            if url:
                url_to_remark[url] = remark
                url_to_node_count[url] = node_count
                if error_msg:
                    url_to_error[url] = error_msg
        
        commented_lines = []
        
        for line in lines:
            line = line.rstrip('\n')
            
            # 检查是否是URL行
            if line.strip() and re.match(r'^https?://', line.strip()):
                url = line.strip()
                remark = url_to_remark.get(url, '')
                node_count = url_to_node_count.get(url, 0)
                error_msg = url_to_error.get(url, '')
                
                # 只添加节点数量行，不添加备注行
                if error_msg:
                    commented_lines.append(f"# {line}")
                    commented_lines.append(f"# 节点数量: 0 (失败原因: {error_msg})")
                else:
                    commented_lines.append(f"# {line}")
                    commented_lines.append(f"# 节点数量: {node_count}")
            elif line.strip().startswith('#'):
                # 注释行直接保留
                commented_lines.append(f"# {line[1:].lstrip()}" if line.startswith('#') else f"# {line}")
            elif line.strip():
                # 其他非空行
                commented_lines.append(f"# {line}")
            else:
                # 空行
                commented_lines.append("#")
        
        return "\n".join(commented_lines)
        
    except Exception as e:
        print(f"读取源文件失败: {e}")
        return "# 无法读取源文件内容"

def generate_combined_stats(remark_stats, remark_failed_stats):
    """生成合并的分组统计信息（成功和失败一起显示）"""
    if not remark_stats and not remark_failed_stats:
        return "#   无分组信息"
    
    stats_lines = []
    
    # 先添加成功的分组
    for remark, count in sorted(remark_stats.items()):
        stats_lines.append(f"#   {remark}: {count} 个节点")
    
    # 再添加失败的分组
    for remark, reason in sorted(remark_failed_stats.items()):
        stats_lines.append(f"#   {remark}: 失败 ({reason})")
    
    return "\n".join(stats_lines)

def main():
    """主函数"""
    print("=" * 70)
    print("自动订阅生成器 - 终极简化版")
    print("仓库: lzhp529")
    print("=" * 70)
    print(f"开始时间（北京时间）: {get_beijing_time()}")
    
    # 清空输出目录
    clear_output_directory()
    
    input_dir = '输入源'
    os.makedirs(input_dir, exist_ok=True)
    
    # 查找输入文件
    txt_files = [f for f in os.listdir(input_dir) if f.endswith('.txt')]
    
    if not txt_files:
        print(f"\n没有找到输入文件，请在 '{input_dir}' 中创建.txt文件")
        print("创建示例文件...")
        example_content = """# 维云云 2年到期
https://vyy.cqsvhb.cn/s/c59454c04c7395f58b5d8165a598ad64

# 机场A 高速稳定
https://example.com/subscribe1.txt

# 免费节点
https://example.com/free.txt
"""
        with open(os.path.join(input_dir, 'example.txt'), 'w', encoding='utf-8') as f:
            f.write(example_content)
        print(f"已创建示例文件: {input_dir}/example.txt")
        txt_files = ['example.txt']
    
    # 处理每个文件
    for filename in txt_files:
        print(f"\n" + "=" * 50)
        print(f"处理文件: {filename}")
        print("=" * 50)
        
        filepath = os.path.join(input_dir, filename)
        
        # 解析源文件，提取带备注的链接
        url_entries = parse_source_file(filepath)
        
        if not url_entries:
            print("  没有找到有效链接")
            continue
        
        total_count = len(url_entries)
        print(f"  找到 {total_count} 个带备注的链接")
        
        # 统计信息
        all_proxies = []
        failed_urls = []
        failed_entries = []  # 保存失败的条目信息
        success_count = 0
        remark_nodes_map = {}  # 按备注分组的成功节点
        remark_stats = {}      # 成功分组统计
        remark_failed_stats = {}  # 失败分组统计
        
        # 判断是否使用并行处理（链接数量多时使用）
        use_parallel = total_count > 5
        
        if use_parallel:
            print(f"  使用并行处理（共{total_count}个链接）")
            # 准备参数
            args_list = [(entry['url'], entry['remark']) for entry in url_entries]
            
            # 使用线程池并行处理
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, total_count)) as executor:
                futures = [executor.submit(fetch_subscription_parallel, args) for args in args_list]
                
                for i, future in enumerate(concurrent.futures.as_completed(futures)):
                    try:
                        result = future.result(timeout=60)  # 每个任务最多60秒
                        
                        if result['success']:
                            all_proxies.extend(result['proxies'])
                            success_count += 1
                            
                            # 按备注分组
                            remark = result['remark']
                            if remark and result['proxies']:
                                if remark not in remark_nodes_map:
                                    remark_nodes_map[remark] = []
                                remark_nodes_map[remark].extend(result['proxies'])
                                
                                # 更新统计
                                remark_stats[remark] = remark_stats.get(remark, 0) + len(result['proxies'])
                            
                            print(f"  [{i+1}/{total_count}] ✅ 成功获取，找到 {len(result['proxies'])} 个节点")
                        else:
                            remark = result['remark']
                            error_msg = result['error_msg']
                            entry_info = result['entry_info']
                            
                            # 添加到失败分组统计
                            if remark:
                                remark_failed_stats[remark] = error_msg
                            
                            failed_urls.append(f"# {remark if remark else '未命名'}: {entry_info['url']} - {error_msg}")
                            failed_entries.append(entry_info)
                            
                            print(f"  [{i+1}/{total_count}] ❌ 失败: {error_msg}")
                        
                        # 保存URL处理结果
                        url_entries[i].update(entry_info)
                        
                    except concurrent.futures.TimeoutError:
                        print(f"  [{i+1}/{total_count}] ⏰ 处理超时")
                        url = url_entries[i]['url']
                        remark = url_entries[i]['remark']
                        failed_urls.append(f"# {remark if remark else '未命名'}: {url} - 处理超时")
                        
                        entry_info = {
                            'url': url,
                            'remark': remark,
                            'node_count': 0,
                            'error': '处理超时'
                        }
                        failed_entries.append(entry_info)
                        url_entries[i].update(entry_info)
                        
                        if remark:
                            remark_failed_stats[remark] = "处理超时"
                    except Exception as e:
                        print(f"  [{i+1}/{total_count}] ⚠️ 处理错误: {str(e)}")
        else:
            # 串行处理
            for i, entry in enumerate(url_entries):
                url = entry['url']
                remark = entry['remark']
                
                print(f"\n  [{i+1}/{total_count}] 处理链接")
                print(f"    链接: {url[:80]}...")
                if remark:
                    print(f"    备注: {remark}")
                
                result = fetch_subscription(url, timeout=30)
                content, success, error_msg = result
                
                entry_info = {
                    'url': url,
                    'remark': remark,
                    'node_count': 0,
                    'error': ''
                }
                
                if success and content:
                    proxies = process_subscription_content(content, remark)
                    if proxies:
                        all_proxies.extend(proxies)
                        success_count += 1
                        
                        # 按备注分组
                        if remark:
                            if remark not in remark_nodes_map:
                                remark_nodes_map[remark] = []
                            remark_nodes_map[remark].extend(proxies)
                            
                            # 更新统计
                            remark_stats[remark] = remark_stats.get(remark, 0) + len(proxies)
                        
                        entry_info['node_count'] = len(proxies)
                        print(f"    ✅ 成功获取，找到 {len(proxies)} 个节点")
                    else:
                        print(f"    ⚠️ 获取成功但未找到有效节点")
                        entry_info['error'] = "无有效节点"
                        
                        # 添加到失败分组统计
                        if remark:
                            remark_failed_stats[remark] = "无有效节点"
                        
                        failed_urls.append(f"# {remark if remark else '未命名'}: {url}")
                        failed_entries.append(entry_info)
                else:
                    error_info = error_msg if error_msg else "未知错误"
                    print(f"    ❌ 失败: {error_info}")
                    entry_info['error'] = error_info
                    
                    # 添加到失败分组统计
                    if remark:
                        remark_failed_stats[remark] = error_info
                    
                    failed_urls.append(f"# {remark if remark else '未命名'}: {url} - {error_info}")
                    failed_entries.append(entry_info)
                
                # 保存URL处理结果，用于生成源文件内容
                url_entries[i].update(entry_info)
                
                # 避免请求过快
                if i < total_count - 1:
                    time.sleep(1)
        
        # 生成失败链接备注
        failed_comments = "\n".join(failed_urls) if failed_urls else "# 无失败链接"
        
        # 去重
        unique_proxies = []
        seen = set()
        
        for proxy in all_proxies:
            if not proxy:
                continue
            
            key = f"{proxy.get('server', '')}:{proxy.get('port', '')}:{proxy.get('type', '')}:{proxy.get('name', '')}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
        
        # 统计信息
        print(f"\n  {'='*30}")
        print(f"  处理完成统计:")
        print(f"    总链接数: {total_count}")
        print(f"    成功获取: {success_count}")
        print(f"    失败链接: {total_count - success_count}")
        print(f"    原始节点: {len(all_proxies)} 个")
        print(f"    去重节点: {len(unique_proxies)} 个")
        
        # 合并分组统计
        combined_stats = generate_combined_stats(remark_stats, remark_failed_stats)
        
        # 按类型统计
        type_stats = {}
        for proxy in unique_proxies:
            proxy_type = proxy.get('type', 'unknown')
            type_stats[proxy_type] = type_stats.get(proxy_type, 0) + 1
        
        if type_stats:
            print(f"    节点类型分布:")
            for proxy_type, count in sorted(type_stats.items()):
                print(f"      {proxy_type}: {count} 个")
        
        # 构建策略组
        proxy_groups = build_proxy_groups(unique_proxies, remark_nodes_map)
        
        # 读取源文件内容（包含节点数量）
        source_content = read_source_file_content(filepath, url_entries)
        
        # 生成配置
        if unique_proxies:
            base_name = os.path.splitext(filename)[0]
            node_count = generate_clash_config_with_groups(
                unique_proxies, 
                proxy_groups,
                base_name, 
                source_content,
                success_count,
                total_count,
                failed_comments,
                combined_stats
            )
            print(f"\n    ✅ 配置文件生成成功")
            print(f"    📊 代理节点: {node_count} 个")
            print(f"    🏷️  成功分组策略组: {len(remark_nodes_map)} 个")
            print(f"    ⚖️  默认策略: 负载均衡")
            print(f"    🔌 代理端口: 7890")
        else:
            print("\n    ⚠️ 没有有效节点，生成空配置")
            # 生成一个空配置，但仍然包含备注
            empty_proxies = []
            empty_groups = build_proxy_groups([], {})
            base_name = os.path.splitext(filename)[0]
            generate_clash_config_with_groups(
                empty_proxies,
                empty_groups,
                base_name,
                source_content,
                success_count,
                total_count,
                failed_comments,
                combined_stats
            )
    
    print(f"\n" + "=" * 70)
    print(f"生成完成！")
    print(f"完成时间（北京时间）: {get_beijing_time()}")
    print("=" * 70)

if __name__ == '__main__':
    main()
