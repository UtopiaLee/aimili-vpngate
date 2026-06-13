#!/usr/bin/env python3
from __future__ import annotations
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import threading
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "vpngate_data"
IP_CACHE_FILE = DATA_DIR / "ip_cache.json"
UI_AUTH_FILE = DATA_DIR / "ui_auth.json"

# Scamalytics fraud-score API (optional). Read from ui_auth.json first (set via
# the web admin panel), falling back to environment variables. The key never
# enters the repo. Without it, purity falls back to the free sources.
SCAMALYTICS_HOST = os.environ.get("SCAMALYTICS_HOST", "api13.scamalytics.com")


def get_scamalytics_config() -> tuple[str, str, str]:
    """Return (user, key, host). UI config takes precedence over env vars."""
    user = os.environ.get("SCAMALYTICS_USER", "")
    key = os.environ.get("SCAMALYTICS_KEY", "")
    host = SCAMALYTICS_HOST
    try:
        if UI_AUTH_FILE.exists():
            cfg = json.loads(UI_AUTH_FILE.read_text(encoding="utf-8"))
            user = cfg.get("scamalytics_user") or user
            key = cfg.get("scamalytics_key") or key
            host = cfg.get("scamalytics_host") or host
    except Exception:
        pass
    return user, key, host


# Cache TTLs (seconds). Purity changes slowly, so a long TTL keeps API usage
# near zero — well under free quotas. Override via env if needed.
IP_CACHE_TTL = int(os.environ.get("IP_CACHE_TTL", str(7 * 24 * 3600)))
PURITY_CACHE_TTL = int(os.environ.get("PURITY_CACHE_TTL", str(30 * 24 * 3600)))

ip_cache_lock = threading.RLock()

COUNTRY_TRANSLATIONS = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡",
}

def get_upstream_proxy() -> tuple[str | None, str | None, int | None]:
    """
    Returns (proxy_type, host, port) from environment variables.
    proxy_type is 'socks' or 'http'.
    """
    socks_env = os.environ.get("OPENVPN_UPSTREAM_SOCKS")
    if socks_env:
        if "://" in socks_env:
            parsed = urllib.parse.urlsplit(socks_env)
            if parsed.hostname and parsed.port:
                return "socks", parsed.hostname, parsed.port
        else:
            parts = socks_env.split(":")
            if len(parts) == 2:
                return "socks", parts[0], int(parts[1])
            elif len(parts) == 1:
                return "socks", parts[0], 10808

    http_env = os.environ.get("OPENVPN_UPSTREAM_HTTP")
    if http_env:
        if "://" in http_env:
            parsed = urllib.parse.urlsplit(http_env)
            if parsed.hostname and parsed.port:
                return "http", parsed.hostname, parsed.port
        else:
            parts = http_env.split(":")
            if len(parts) == 2:
                return "http", parts[0], int(parts[1])
            elif len(parts) == 1:
                return "http", parts[0], 10808

    for env_name in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"]:
        val = os.environ.get(env_name)
        if not val:
            continue
        if "://" in val:
            parsed = urllib.parse.urlsplit(val)
            ptype = "socks" if parsed.scheme.startswith("socks") else "http"
            if parsed.hostname and parsed.port:
                return ptype, parsed.hostname, parsed.port
        else:
            parts = val.split(":")
            if len(parts) == 2:
                return "http", parts[0], int(parts[1])
    return None, None, None

def is_config_tcp(config_text: str) -> bool:
    try:
        for line in config_text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            parts = line.split()
            if parts[0].lower() == "proto" and len(parts) >= 2:
                if "tcp" in parts[1].lower():
                    return True
            elif parts[0].lower() == "remote" and len(parts) >= 4:
                if "tcp" in parts[3].lower():
                    return True
    except Exception:
        pass
    return False

def parse_remote(config_text: str, fallback_ip: str = "") -> tuple[str, int, str]:
    remote_host = fallback_ip
    remote_port = 0
    proto = "unknown"
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if parts[0].lower() == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        elif parts[0].lower() == "remote" and len(parts) >= 3:
            remote_host = parts[1]
            remote_port = int(parts[2]) if parts[2].isdigit() else 0
    return remote_host, remote_port, proto

def get_physical_interface() -> str | None:
    try:
        res = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            routes = []
            for line in res.stdout.splitlines():
                if line.startswith("default via"):
                    parts = line.split()
                    try:
                        gw = parts[2]
                        dev = parts[parts.index("dev") + 1]
                        metric = 0
                        if "metric" in parts:
                            metric = int(parts[parts.index("metric") + 1])
                        routes.append((gw, dev, metric))
                    except (ValueError, IndexError):
                        continue
            if routes:
                routes.sort(key=lambda x: x[2], reverse=True)
                for gw, dev, metric in routes:
                    if not dev.startswith(("tun", "tap", "wg", "ppp")):
                        return dev
                return routes[0][1]
    except Exception:
        pass
    return None

def tcp_latency_ms(host: str, port: int, dev: str | None = None) -> int:
    started = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(5)
        if dev:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode("utf-8"))
            except OSError:
                pass
        s.connect((host, port))
        return max(1, int((time.time() - started) * 1000))
    except OSError:
        return 0
    finally:
        try:
            s.close()
        except Exception:
            pass

def ping_latency_ms(host: str, port: int, fallback_ping: int = 0) -> int:
    dev = get_physical_interface()
    # 1. Try ping with interface binding
    if dev:
        try:
            cmd = ["ping", "-c", "1", "-W", "2", "-I", dev, host]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2
            )
            if res.returncode == 0:
                match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
                if match:
                    val = int(float(match.group(1)))
                    if val > 0:
                        return val
        except Exception:
            pass

    # 2. Try ping without interface binding
    try:
        cmd = ["ping", "-c", "1", "-W", "2", host]
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2
        )
        if res.returncode == 0:
            match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
            if match:
                val = int(float(match.group(1)))
                if val > 0:
                    return val
    except Exception:
        pass

    # 3. Try TCP latency check
    tcp_val = tcp_latency_ms(host, port, dev)
    if tcp_val > 0:
        return tcp_val

    # 4. Fallback
    if fallback_ping > 0:
        return fallback_ping
    return 0

def check_and_fix_dns() -> None:
    """
    Checks if DNS resolution is broken in WSL.
    If names fail but direct IP connections work, appends public DNS nameservers to /etc/resolv.conf.
    """
    try:
        socket.gethostbyname("www.vpngate.net")
        return
    except socket.gaierror:
        pass

    network_ok = False
    for ip in ["8.8.8.8", "1.1.1.1"]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(2)
            s.connect((ip, 53))
            network_ok = True
            break
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    if not network_ok:
        return

    resolv_file = Path("/etc/resolv.conf")
    if resolv_file.exists():
        try:
            content = resolv_file.read_text(encoding="utf-8", errors="replace")
            if "nameserver 1.1.1.1" not in content and "nameserver 8.8.8.8" not in content:
                print("[dns_heal] Resolving names failed, but IP network is OK. Appending public DNS to /etc/resolv.conf...", flush=True)
                with open("/etc/resolv.conf", "a", encoding="utf-8") as f:
                    f.write("\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")
        except Exception as e:
            print(f"[dns_heal] Failed to write DNS fallback: {e}", flush=True)

def load_ip_cache() -> dict[str, dict[str, Any]]:
    with ip_cache_lock:
        try:
            if IP_CACHE_FILE.exists():
                return json.loads(IP_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

def save_ip_cache(cache: dict[str, dict[str, Any]]) -> None:
    with ip_cache_lock:
        try:
            DATA_DIR.mkdir(exist_ok=True)
            IP_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

def enrich_ip_info(nodes: list[dict[str, Any]]) -> None:
    # 1. Read cache thread-safely
    with ip_cache_lock:
        cache = load_ip_cache()

    ips_to_query = []
    now = time.time()

    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if not ip:
            continue
        if ip in cache and now - cache[ip].get("cached_at", 0) < IP_CACHE_TTL:
            cached = cache[ip]
            node["owner"] = cached.get("owner", "")
            node["asn"] = cached.get("asn", "")
            node["as_name"] = cached.get("as_name", "")
            node["location"] = cached.get("location", "")
            node["ip_type"] = cached.get("ip_type", "")
            node["quality"] = cached.get("quality", "")
        else:
            if ip not in ips_to_query:
                ips_to_query.append(ip)

    if not ips_to_query:
        return

    # 2. Perform HTTP query outside lock
    new_entries = {}
    chunk_size = 100
    for i in range(0, len(ips_to_query), chunk_size):
        chunk = ips_to_query[i : i + chunk_size]
        payload = json.dumps(chunk).encode("utf-8")
        request = urllib.request.Request(
            "http://ip-api.com/batch?lang=zh-CN&fields=status,message,query,country,regionName,city,isp,org,as,asname,proxy,hosting,mobile",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "vpngate-manager/2.2"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
                for item in data:
                    if item.get("status") != "success":
                        continue
                    query_ip = item.get("query")
                    if not query_ip:
                        continue

                    ip_type = "residential"
                    if item.get("mobile"):
                        ip_type = "mobile"
                    elif item.get("proxy"):
                        ip_type = "proxy"
                    elif item.get("hosting"):
                        ip_type = "hosting"

                    quality = "normal"
                    if item.get("proxy"):
                        quality = "proxy"
                    elif item.get("hosting"):
                        quality = "datacenter"
                    elif item.get("mobile"):
                        quality = "mobile"

                    loc = " ".join(part for part in [item.get("country"), item.get("regionName"), item.get("city")] if part)

                    new_entries[query_ip] = {
                        "owner": item.get("org") or item.get("isp") or "",
                        "asn": item.get("as") or "",
                        "as_name": item.get("asname") or "",
                        "location": loc,
                        "ip_type": ip_type,
                        "quality": quality,
                        "cached_at": now,
                    }
        except Exception as e:
            print(f"[enrich_ip_info] Query failed: {e}", flush=True)

    if not new_entries:
        return

    # 3. Save cache thread-safely (reload & update to avoid overwrite of concurrent queries)
    with ip_cache_lock:
        cache = load_ip_cache()
        cache.update(new_entries)
        save_ip_cache(cache)

    # 4. Enrich nodes with newly queried info
    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if ip in new_entries:
            cached = new_entries[ip]
            node["owner"] = cached.get("owner", "")
            node["asn"] = cached.get("asn", "")
            node["as_name"] = cached.get("as_name", "")
            node["location"] = cached.get("location", "")
            node["ip_type"] = cached.get("ip_type", "")
            node["quality"] = cached.get("quality", "")


PURITY_CACHE_FILE = DATA_DIR / "purity_cache.json"
purity_cache_lock = threading.RLock()


def load_purity_cache() -> dict[str, dict[str, Any]]:
    with purity_cache_lock:
        try:
            if PURITY_CACHE_FILE.exists():
                return json.loads(PURITY_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}


def save_purity_cache(cache: dict[str, dict[str, Any]]) -> None:
    with purity_cache_lock:
        try:
            DATA_DIR.mkdir(exist_ok=True)
            PURITY_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass


def _parse_abuser_level(raw: Any) -> tuple[float, str]:
    """ipapi.is company.abuser_score looks like '0.0039 (Low)' or '1 (Very High)'.
    Return (numeric_score, level_text)."""
    score = 0.0
    level = ""
    try:
        s = str(raw)
        m = re.match(r"\s*([\d.]+)", s)
        if m:
            score = float(m.group(1))
        lm = re.search(r"\(([^)]+)\)", s)
        if lm:
            level = lm.group(1).strip()
    except Exception:
        pass
    return score, level


def _fetch_json(url: str, timeout: float = 8.0) -> dict[str, Any]:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "vpngate-manager/2.2"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _compute_purity(ipapi: dict[str, Any], pxchk: dict[str, Any], ipapi_com: dict[str, Any], sca: dict[str, Any] | None = None) -> dict[str, Any]:
    """Aggregate free sources into a 0-100 purity score, modelled on the
    iprisk.top weighting. Higher score = cleaner. Optionally includes
    Scamalytics fraud score when an API key is configured. Returns score, level,
    flags and a per-item breakdown (each item: name, got, max, note)."""
    company = ipapi.get("company") or {}
    asn = ipapi.get("asn") or {}
    abuser_score, abuser_level = _parse_abuser_level(company.get("abuser_score"))
    sca = sca or {}
    sca_block = sca.get("scamalytics") or {}
    sca_score = sca_block.get("scamalytics_score")
    try:
        sca_score = int(sca_score)
    except (TypeError, ValueError):
        sca_score = -1
    sca_proxy = sca_block.get("scamalytics_proxy") or {}

    is_tor = bool(ipapi.get("is_tor")) or str(pxchk.get("type", "")).upper() == "TOR"
    px_type = str(pxchk.get("type", ""))
    px_is_proxy = str(pxchk.get("proxy", "")).lower() == "yes"
    px_risk = pxchk.get("risk")
    try:
        px_risk = int(px_risk)
    except (TypeError, ValueError):
        px_risk = -1
    # VPN 以 proxycheck 的 type 为准(ipapi 的 is_vpn 误报多), scamalytics 辅助
    is_vpn = px_type.upper() in ("VPN", "OPENVPN", "WIREGUARD") or "vpn" in px_type.lower() or bool(sca_proxy.get("is_vpn"))
    is_proxy = px_is_proxy or bool(ipapi.get("is_proxy")) or bool(ipapi_com.get("proxy"))
    is_datacenter = bool(ipapi.get("is_datacenter")) or bool(ipapi_com.get("hosting")) or bool(sca_proxy.get("is_datacenter"))
    ip_type_str = str(company.get("type") or asn.get("type") or "").lower()
    is_isp = ip_type_str == "isp" and not is_datacenter

    detail = []
    score = 0

    # IP 类型判定 (40): ISP/住宅满分, 机房大扣分
    if is_isp:
        got = 40; note = "住宅/ISP"
    elif is_datacenter:
        got = 12; note = "机房 IP"
    elif ip_type_str == "business":
        got = 28; note = "商业网络"
    else:
        got = 24; note = "类型未知"
    score += got; detail.append({"name": "IP类型", "got": got, "max": 40, "note": note})

    # Tor 检测 (8)
    got = 0 if is_tor else 8
    score += got; detail.append({"name": "Tor暗网", "got": got, "max": 8, "note": "Tor出口" if is_tor else "非Tor"})

    # VPN 检测 (10)
    got = 2 if is_vpn else 10
    score += got; detail.append({"name": "VPN检测", "got": got, "max": 10, "note": f"命中({px_type})" if is_vpn else "未命中"})

    # 代理检测 (10)
    got = 3 if is_proxy else 10
    score += got; detail.append({"name": "代理检测", "got": got, "max": 10, "note": "命中" if is_proxy else "无代理"})

    # proxycheck 风险分 (12): risk 越高扣越多
    if px_risk < 0:
        got = 8; note = "无数据"
    else:
        got = max(0, round(12 * (1 - px_risk / 100.0)))
        note = f"risk={px_risk}"
    score += got; detail.append({"name": "代理风险", "got": got, "max": 12, "note": note})

    # 滥用历史 (8): abuser_score 0..1, 越高越脏
    got = max(0, round(8 * (1 - min(1.0, abuser_score))))
    score += got; detail.append({"name": "滥用历史", "got": got, "max": 8, "note": abuser_level or f"{abuser_score:.3f}"})

    # Scamalytics 欺诈分 (7): 0-100, 越高越脏。无 key 时给满分(不惩罚)
    if sca_score < 0:
        got = 7; note = "未启用"
    else:
        got = max(0, round(7 * (1 - sca_score / 100.0)))
        note = f"欺诈{sca_score}"
    score += got; detail.append({"name": "欺诈评分", "got": got, "max": 7, "note": note})

    # 数据中心标记 (5)
    got = 0 if is_datacenter else 5
    score += got; detail.append({"name": "数据中心", "got": got, "max": 5, "note": "是" if is_datacenter else "否"})

    # 关键风险信号封顶: 命中明确的高危信号时大幅压低总分,
    # 避免坏 IP 因基础分(IP类型等)虚高而被误判为可用。
    if is_tor:
        score = min(score, 25)  # Tor 出口 -> 高危
    elif is_proxy and px_risk >= 80:
        score = min(score, 40)  # 高风险代理
    elif sca_score >= 90:
        score = min(score, 55)  # Scamalytics 判极高欺诈
    elif is_vpn or (is_proxy and px_risk >= 50):
        score = min(score, 60)  # VPN/中风险代理 -> 至多"有风险"

    score = max(0, min(100, int(round(score))))
    if score >= 85:
        level = "纯净"
    elif score >= 65:
        level = "良好"
    elif score >= 45:
        level = "有风险"
    else:
        level = "高危"

    return {
        "purity_score": score,
        "purity_level": level,
        "purity_detail": detail,
        "is_tor": is_tor,
        "is_proxy": is_proxy,
        "is_vpn": is_vpn,
        "is_abuser": abuser_score >= 0.1,
        "px_risk": px_risk,
    }


def enrich_purity(nodes: list[dict[str, Any]]) -> None:
    """Aggregate ipapi.is + proxycheck.io + ip-api.com into a 0-100 purity score
    (modelled on iprisk.top). Attaches purity_score, purity_level, purity_detail
    and is_tor/is_proxy/is_vpn flags. Cached 7 days. Failures are silent."""
    fields = ["purity_score", "purity_level", "purity_detail", "is_tor", "is_proxy", "is_vpn", "is_abuser", "px_risk"]
    with purity_cache_lock:
        cache = load_purity_cache()
    now = time.time()
    to_query = []
    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if not ip:
            continue
        c = cache.get(ip)
        if c and now - c.get("cached_at", 0) < PURITY_CACHE_TTL and "purity_detail" in c:
            for f in fields:
                if f in c:
                    node[f] = c[f]
        elif ip not in to_query:
            to_query.append(ip)

    new_entries: dict[str, dict[str, Any]] = {}
    sca_user, sca_key, sca_host = get_scamalytics_config()
    for ip in to_query:
        try:
            qip = urllib.parse.quote(ip)
            ipapi = _fetch_json(f"https://api.ipapi.is/?q={qip}")
            pxchk_raw = _fetch_json(f"https://proxycheck.io/v2/{qip}?vpn=1&risk=1")
            pxchk = pxchk_raw.get(ip, {}) if isinstance(pxchk_raw, dict) else {}
            ipapi_com = _fetch_json(f"http://ip-api.com/json/{qip}?fields=proxy,hosting,mobile,query")
            sca = {}
            if sca_user and sca_key:
                sca = _fetch_json(
                    f"https://{sca_host}/v3/{sca_user}/?key={sca_key}&ip={qip}"
                )
            if not ipapi and not pxchk and not ipapi_com:
                continue  # 免费源全失败,不写缓存,下次重试
            result = _compute_purity(ipapi, pxchk, ipapi_com, sca)
            result["cached_at"] = now
            new_entries[ip] = result
        except Exception as e:
            print(f"[enrich_purity] Query failed for {ip}: {e}", flush=True)

    if not new_entries:
        return

    with purity_cache_lock:
        cache = load_purity_cache()
        cache.update(new_entries)
        save_purity_cache(cache)

    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if ip in new_entries:
            for f in fields:
                if f in new_entries[ip]:
                    node[f] = new_entries[ip][f]