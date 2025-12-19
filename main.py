#!/usr/bin/env python3
import json, time, hashlib, subprocess, urllib.request, urllib.error, sys
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


def rpc_post(url: str, payload: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e}") from e


def md5crypt_openssl(password: str, salt: str) -> str:
    out = subprocess.check_output(["openssl", "passwd", "-1", "-salt", salt, password], text=True).strip()
    if not out.startswith("$1$"):
        raise RuntimeError(f"Unexpected md5-crypt output: {out}")
    return out


def compute_login_hash(username: str, password: str, alg: int, salt: str, nonce: str) -> str:
    if alg != 1:
        raise RuntimeError(f"Unsupported alg={alg} (script supports alg=1).")
    shadow = md5crypt_openssl(password, salt)
    return hashlib.md5(f"{username}:{shadow}:{nonce}".encode()).hexdigest()


def extract_sid(login_resp: Dict[str, Any]) -> str:
    r = login_resp.get("result")
    if isinstance(r, dict):
        for k in ("sid", "ubus_rpc_session", "token"):
            v = r.get(k)
            if isinstance(v, str) and v:
                return v
    return ""


def unwrap_call_result(resp: Dict[str, Any]) -> Any:
    if "result" not in resp:
        raise RuntimeError(f"Missing 'result': {resp}")
    r = resp["result"]
    if isinstance(r, list):
        return r[1] if len(r) >= 2 else (r[0] if r else None)
    return r


def call(url: str, sid: str, obj: str, method: str, args: Dict[str, Any], rid: int) -> Any:
    resp = rpc_post(url, {"jsonrpc": "2.0", "id": rid, "method": "call", "params": [sid, obj, method, args]})
    if "error" in resp:
        raise RuntimeError(f"ubus {obj}.{method} error: {resp['error']}")
    return unwrap_call_result(resp)


def wait_rpc(ip: str, timeout_s: int = 90) -> None:
    url = f"http://{ip}/rpc"
    t0 = time.time()
    while True:
        try:
            rpc_post(url, {"jsonrpc":"2.0","id":1,"method":"challenge","params":{"username":"root"}}, timeout=3)
            return
        except Exception:
            if time.time() - t0 > timeout_s:
                raise RuntimeError(f"{ip}: timeout waiting /rpc")
            time.sleep(2)


def login(ip: str, username: str, password: str) -> Tuple[str, str]:
    url = f"http://{ip}/rpc"
    chal = rpc_post(url, {"jsonrpc":"2.0","id":1,"method":"challenge","params":{"username":username}})
    if "result" not in chal:
        raise RuntimeError(f"{ip}: bad challenge: {chal}")
    alg = int(chal["result"]["alg"])
    salt = chal["result"]["salt"]
    nonce = chal["result"]["nonce"]
    h = compute_login_hash(username, password, alg, salt, nonce)
    resp = rpc_post(url, {"jsonrpc":"2.0","id":2,"method":"login","params":{"username":username,"hash":h}})
    if "error" in resp:
        raise RuntimeError(f"{ip}: login failed: {resp['error']}")
    sid = extract_sid(resp)
    if not sid:
        raise RuntimeError(f"{ip}: SID not found: {resp}")
    return url, sid


# ---------- GL WiFi API ----------
def wifi_get_config(url: str, sid: str) -> Dict[str, Any]:
    raw = call(url, sid, "wifi", "get_config", {}, rid=120)
    if not isinstance(raw, dict):
        raise RuntimeError(f"wifi.get_config unexpected: {raw}")
    return raw


def wifi_set_config(url: str, sid: str, payload: Dict[str, Any]) -> Any:
    return call(url, sid, "wifi", "set_config", payload, rid=121)


def get_band_blocks(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    res = raw.get("res")
    return [x for x in res if isinstance(x, dict)] if isinstance(res, list) else []


def pick_band(blocks: List[Dict[str, Any]], device: str) -> Optional[Dict[str, Any]]:
    return next((b for b in blocks if b.get("device") == device), None)


def read_channels_from_get_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    blocks = get_band_blocks(raw)
    out = {}
    b24 = pick_band(blocks, "radio0")
    b5  = pick_band(blocks, "radio1")
    if b24: out["2.4"] = {"channel": b24.get("channel")}
    if b5:  out["5"]   = {"channel": b5.get("channel")}
    return out


def build_payload(band: Dict[str, Any], iface: Dict[str, Any], new_channel: int) -> Dict[str, Any]:
    # preserve iface + band fields like UI
    return {
        "iface_name": iface.get("name"),
        "ssid": iface.get("ssid"),
        "encryption": iface.get("encryption"),
        "key": iface.get("key", ""),
        "hidden": iface.get("hidden", False),
        "enabled": iface.get("enabled", True),
        "guest": iface.get("guest", False),

        "device": band.get("device"),
        "channel": int(new_channel),
        "hwmode": band.get("hwmode"),
        "htmode": band.get("htmode"),
        "txpower": band.get("txpower", "Max"),
    }


# ---------- Persist helpers (AUTO-PROBE) ----------
def ubus_list(url: str, sid: str, path: Optional[str] = None) -> Dict[str, Any]:
    """
    Try ubus.list. Some firmwares support: ubus.list { "path": "wifi" }
    Others ignore args.
    """
    args = {} if path is None else {"path": path}
    return call(url, sid, "ubus", "list", args, rid=200)


def collect_candidate_calls(ubus_listing: Any) -> List[Tuple[str, str]]:
    """
    ubus.list may return dict of {object: {methods...}} or list, varies.
    We'll extract (obj, method) pairs heuristically for wifi-related objects.
    """
    pairs: List[Tuple[str, str]] = []

    if isinstance(ubus_listing, dict):
        for obj, v in ubus_listing.items():
            if not isinstance(obj, str):
                continue
            if "wifi" not in obj and "wireless" not in obj and "gl" not in obj:
                continue
            # v could be dict of methods or list
            if isinstance(v, dict):
                for m in v.keys():
                    if isinstance(m, str):
                        pairs.append((obj, m))
            elif isinstance(v, list):
                for m in v:
                    if isinstance(m, str):
                        pairs.append((obj, m))

    return pairs


def try_persist_methods(url: str, sid: str, device: str, channel: int) -> List[str]:
    """
    Try a bunch of common persist/apply methods.
    Return list of methods that succeeded.
    """
    successes: List[str] = []

    # 1) First, attempt to discover via ubus.list (if available)
    discovered: List[Tuple[str, str]] = []
    try:
        listing = ubus_list(url, sid, None)
        discovered = collect_candidate_calls(listing)
    except Exception:
        discovered = []

    # 2) Deterministic candidates (safe: if method missing -> handled)
    # Reload methods don't need channel args - they just reload current config
    reload_methods = [
        ("wifi", "reload"),
        ("wifi", "restart"),
        ("network.wireless", "reload"),
        ("network", "reload"),
        ("network.wireless", "up"),
        ("network.wireless", "down"),
        ("wireless", "reload"),
    ]
    
    # Save/commit methods that might persist config
    save_methods = [
        ("uci", "commit"),
        ("wifi", "save"),
        ("wifi", "apply"),
        ("network.wireless", "commit"),
    ]
    
    # Methods that need channel/device args
    set_methods = [
        ("wifi", "set_channel"),
        ("wifi", "set_radio"),
        ("wifi", "set_device"),
        ("wifi", "set_band"),
        ("wifi", "set"),
        ("wireless", "set_channel"),
        ("network.wireless", "set_channel"),
    ]

    # Merge: discovered first (more likely correct), then deterministic
    tried = []
    for obj, m in discovered:
        if (obj, m) not in tried:
            tried.append((obj, m))
    
    # Add set methods
    for obj, m in set_methods:
        if (obj, m) not in tried:
            tried.append((obj, m))
    
    # Try set methods with channel args
    arg_shapes = [
        {"device": device, "channel": int(channel)},
        {"radio": device, "channel": int(channel)},
        {"band": "5G" if device == "radio1" else "2G", "channel": int(channel)},
        {"channel": int(channel)},
        {},
    ]

    for obj, m in tried:
        for args in arg_shapes:
            try:
                call(url, sid, obj, m, args, rid=210)
                successes.append(f"{obj}.{m} {args}")
                break
            except Exception:
                continue
    
    # Try save/commit methods first (they persist config)
    for obj, m in save_methods:
        if (obj, m) in tried:
            continue
        try:
            call(url, sid, obj, m, {}, rid=212)
            successes.append(f"{obj}.{m} {{}}")
        except Exception:
            continue
    
    # Try reload methods separately (no channel args needed)
    for obj, m in reload_methods:
        if (obj, m) in tried:
            continue
        # Try with device arg, then without
        for args in [{"device": device}, {}]:
            try:
                call(url, sid, obj, m, args, rid=211)
                successes.append(f"{obj}.{m} {args}")
                break
            except Exception:
                continue

    return successes


def reload_wifi_after_config(url: str, sid: str, device: str) -> None:
    """Try to reload/restart wifi after config change to persist it."""
    reload_methods = [
        ("wifi", "reload", {}),
        ("wifi", "reload", {"device": device}),
        ("network.wireless", "reload", {}),
        ("network.wireless", "reload", {"device": device}),
        ("network", "reload", {}),
    ]
    for obj, method, args in reload_methods:
        try:
            call(url, sid, obj, method, args, rid=130)
            break  # If one succeeds, we're done
        except Exception:
            continue


def set_band_channel(url: str, sid: str, band: Dict[str, Any], channel: int) -> None:
    # call set_config for ALL ifaces in this band (default + guest)
    ifaces = band.get("ifaces", [])
    if not isinstance(ifaces, list) or not ifaces:
        raise RuntimeError(f"No ifaces for {band.get('device')}")
    for iface in ifaces:
        if isinstance(iface, dict):
            p = build_payload(band, iface, int(channel))
            if not p.get("iface_name"):
                continue
            wifi_set_config(url, sid, p)
    
    # Note: We don't reload here anymore - let it be handled after all configs are set


def set_channels_on_router(item: Dict[str, Any]) -> Dict[str, Any]:
    ip = item["ip"]
    username = item.get("username", "root")
    password = item["password"]
    wifi_req = item.get("wifi", {})
    ch_24 = wifi_req.get("ch_24")
    ch_5  = wifi_req.get("ch_5")

    wait_rpc(ip)
    url, sid = login(ip, username, password)

    before_raw = wifi_get_config(url, sid)
    before = read_channels_from_get_config(before_raw)

    blocks = get_band_blocks(before_raw)
    b24 = pick_band(blocks, "radio0")
    b5  = pick_band(blocks, "radio1")

    # Apply runtime set_config (and maybe persist if firmware does it)
    if ch_24 is not None:
        if not b24:
            raise RuntimeError(f"{ip}: radio0 not found")
        set_band_channel(url, sid, b24, int(ch_24))

    if ch_5 is not None:
        if not b5:
            raise RuntimeError(f"{ip}: radio1 not found")
        set_band_channel(url, sid, b5, int(ch_5))

    # Try persist/apply methods after all configs are set
    persist_success = []
    if ch_5 is not None:
        # First try reload to persist 5G changes
        reload_wifi_after_config(url, sid, "radio1")
        time.sleep(0.5)
        # Then try other persist methods
        persist_success = try_persist_methods(url, sid, "radio1", int(ch_5))
    elif ch_24 is not None:
        # Try reload for 2.4G as well
        reload_wifi_after_config(url, sid, "radio0")
        time.sleep(0.5)

    # Wait longer for changes to take effect, especially if persist methods didn't work
    # If persist methods succeeded (non-empty list), we can wait less
    if ch_5 is not None:
        wait_time = 4.0 if not persist_success else 2.5
    elif ch_24 is not None:
        wait_time = 2.0
    else:
        wait_time = 1.0
    time.sleep(wait_time)
    after_raw = wifi_get_config(url, sid)
    after = read_channels_from_get_config(after_raw)

    ok = True
    if ch_24 is not None and str(after.get("2.4", {}).get("channel")) != str(int(ch_24)):
        ok = False
    if ch_5 is not None and str(after.get("5", {}).get("channel")) != str(int(ch_5)):
        ok = False

    status = call(url, sid, "system", "get_status", {}, rid=50)

    return {
        "ip": ip,
        "ok": ok,
        "before_get_config": before,
        "after_get_config": after,
        "persist_attempts_success": persist_success,
        "status": status,
    }


def load_inventory(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        inv = json.load(f)
    if "routers" not in inv or not isinstance(inv["routers"], list):
        raise RuntimeError("inventory.json must contain {\"routers\": [ ... ]}")
    return inv["routers"]


def print_progress_bar(completed: int, total: int, prefix: str = "Progress", length: int = 30):
    """Print a progress bar."""
    if total == 0:
        return
    percent = completed / total
    filled = int(length * percent)
    bar = "█" * filled + "░" * (length - filled)
    percent_str = f"{percent * 100:.1f}%"
    print(f"{prefix}: [{bar}] {percent_str} ({completed}/{total})", file=sys.stderr, flush=True)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="GL mass WiFi channel setter with persist auto-probe.")
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--workers", type=int, default=8, help="Number of parallel workers (default: 8)")
    args = ap.parse_args()

    routers = load_inventory(args.inventory)
    total = len(routers)
    results = []
    completed = 0

    print(f"Processing {total} router(s) with {args.workers} worker(s)...", file=sys.stderr)
    # Show initial progress bar (0%)
    print_progress_bar(0, total)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(set_channels_on_router, r): r for r in routers}

        for fut in as_completed(futs):
            r = futs[fut]
            completed += 1
            ip = r.get("ip", "unknown")
            
            try:
                result = fut.result()
                results.append(result)
                status = "✓" if result.get("ok", False) else "✗"
                print(f"[{completed}/{total}] {status} {ip}", file=sys.stderr, flush=True)
            except Exception as e:
                results.append({"ip": ip, "ok": False, "error_type": type(e).__name__, "error": str(e)})
                # Extract meaningful error message (after IP if present, otherwise use type)
                error_str = str(e)
                if ":" in error_str and ip in error_str:
                    # Take part after IP address
                    error_msg = error_str.split(":", 1)[1].strip()
                else:
                    error_msg = type(e).__name__
                print(f"[{completed}/{total}] ✗ {ip} - ERROR: {error_msg}", file=sys.stderr, flush=True)
            
            # Update progress bar
            print_progress_bar(completed, total)

    print("", file=sys.stderr)
    print("Done!", file=sys.stderr)
    results.sort(key=lambda x: x.get("ip", ""))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
