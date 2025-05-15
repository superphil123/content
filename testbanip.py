ip_field = demisto.args().get("source_ip") or demisto.args().get("ip")

# 從 incident.customFields 嘗試取得 IP（fallback）
if not ip_field:
    incidents = demisto.incidents()
    incident = incidents[0] if incidents and isinstance(incidents, list) and incidents[0] else None

    if incident and isinstance(incident, dict):
        ip_field = incident.get("CustomFields", {}).get("source_ip") or \
                   incident.get("CustomFields", {}).get("sourceip")

if not ip_field:
    return_error("❌ No IP provided or found in arguments or incident fields.")

# 拆分 IP 列表
ip_list = [ip.strip() for ip in ip_field.split(",") if ip.strip()]
blocked = []
not_blocked = []

for ip in ip_list:
    vt_result = demisto.executeCommand("ip", {"ip": ip})

    if isError(vt_result[0]):
        not_blocked.append(f"{ip} (VT error: {vt_result[0]['Contents']})")
        continue

    try:
        vt_data = vt_result[0]["Contents"]["data"]
        malicious = vt_data["attributes"]["last_analysis_stats"].get("malicious", 0)
    except Exception as e:
        not_blocked.append(f"{ip} (parse error: {str(e)})")
        continue

    if malicious > 0:
        res = demisto.executeCommand("fortigate-ban-ip", {
            "ip_address": ip,
            "comment": f"Blocked by XSOAR (VT malicious score: {malicious})"
        })
        if isError(res[0]):
            not_blocked.append(f"{ip} (block error: {res[0]['Contents']})")
        else:
            blocked.append(ip)
    else:
        not_blocked.append(f"{ip} (VT malicious: {malicious})")

# 輸出結果
demisto.results({
    "Type": entryTypes["note"],
    "ContentsFormat": formats["markdown"],
    "Contents": f"""## 🚨 VirusTotal 判斷 + FortiGate 封鎖報告

### ✅ 封鎖成功 IP：
{', '.join(blocked) if blocked else '無'}

### ⚠️ 未封鎖（非惡意或錯誤）：
{', '.join(not_blocked) if not_blocked else '無'}
""",
    "EntryContext": {
        "FortiGate.BlockedIPs": blocked,
        "FortiGate.NotBlockedIPs": not_blocked
    }
})