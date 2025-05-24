import streamlit as st
import socket
import pandas as pd
import requests
import time
import json
import pdfkit
import io

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = "bc9e34bf9ca46dae4ab235e8de75ffe28828c25ded421ce4781cbbcd75389362209914a80052fe2c"
WKHTMLTOPDF_PATH   = "/usr/bin/wkhtmltopdf"  # adjust if wkhtmltopdf is elsewhere

st.set_page_config(page_title="🛡️ Cyber Scanner", layout="wide")

# ──────────────────────────────────────────────────────────────────────────────
# Custom CSS
# ──────────────────────────────────────────────────────────────────────────────
st.markdown("""
    <style>
        body, .stApp { font-family: 'Segoe UI', sans-serif; background-color: #f5f7fa; }
        .center-title { text-align: center; font-size: 36px; font-weight: bold; margin-bottom: 10px; }
        .center-subtitle { text-align: center; font-size: 22px; margin-bottom: 30px; }
        .stTextArea label { font-size: 24px !important; font-weight: bold !important; }
        textarea { font-size: 22px !important; height: 80px !important; font-weight: bold; }
        .stButton > button {
            width: 100% !important; font-size: 22px !important;
            padding: 14px 24px; font-weight: bold;
            background-color: #2d6cdf; color: white; border-radius: 6px;
        }
        .stButton > button:hover { background-color: #1b4eb3; }
        .box {
            border: 1px solid #ccc; border-radius: 10px;
            padding: 20px; background-color: #fff;
            box-shadow: 0 2px 6px rgba(0,0,0,0.05);
            font-size: 20px; margin-top: 10px;
        }
        table { width:100%; font-size:20px; border-collapse: collapse; }
        th, td { padding:10px; border-bottom:1px solid #ddd; text-align:left; }
        th { background-color:#f0f0f0; }
    </style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# Title & Subtitle
# ──────────────────────────────────────────────────────────────────────────────
st.markdown("<div class='center-title'>🛡️ Cyber Scanner – Domain/IP Intelligence Platform</div>", unsafe_allow_html=True)
st.markdown("<div class='center-subtitle'>Analyze domains or IPs for vulnerabilities, ports, geo info, and threats.</div>", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# Input & Action Buttons
# ──────────────────────────────────────────────────────────────────────────────
host_input = st.text_area("🔍 Enter a domain or IP to scan:")

col1, col2, col3, col4, col5, col6 = st.columns(6)
with col1: ping_clicked   = st.button("📶 Ping")
with col2: geo_clicked    = st.button("🌍 Geo-IP")
with col3: scan_clicked   = st.button("🔎 Port Scan")
with col4: vuln_clicked   = st.button("🛡️ Vulnerability")
with col5: threat_clicked = st.button("🚨 Threat Check")
with col6: run_all        = st.button("▶️ Run All")

# ──────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ──────────────────────────────────────────────────────────────────────────────
def ping_host(ip):
    times = []
    for _ in range(5):
        try:
            start = time.time()
            socket.create_connection((ip, 80), timeout=2)
            times.append((time.time() - start) * 1000)
        except:
            times.append(None)
    valid = [t for t in times if t is not None]
    if valid:
        avg = round(sum(valid) / len(valid), 2)
        return f"Pinged 5 times. Avg latency: {avg} ms", times
    return "Host unreachable or timed out.", times

def geo_ip_lookup(ip):
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
            timeout=5)
        return r.json()
    except:
        return {"status":"fail","message":"Geo-IP lookup failed"}

def scan_ports(ip):
    results = []
    services = {
        21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
        80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",3389:"RDP"
    }
    for port, svc in services.items():
        try:
            with socket.socket() as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    results.append({"Port":port,"Service":svc,"Status":"Open"})
        except:
            pass
    return pd.DataFrame(results)

def assess_vulnerability(df):
    return min(len(df), 5)

def lookup_abuse(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key":ABUSEIPDB_API_KEY,"Accept":"application/json"},
            params={"ipAddress":ip,"maxAgeInDays":90}, timeout=5)
        d = r.json().get("data",{})
        return {
            "Country":d.get("countryCode","N/A"),
            "Abuse Score":d.get("abuseConfidenceScore",0),
            "Total Reports":d.get("totalReports",0),
            "VPN Hint": "No VPN/proxy detected" if not d.get("isPublicProxy",False)
                        else "Possible VPN/proxy detected"
        }
    except:
        return {"error":"Threat lookup failed"}

def assess_threat_score(score, reports):
    if score>=80 or reports>100: return 5
    if score>=50 or reports>50:   return 4
    if score>=20 or reports>10:   return 3
    if score>=5:                  return 2
    return 1

def generate_export_buttons(host, ip, results):
    # Display target: domain/ip or just ip
    display = f"{host}/{ip}" if host != ip else ip

    geo = results.get("geo", {})

    # Build HTML without emojis, with slightly smaller headers
    html = f"""
    <html><head><style>
    body{{font-family:'Segoe UI',sans-serif;background:#f5f7fa;}}
    h1{{font-size:24px;text-align:center;margin-bottom:5px;}}
    h3{{font-size:18px;text-align:center;margin-top:0;}}
    h2{{font-size:20px;margin-bottom:10px;}}
    .box{{border:1px solid #ccc;border-radius:10px;padding:15px;
           background:#fff;box-shadow:0 2px 6px rgba(0,0,0,0.05);margin:15px 0;}}
    table{{width:100%;border-collapse:collapse;}}
    th,td{{padding:8px;border-bottom:1px solid #ddd;text-align:left;}}
    th{{background:#f0f0f0;}}
    </style></head><body>
      <h1>Cyber Scanner - Report</h1>
      <h3>Scanned Target: {display}</h3>

      <div class="box">
        <h2>Ping</h2>
        <p>{results['ping']['summary']}</p>
        <ul>
          {"".join(f"<li>Attempt {i+1}: {t:.2f} ms</li>" if t else f"<li>Attempt {i+1}: Failed</li>"
                    for i,t in enumerate(results['ping']['latencies_ms']))}
        </ul>
      </div>

      <div class="box">
        <h2>Geo-IP</h2>
        <p>IP: {geo.get('query','')}</p>
        <p>Country: {geo.get('country','')}</p>
        <p>Region: {geo.get('regionName','')}</p>
        <p>City: {geo.get('city','')}</p>
        <p>ZIP: {geo.get('zip','')}</p>
        <p>Lat/Lon: {geo.get('lat','')}, {geo.get('lon','')}</p>
        <p>Timezone: {geo.get('timezone','')}</p>
        <p>ISP: {geo.get('isp','')}</p>
        <p>Org: {geo.get('org','')}</p>
        <p>ASN: {geo.get('as','')}</p>
      </div>

      <div class="box">
        <h2>Open Ports</h2>
        <table>
          <tr><th>Port</th><th>Service</th><th>Status</th></tr>
          {"".join(f"<tr><td>{r['Port']}</td><td>{r['Service']}</td><td>{r['Status']}</td></tr>"
                    for r in results['ports'])}
        </table>
      </div>

      <div class="box">
        <h2>Vulnerability Score</h2>
        <p>Risk Score: {results['vuln']['score']} / 5</p>
      </div>

      <div class="box">
        <h2>Threat Check</h2>
        <p>Country: {results['threat']['Country']}</p>
        <p>Abuse Score: {results['threat']['Abuse Score']}</p>
        <p>Total Reports: {results['threat']['Total Reports']}</p>
        <p>VPN Hint: {results['threat']['VPN Hint']}</p>
        <p>Threat Score: {results['threat']['Threat Score']} / 5</p>
      </div>
    </body></html>
    """

    config   = pdfkit.configuration(wkhtmltopdf=WKHTMLTOPDF_PATH)
    pdf_bytes= pdfkit.from_string(html, False, configuration=config)
    buf      = io.BytesIO(pdf_bytes)

    json_data = json.dumps({"Scanned Target":display, **results}, indent=2)

    st.download_button("📥 Download JSON", json_data,
                       file_name="report.json", mime="application/json")
    st.download_button("📥 Download PDF", buf,
                       file_name="report.pdf", mime="application/pdf")


# ──────────────────────────────────────────────────────────────────────────────
# Main Logic
# ──────────────────────────────────────────────────────────────────────────────
if host_input:
    try:
        ip      = socket.gethostbyname(host_input)
        results = {}

        if ping_clicked or run_all:
            summary, times = ping_host(ip)
            logs  = "".join(
                f"<li>Attempt {i+1}: {round(t,2)} ms</li>" if t else f"<li>Attempt {i+1}: Failed</li>"
                for i,t in enumerate(times)
            )
            st.subheader("📶 Ping")
            st.markdown(f"<div class='box'><strong>{summary}</strong><br><ul>{logs}</ul></div>", unsafe_allow_html=True)
            results["ping"] = {"summary": summary, "latencies_ms": times}

        if geo_clicked or run_all:
            geo = geo_ip_lookup(ip)
            if geo.get("status") != "fail":
                st.subheader("🌍 Geo-IP Information")
                st.markdown(f"""
                    <div class='box'>
                        <strong>🌐 IP:</strong> {geo['query']}<br>
                        <strong>📍 Location:</strong> {geo['city']}, {geo['regionName']}, {geo['country']} {geo['zip']}<br>
                        <strong>🕒 Timezone:</strong> {geo['timezone']}<br>
                        <strong>🏢 ISP:</strong> {geo['isp']}<br>
                        <strong>🏢 Org:</strong> {geo['org']}<br>
                        <strong>🛰️ ASN:</strong> {geo['as']}
                    </div>
                """, unsafe_allow_html=True)
                results["geo"] = geo

        if scan_clicked or run_all:
            df = scan_ports(ip)
            st.subheader("🔎 Open Ports")
            if df.empty:
                st.info("✅ No common ports open.")
            else:
                rows = "".join(
                    f"<tr><td>{r['Port']}</td><td>{r['Service']}</td><td>{r['Status']}</td></tr>"
                    for _,r in df.iterrows()
                )
                st.markdown(f"<div class='box'><table><tr><th>Port</th><th>Service</th><th>Status</th></tr>{rows}</table></div>", unsafe_allow_html=True)
            results["ports"] = df.to_dict(orient="records")

        if vuln_clicked or run_all:
            score = assess_vulnerability(scan_ports(ip))
            st.subheader("🛡️ Vulnerability Score")
            st.markdown(f"<div class='box'><strong>Risk Score:</strong> {score} / 5</div>", unsafe_allow_html=True)
            results["vuln"] = {"score": score}

        if threat_clicked or run_all:
            threat = lookup_abuse(ip)
            st.subheader("🚨 Threat Check")
            if "error" in threat:
                st.error("Threat lookup failed.")
            else:
                threat["Threat Score"] = assess_threat_score(threat["Abuse Score"], threat["Total Reports"])
                st.markdown(f"""
                    <div class='box'>
                        <strong>🌍 Country:</strong> {threat['Country']}<br>
                        <strong>⚠️ Abuse Score:</strong> {threat['Abuse Score']}<br>
                        <strong>📋 Total Reports:</strong> {threat['Total Reports']}<br>
                        <strong>🔍 VPN/Proxy:</strong> {threat['VPN Hint']}<br>
                        <strong>📊 Threat Score:</strong> {threat['Threat Score']} / 5
                    </div>
                """, unsafe_allow_html=True)
                results["threat"] = threat

        if run_all:
            generate_export_buttons(host_input, ip, results)

    except socket.gaierror:
        st.error("❌ Invalid domain or IP")
