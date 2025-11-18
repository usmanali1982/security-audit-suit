#!/usr/bin/env python3
import os, sys, json, argparse, glob, shutil
from datetime import datetime
from jinja2 import Template
import plotly.express as px
import pandas as pd

parser = argparse.ArgumentParser()
parser.add_argument("--scan-dir", required=True)
parser.add_argument("--config", required=True)
args = parser.parse_args()

scan_dir = args.scan_dir
out = os.path.join(scan_dir, "final_report")
os.makedirs(out, exist_ok=True)

# simple parsing
trivy = open(os.path.join(scan_dir,"trivy-fs.json")).read() if os.path.exists(os.path.join(scan_dir,"trivy-fs.json")) else ""
high = trivy.count("HIGH")
critical = trivy.count("CRITICAL")
nmap = open(os.path.join(scan_dir,"nmap-local.txt")).read() if os.path.exists(os.path.join(scan_dir,"nmap-local.txt")) else ""
open_ports = nmap.count("open")

df = pd.DataFrame({"metric":["High","Critical","OpenPorts"], "value":[high,critical,open_ports]})
fig = px.bar(df, x='metric', y='value', title='Security Metrics')
chart = fig.to_html(full_html=False, include_plotlyjs='cdn')

template = """<html><head><meta charset='utf-8'><title>Report</title></head><body>
<h1>Security Report</h1>
<p>Generated: {{ now }}</p>
<div>{{ chart|safe }}</div>
<h2>Summary</h2><ul>
<li>High: {{ high }}</li>
<li>Critical: {{ critical }}</li>
<li>Open ports: {{ open_ports }}</li>
</ul>
</body></html>"""

t = Template(template)
html = t.render(now=datetime.utcnow().isoformat(), chart=chart, high=high, critical=critical, open_ports=open_ports)
open(os.path.join(out,"server_report.html"),"w").write(html)
# create PDF if weasyprint installed
try:
    from weasyprint import HTML
    HTML(string=html).write_pdf(os.path.join(out,"server_report.pdf"))
except Exception:
    pass
# copy zap and nikto outputs for serving
for f in glob.glob(os.path.join(scan_dir,"zap","*")):
    shutil.copy2(f, out)
for f in glob.glob(os.path.join(scan_dir,"nikto","*")):
    shutil.copy2(f, out)
print("Report created at", out)
