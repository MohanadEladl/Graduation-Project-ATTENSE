"""
routes/search.py – Search endpoint.

[VULN APP-01] REFLECTED CROSS-SITE SCRIPTING (XSS)
====================================================
The query parameter `q` is rendered into the HTML response with NO
sanitization. We use Jinja's |safe filter to preserve the vulnerability
while still allowing form actions/links to use {{ lab_url(...) }} for
iframe-safe routing.
"""
import json
import logging

from flask import Blueprint, request, render_template_string, current_app
from markupsafe import escape

import containment

logger = logging.getLogger("target.search")
search_bp = Blueprint("search", __name__)

_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<title>Product Search — AcmeCorp</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#c8cdd8;min-height:100vh;}
a{color:#6ea8fe;text-decoration:none;}

.topbar{background:linear-gradient(90deg,#1a1f2e,#252b3b);border-bottom:1px solid rgba(255,255,255,.08);padding:14px 32px;display:flex;align-items:center;gap:12px;}
.topbar .logo{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#6366f1);display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:14px;}
.topbar span{font-size:15px;font-weight:600;color:#e2e8f0;}
.topbar nav{margin-left:auto;display:flex;gap:16px;font-size:13px;}

.container{max-width:800px;margin:0 auto;padding:40px 24px;}
.search-header{margin-bottom:28px;}
.search-header h2{font-size:22px;font-weight:600;color:#e2e8f0;margin-bottom:6px;}
.search-header p{font-size:13px;color:#64748b;}

.search-box{display:flex;gap:8px;margin-bottom:32px;}
.search-box input{flex:1;padding:12px 16px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:10px;color:#e2e8f0;font-size:15px;outline:none;}
.search-box input:focus{border-color:rgba(59,130,246,.5);}
.search-box button{padding:12px 24px;background:linear-gradient(135deg,#3b82f6,#6366f1);border:none;border-radius:10px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;}

.results{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:24px;min-height:120px;}
.results .label{font-size:11px;color:#64748b;letter-spacing:.06em;text-transform:uppercase;margin-bottom:12px;}
.results .content{font-size:14px;color:#c8cdd8;line-height:1.7;}

.sidebar-info{margin-top:28px;display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.sidebar-info .cat{background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:12px 16px;font-size:12px;color:#64748b;}
.sidebar-info .cat strong{color:#94a3b8;display:block;margin-bottom:2px;}

.back{display:inline-block;margin-top:28px;font-size:12px;}
</style>
</head><body>

<div class="topbar">
  <div class="logo">A</div>
  <span>AcmeCorp</span>
  <nav>
    <a href="{{ lab_url('/') }}">Home</a>
    <a href="{{ lab_url('/search?q=') }}">Search</a>
    <a href="{{ lab_url('/profile/') }}">Profile</a>
  </nav>
</div>

<div class="container">
  <div class="search-header">
    <h2>&#128269; Product Catalog</h2>
    <p>Search our internal product database and knowledge base</p>
  </div>

  <form method="GET" action="{{ lab_url('/search') }}">
    <div class="search-box">
      <input name="q" value="{{ q }}" placeholder="Search products, articles, resources..."/>
      <button type="submit">Search</button>
    </div>
  </form>

  <div class="results">
    <div class="label">Search Results</div>
    <div class="content">
      {{ q|safe }}
    </div>
  </div>

  <div class="sidebar-info">
    <div class="cat"><strong>Categories</strong>Hardware, Software, Services, Docs</div>
    <div class="cat"><strong>Popular</strong>VPN Setup, Email Config, Printers</div>
  </div>

  <a href="{{ lab_url('/') }}" class="back">&larr; Back to Portal</a>
</div>
</body></html>
"""


@search_bp.route("/search")
def search():
    # [VULN] q is rendered with |safe — no escaping. XSS lives here.
    q = request.args.get("q", "")

    logger.info(json.dumps({
        "event": "search_request",
        "endpoint": "/search",
        "query": q,
        "source_ip": request.remote_addr,
        "method": request.method,
    }))

    # Lab evidence — generic usage
    import evidence
    evidence.record(
        "search_used",
        module_id="xss",
        path="/search", method="GET",
        source_ip=request.remote_addr,
        via=current_app.detect_via(),
        extra={"query": q},
    )
    # Detect XSS-like payloads: script tags, event handlers, javascript:
    if q:
        low = q.lower()
        if any(s in low for s in ("<script", "</script", "onerror=", "onload=",
                                  "onclick=", "onmouseover=", "javascript:",
                                  "<svg", "<img ", "<iframe")):
            evidence.record(
                "xss_payload_observed",
                module_id="xss",
                path="/search", method="GET",
                source_ip=request.remote_addr,
        via=current_app.detect_via(),
                severity="medium",
                extra={"query": q[:200]},
            )
            evidence.record(
                "reflected_input_detected",
                module_id="xss",
                path="/search", method="GET",
                source_ip=request.remote_addr,
        via=current_app.detect_via(),
                severity="high",
                extra={"query": q[:200]},
            )

    rendered_q = escape(q) if containment.is_enabled("sanitize_input") else q
    return render_template_string(_TEMPLATE, q=rendered_q)
