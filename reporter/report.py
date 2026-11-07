"""Scheduled network reports (weekly, monthly, quarterly) from Prometheus and Loki.

  python report.py run weekly [--end 2026-11-02] [--no-email]   build one report now
  python report.py serve                                         run the schedule forever

Each report covers a closed period (Mon-Sun week, calendar month, calendar
quarter) in the local timezone and compares it with the period before.
Output goes to OUT_DIR as PDF + HTML; the PDF is emailed when SMTP is set.
"""
import argparse
import datetime as dt
import html
import json
import logging
import math
import os
import re
import smtplib
import sys
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader

PROM = os.environ.get("PROM_URL", "http://prometheus:9090")
LOKI = os.environ.get("LOKI_URL", "http://loki:3100")
TZ = ZoneInfo(os.environ.get("TZ", "Africa/Accra"))
NETWORK = os.environ.get("REPORT_NETWORK_NAME", "PXGH network")
OUT = Path(os.environ.get("OUT_DIR", "/out"))
HERE = Path(__file__).parent
log = logging.getLogger("reporter")

# private address ranges, same as the firewall dashboard
PRIVATE = r"(10|127)\..*|192\.168\..*|172\.(1[6-9]|2[0-9]|3[01])\..*|f[cd][0-9a-f]{2}:.*|fe80:.*"
FW = ('{application="unifi_system_log", category="SECURITY"} |= `"subcategory":"SECURITY_FIREWALL"` '
      '| json sub="subcategory", policy="parameters.TRIGGER.name", sip="parameters.SRC_IP.name", '
      'scl="parameters.SRC_CLIENT.name", sclip="parameters.SRC_CLIENT.ip", dip="parameters.DST_IP.name", '
      'ddev="parameters.DST_DEVICE.name" | sub="SECURITY_FIREWALL" '
      '| label_format src=`{{ or .scl .sip }}`, srcaddr=`{{ or .sclip .sip }}`')
FW_IN = FW + f" | srcaddr !~ `{PRIVATE}`"
FW_OUT = FW + f" | srcaddr =~ `{PRIVATE}`"
IPS = ('{application="unifi_system_log", category="SECURITY"} != `"subcategory":"SECURITY_FIREWALL"` '
       '| json sub="subcategory", evt="event", scl="parameters.SRC_CLIENT.name", sip="parameters.SRC_IP.name", sev="severity" '
       '| sub!="SECURITY_FIREWALL" | label_format src=`{{ or .scl .sip }}`, '
       'type=`{{ regexReplaceAll "_" (regexReplaceAll "^SECURITY_" .sub "") " " }}`')
AUDIT_FW = ('{application="unifi_system_log", category="AUDIT"} |= `FIREWALL` '
            '| json evt="event", section="parameters.SECTION.id" | section=~`FIREWALL_.*|NAT`')
LOGINS = ('{application="unifi_system_log", category="AUDIT"} |= `"event":"ADMIN_ACCESS"` '
          '| json evt="event", ip="parameters.IP.name" | evt="ADMIN_ACCESS"')
WAN_EVENTS = '{application="unifi_system_log", category="INTERNET_AND_WAN"}'


# ---------------------------------------------------------------- periods

KINDS = {"weekly": "week", "monthly": "month", "quarterly": "quarter", "custom": "period"}


def period_end(kind, now):
    """Start of the current (unfinished) period = end of the last closed one."""
    d = now.astimezone(TZ).date()
    if kind == "weekly":
        d -= dt.timedelta(days=d.weekday())
    elif kind == "monthly":
        d = d.replace(day=1)
    else:
        d = d.replace(month=(d.month - 1) // 3 * 3 + 1, day=1)
    return dt.datetime.combine(d, dt.time(), TZ)


def period_start(kind, end, length=None):
    if kind == "custom":
        return end - length
    if kind == "weekly":
        return end - dt.timedelta(days=7)
    months = 1 if kind == "monthly" else 3
    m = end.month - months
    y = end.year + (m - 1) // 12
    return end.replace(year=y, month=(m - 1) % 12 + 1)


def period_label(kind, start, end):
    last = end - dt.timedelta(days=1)
    if kind == "weekly":
        return (f"Week {start.isocalendar().week}",
                f"{start:%-d %b} – {last:%-d %b %Y}")
    if kind == "monthly":
        return f"{start:%B %Y}", f"{start:%-d %b} – {last:%-d %b %Y}"
    if kind == "custom":
        return f"{start:%-d %b} – {last:%-d %b %Y}", f"{(end - start).days} days"
    return (f"Q{(start.month - 1) // 3 + 1} {start.year}",
            f"{start:%b} – {last:%b %Y}")


# ---------------------------------------------------------------- data sources

def _get(url, params):
    full = url + "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(full, timeout=120) as r:
        body = json.load(r)
    if body.get("status") != "success":
        raise RuntimeError(body)
    return body["data"]["result"]


class Source:
    """Runs one period's queries; any failure becomes None, not a crash."""

    def __init__(self, start, end):
        self.start, self.end = start, end
        self.secs = int((end - start).total_seconds())
        self.r = f"{self.secs}s"
        self.errors = []

    def _safe(self, fn, q, *a):
        try:
            return fn(q, *a)
        except Exception as e:  # noqa: BLE001 - one bad query must not kill the report
            self.errors.append(f"{q[:80]}…: {e}")
            log.warning("query failed: %s: %s", q[:120], e)
            return None

    def prom(self, q):
        """Instant query at period end; $R is the period length."""
        return self._safe(lambda q: _get(PROM + "/api/v1/query",
                                         {"query": q.replace("$R", self.r), "time": self.end.timestamp()}), q)

    def prom_range(self, q, step):
        return self._safe(lambda q: _get(PROM + "/api/v1/query_range", {
            "query": q, "start": self.start.timestamp() + step,
            "end": self.end.timestamp(), "step": step}), q)

    def loki(self, q):
        return self._safe(lambda q: _get(LOKI + "/loki/api/v1/query", {
            "query": q.replace("$R", self.r), "time": int(self.end.timestamp() * 1e9)}), q)

    def loki_lines(self, q, limit=500):
        return self._safe(lambda q: _get(LOKI + "/loki/api/v1/query_range", {
            "query": q, "start": int(self.start.timestamp() * 1e9), "end": int(self.end.timestamp() * 1e9),
            "limit": limit, "direction": "forward"}), q)

    # helpers ----------------------------------------------------------
    def scalar(self, q, src="prom"):
        res = (self.prom if src == "prom" else self.loki)(q)
        if res is None:
            return None
        if not res:
            return 0.0 if src == "loki" else None  # loki returns nothing when the count is 0
        v = float(res[0]["value"][1])
        return None if math.isnan(v) else v

    def by(self, q, label, src="prom"):
        res = (self.prom if src == "prom" else self.loki)(q) or []
        return {x["metric"].get(label, ""): float(x["value"][1]) for x in res}

    def coverage(self):
        """Share of the period's days that have data, per source."""
        days = max(1, round(self.secs / 86400))
        def frac(res, per_day=None):
            if not res:
                return 0.0
            vals = [float(v) for _, v in res[0]["values"]]
            if per_day:  # metrics: share of expected samples (Prometheus scrapes UnPoller every 60s)
                return min(1.0, sum(min(v / per_day, 1) for v in vals) / days)
            return sum(1 for v in vals if v > 0) / days
        p = self.prom_range('count_over_time(up{job="unpoller"}[1d])', 86400)
        l = self._safe(lambda q: _get(LOKI + "/loki/api/v1/query_range", {
            "query": q, "start": int((self.start.timestamp() + 86400) * 1e9),
            "end": int(self.end.timestamp() * 1e9), "step": "86400"}),
            'sum(count_over_time({application="unifi_system_log"}[1d]))')
        return {"prom": frac(p, 1440 * 0.98), "loki": frac(l)}


# ---------------------------------------------------------------- collect

def collect(s: Source):
    d = {}
    # internet
    # The UDM's per-port WAN byte counters barely move, so traffic comes from the
    # site-level WAN rate gauge (bytes/s), averaged over the period and scaled up.
    rx = 'max(unpoller_site_receive_rate_bytes{subsystem="wan"})'
    tx = 'max(unpoller_site_transmit_rate_bytes{subsystem="wan"})'
    d["wan_down"] = s.scalar(f"avg_over_time({rx}[$R:1m]) * {s.secs}")
    d["wan_up"] = s.scalar(f"avg_over_time({tx}[$R:1m]) * {s.secs}")
    d["wan_p95"] = s.scalar(f"quantile_over_time(0.95, {rx}[$R:5m]) * 8")
    d["latency_avg"] = s.scalar('avg_over_time(unpoller_site_latency_seconds{subsystem="www"}[$R])')
    d["latency_max"] = s.scalar('max_over_time(unpoller_site_latency_seconds{subsystem="www"}[$R])')
    up = s.by("avg_over_time((unpoller_wan_uptime_percentage >= 0)[$R:5m])", "wan_name")
    names = s.by("max_over_time(unpoller_wan_uptime_percentage[$R])", "wan_name")
    d["wans"] = [{"name": n, "uptime": up.get(n)} for n in sorted(names)]
    d["failovers"] = s.scalar(f'sum(count_over_time({WAN_EVENTS} |= `FAILED_OVER` [$R]))', "loki")

    # gateway
    gw = 'type="udm"'
    d["cpu_avg"] = s.scalar(f"avg(avg_over_time(unpoller_device_cpu_utilization_ratio{{{gw}}}[$R]))")
    d["cpu_max"] = s.scalar(f"max(max_over_time(unpoller_device_cpu_utilization_ratio{{{gw}}}[$R]))")
    d["mem_start"] = s.scalar(f"avg(avg_over_time(unpoller_device_memory_utilization_ratio{{{gw}}}[1d] offset {s.secs - 86400}s))")
    d["mem_end"] = s.scalar(f"avg(avg_over_time(unpoller_device_memory_utilization_ratio{{{gw}}}[1d]))")
    d["mem_max"] = s.scalar(f"max(max_over_time(unpoller_device_memory_utilization_ratio{{{gw}}}[$R]))")
    d["temp_max"] = s.scalar(f'max(max_over_time(unpoller_device_temperature_celsius{{{gw},temp_area="CPU"}}[$R]))')
    d["gw_reboots"] = s.scalar(f"sum(resets(unpoller_device_uptime_seconds{{{gw}}}[$R]))")

    # clients
    clients = "unpoller_client_uptime_seconds"
    d["clients_peak"] = s.scalar(f"max_over_time(count({clients})[$R:5m])")
    d["clients_unique"] = s.scalar(f"count(count by (mac) (last_over_time({clients}[$R])))")
    d["clients_new"] = s.scalar(f"count(count by (mac) (last_over_time({clients}[$R])) "
                                f"unless count by (mac) (last_over_time({clients}[$R] offset $R)))")
    rx = s.prom("sum by (mac, name, oui) (increase(unpoller_client_receive_bytes_total[$R]))") or []
    tx = s.by("sum by (mac) (increase(unpoller_client_transmit_bytes_total[$R]))", "mac")
    top = []
    for x in rx:
        m = x["metric"]
        name = m.get("name") or m.get("mac", "")
        if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", name) and m.get("oui"):
            name = f"{m['oui']} device"  # no hostname: say what it is, keep the MAC as detail
        top.append({"name": name, "mac": m.get("mac", ""),
                    "bytes": float(x["value"][1]) + tx.get(m.get("mac"), 0)})
    d["top_clients"] = sorted(top, key=lambda c: -c["bytes"])[:10]

    # access points
    aps = s.by('max_over_time(sum by (name) (unpoller_device_radio_stations)[$R:5m])', "name")
    traffic = s.by('sum by (name) (increase(unpoller_device_bytes_total{type="uap"}[$R]))', "name")
    sat = s.by("avg_over_time(avg by (name) (unpoller_device_vap_satisfaction_ratio >= 0)[$R:5m])", "name")
    reb = s.by('sum by (name) (resets(unpoller_device_uptime_seconds{type="uap"}[$R]))', "name")
    util = s.prom("avg by (name, band) (avg_over_time(unpoller_device_radio_channel_utilization_total_ratio[$R]))") or []
    u = {}
    for x in util:
        u.setdefault(x["metric"]["name"], {})[x["metric"].get("band")] = float(x["value"][1])
    d["aps"] = sorted(({"name": n, "peak": aps[n], "bytes": traffic.get(n), "sat": sat.get(n),
                        "u24": u.get(n, {}).get("2.4"), "u5": u.get(n, {}).get("5"),
                        "reboots": reb.get(n, 0)} for n in aps), key=lambda a: -(a["bytes"] or 0))

    # security
    L = "loki"
    d["blocks_in"] = s.scalar(f"sum(count_over_time({FW_IN} [$R]))", L)
    d["blocks_out"] = s.scalar(f"sum(count_over_time({FW_OUT} [$R]))", L)
    d["block_sources"] = s.scalar(f"count(sum by (src) (count_over_time({FW_IN} [$R])))", L)
    d["top_policies"] = _top(s.by(f"topk(8, sum by (policy) (count_over_time({FW} [$R])))", "policy", L))
    d["top_sources"] = _top(s.by(f"topk(8, sum by (src) (count_over_time({FW_IN} [$R])))", "src", L))
    d["top_devices"] = _top(s.by(f"topk(8, sum by (src) (count_over_time({FW_OUT} [$R])))", "src", L))
    d["threats"] = s.scalar(f"sum(count_over_time({IPS} [$R]))", L)
    d["threats_high"] = s.scalar(f'sum(count_over_time({IPS} | sev=~"HIGH|VERY_HIGH" [$R]))', L)
    d["threats_blocked"] = s.scalar(f'sum(count_over_time({IPS} | evt=~"(?i).*block.*" [$R]))', L)
    d["threats_open"] = (d["threats"] - d["threats_blocked"]) if None not in (d["threats"], d["threats_blocked"]) else None
    d["threat_devices"] = _top(s.by(f"topk(8, sum by (src) (count_over_time({IPS} [$R])))", "src", L))
    d["fw_changes"] = s.scalar(f"sum(count_over_time({AUDIT_FW} [$R]))", L)
    d["logins"] = s.scalar(f"sum(count_over_time({LOGINS} [$R]))", L)
    d["logins_outside"] = s.scalar(f"sum(count_over_time({LOGINS} | ip !~ `{PRIVATE}` [$R]))", L)
    return d


def _top(m):
    return [{"name": k or "unknown", "n": v} for k, v in sorted(m.items(), key=lambda kv: -kv[1])]


def events(s: Source):
    """Notable events: each internet failover, and firewall changes grouped per admin per day."""
    out, changes = [], {}
    for stream in s.loki_lines(f'{WAN_EVENTS} |= `FAILED_OVER`', 200) or []:
        for ts, line in stream["values"]:
            t = dt.datetime.fromtimestamp(int(ts) / 1e9, TZ)
            out.append({"t": t, "kind": "Internet", "msg": _json(line).get("message", line)})
    for stream in s.loki_lines(AUDIT_FW, 2000) or []:
        for ts, line in stream["values"]:
            t = dt.datetime.fromtimestamp(int(ts) / 1e9, TZ)
            prm = _json(line).get("parameters", {})
            admin = prm.get("ADMIN", {}).get("name", "someone")
            obj = prm.get("OBJECT", {}).get("name", "")
            g = changes.setdefault((admin, t.date()), {"t": t, "n": 0, "objs": []})
            g["n"] += 1
            if obj and obj not in g["objs"]:
                g["objs"].append(obj)
    for (admin, _), g in changes.items():
        objs = ", ".join(g["objs"][:6]) + (f" and {len(g['objs']) - 6} more" if len(g["objs"]) > 6 else "")
        what = f"{len(g['objs'])} rule{'s' * (len(g['objs']) != 1)}" if g["objs"] else "firewall settings"
        out.append({"t": g["t"], "kind": "Firewall change",
                    "msg": f"{admin} made {g['n']} change{'s' * (g['n'] != 1)} to {what}" + (f": {objs}" if objs else "")})
    return sorted(out, key=lambda e: e["t"])


def _json(line):
    try:
        return json.loads(line)
    except ValueError:
        return {}


def threat_list(s: Source, limit=30):
    """Individual IPS events, newest first: when, device, target, severity, blocked or not."""
    rows = []
    for stream in s.loki_lines(IPS.split(" | json")[0], 1000) or []:
        for ts, line in stream["values"]:
            j = _json(line)
            prm = j.get("parameters", {})
            name = lambda k: prm.get(k, {}).get("name") or prm.get(k, {}).get("id") or ""
            rows.append({"t": dt.datetime.fromtimestamp(int(ts) / 1e9, TZ),
                         "src": name("SRC_CLIENT") or name("SRC_IP"),
                         "dst": name("DST_CLIENT") or name("DST_IP") or name("DST_DEVICE"),
                         "sev": (j.get("severity") or "").replace("_", " ").capitalize(),
                         "blocked": "BLOCK" in (j.get("event") or "").upper()})
    rows.sort(key=lambda r: r["t"], reverse=True)
    return rows[:limit], len(rows)


def wan_series(s: Source, kind):
    days = (s.end - s.start).days
    step = 3600 if days <= 10 else 6 * 3600 if days <= 45 else 86400
    w = f"{step}s"
    down = s.prom_range(f'max(avg_over_time(unpoller_site_receive_rate_bytes{{subsystem="wan"}}[{w}]))*8', step) or []
    up = s.prom_range(f'max(avg_over_time(unpoller_site_transmit_rate_bytes{{subsystem="wan"}}[{w}]))*8', step) or []
    pts = lambda r: [(float(t), float(v)) for t, v in r[0]["values"]] if r else []
    return pts(down), pts(up), step


# ---------------------------------------------------------------- formatting

def fbytes(b):
    if b is None:
        return "–"
    for unit, size in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if b >= size:
            return f"{b / size:.{1 if b / size < 100 else 0}f} {unit}"
    return f"{b:.0f} B"


def fbits(b):
    if b is None:
        return "–"
    for unit, size in (("Gbps", 1e9), ("Mbps", 1e6), ("kbps", 1e3)):
        if b >= size:
            return f"{b / size:.{1 if b / size < 100 else 0}f} {unit}"
    return f"{b:.0f} bps"


def fnum(n):
    return "–" if n is None else f"{n:,.0f}"


def fpct(r, digits=0):
    return "–" if r is None else f"{r * 100:.{digits}f}%"


def change(cur, prev, unit_word, period_word, covered):
    """'+12% vs last week' / '3 fewer vs last week' / reason it can't be compared."""
    if not covered:
        return f"no earlier {period_word} to compare"
    if cur is None or prev is None:
        return ""
    vs = f"vs last {period_word}"
    if prev == 0:
        return "none last " + period_word if cur else f"none, same as last {period_word}"
    diff = cur - prev
    if abs(prev) < 20:  # small counts read better as absolute numbers
        if diff == 0:
            return f"same as last {period_word}"
        word = "more" if diff > 0 else "fewer"
        return f"{abs(diff):.0f} {word} {vs}"
    pct = diff / prev * 100
    if abs(pct) < 0.5:
        return f"same as last {period_word}"
    return f"{'+' if pct > 0 else '−'}{abs(pct):.0f}% {vs}"


# ---------------------------------------------------------------- chart

def svg_chart(down, up, kind, start, end, w=658, h=236):
    """WAN throughput line chart as inline SVG (two series, one shared axis)."""
    if not down:
        return '<p class="muted">No throughput data for this period</p>'
    L, R, T, B = 44, 12, 28, 28
    pw, ph = w - L - R, h - T - B
    t0, t1 = start.timestamp(), end.timestamp()
    vmax = max(v for _, v in down + up) or 1
    # nice axis maximum in Mbps
    mb = vmax / 1e6
    stepv = 10 ** math.floor(math.log10(mb / 4)) if mb > 0 else 1
    for m in (1, 2, 2.5, 5, 10):
        if mb / (stepv * m) <= 4:
            stepv *= m
            break
    top = stepv * math.ceil(mb / stepv) * 1e6
    x = lambda t: L + (t - t0) / (t1 - t0) * pw
    y = lambda v: T + ph - v / top * ph
    path = lambda pts: "M" + " L".join(f"{x(t):.1f},{y(v):.1f}" for t, v in pts)
    g = []
    # grid + y labels
    v = 0.0
    while v <= top + 1:
        yy = y(v)
        g.append(f'<line x1="{L}" x2="{w - R}" y1="{yy:.1f}" y2="{yy:.1f}" stroke="#1b1b1a" stroke-opacity="0.08" stroke-width="1"/>')
        g.append(f'<text x="{L - 8}" y="{yy + 3:.1f}" font-family="PlexMono" font-size="7pt" fill="#8a8984" text-anchor="end">{v / 1e6:.0f}</text>')
        v += stepv * 1e6
    g.append(f'<text x="{L - 8}" y="{T - 14}" font-family="PlexMono" font-size="7pt" fill="#8a8984" text-anchor="end">Mbps</text>')
    # x labels
    day = start
    while day < end:
        xx = x(day.timestamp())
        if (end - start).days <= 10:
            g.append(f'<line x1="{xx:.1f}" x2="{xx:.1f}" y1="{T}" y2="{T + ph}" stroke="#1b1b1a" stroke-opacity="0.08" stroke-width="1"/>')
            g.append(f'<text x="{xx + pw / max(1, (end - start).days) / 2:.1f}" y="{h - 8}" font-family="PlexMono" font-size="7pt" fill="#8a8984" text-anchor="middle">{day:%a %-d}</text>')
            day += dt.timedelta(days=1)
        else:
            stride = 7 if (end - start).days <= 45 else 14
            g.append(f'<text x="{xx:.1f}" y="{h - 8}" font-family="PlexMono" font-size="7pt" fill="#8a8984" text-anchor="middle">{day:%-d %b}</text>')
            day += dt.timedelta(days=stride)
    # series: download leads in the accent, upload sits in a quiet neutral
    g.append(f'<path d="{path(up)}" fill="none" stroke="#a9a8a2" stroke-width="1.4" stroke-linejoin="round"/>')
    g.append(f'<path d="{path(down)}" fill="none" stroke="#2a78d6" stroke-width="1.6" stroke-linejoin="round"/>')
    # direct label at the peak of download
    pt, pv = max(down, key=lambda p: p[1])
    px, py = x(pt), y(pv)
    when = dt.datetime.fromtimestamp(pt, TZ)
    anchor = "end" if px > L + pw * 0.75 else "start"
    dx = -8 if anchor == "end" else 8
    g.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="4" fill="#2a78d6" stroke="#ffffff" stroke-width="2"/>')
    g.append(f'<text x="{px + dx:.1f}" y="{py + 4:.1f}" font-family="Plex" font-weight="500" font-size="7.5pt" fill="#1b1b1a" text-anchor="{anchor}">'
             f'Peak {fbits(pv)}, {when:%a %H:%M}</text>')
    return (f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
            f'aria-label="Internet throughput, download and upload">{"".join(g)}</svg>')


# ---------------------------------------------------------------- summary

def summary(d, p, word, covered):
    """Plain-language lines for page 1, written from the numbers."""
    lines = []
    up = [w for w in d["wans"] if w["uptime"] is not None]
    if up:
        prim = max(up, key=lambda w: w["uptime"])
        fo = d["failovers"] or 0
        tail = (f" It failed over to a backup line {fo:.0f} time{'s' * (fo != 1)}"
                if fo else " There were no failovers to the backup lines")
        lines.append(f"The main internet line ({prim['name']}) was up {prim['uptime']:.2f}% of the {word}.{tail}.")
    if d["wan_down"] is not None:
        ch = change(d["wan_down"], p.get("wan_down"), "", word, covered["prom"])
        lines.append(f"The office downloaded {fbytes(d['wan_down'])} and uploaded {fbytes(d['wan_up'])}"
                     + (f" ({ch})" if ch and not ch.startswith("no full") else "") + ".")
    if d["clients_peak"] is not None:
        new = d["clients_new"] if covered["prom"] else None
        lines.append(f"{fnum(d['clients_peak'])} devices were online at the busiest moment, "
                     f"{fnum(d['clients_unique'])} different devices over the {word}"
                     + (f", {fnum(new)} of them seen for the first time" if new else "") + ".")
    if d["blocks_in"] is not None:
        lines.append(f"The firewall blocked {fnum(d['blocks_in'])} connection attempts from the internet "
                     f"and {fnum(d['blocks_out'])} from devices inside the network. "
                     f"Intrusion prevention blocked {fnum(d['threats_blocked'])} of {fnum(d['threats'])} threats"
                     + ((", all of them high severity" if d["threats_high"] == d["threats"] else
                            f", {fnum(d['threats_high'])} of them high severity") if d["threats_high"] else "") + ".")
    return lines


def attention(d):
    """Things a reader should act on. Empty list = nothing to flag."""
    a = []
    if d["gw_reboots"]:
        a.append(f"The gateway restarted {d['gw_reboots']:.0f} time(s)")
    for ap in d["aps"]:
        if ap["reboots"]:
            a.append(f"Access point {ap['name']} restarted {ap['reboots']:.0f} time(s)")
    if d["mem_end"] is not None and d["mem_start"] is not None and d["mem_end"] - d["mem_start"] > 0.05:
        a.append(f"Gateway memory use climbed from {fpct(d['mem_start'])} to {fpct(d['mem_end'])}")
    if d["mem_max"] and d["mem_max"] > 0.9:
        a.append(f"Gateway memory peaked at {fpct(d['mem_max'])}")
    if d["threats_open"]:
        a.append(f"{fnum(d['threats_open'])} threats were detected but not blocked, see Security")
    if d["threats_high"]:
        a.append(f"{fnum(d['threats_high'])} high-severity threats were detected"
                 + (", all blocked" if not d["threats_open"] else "") + ", see Security")
    if d["logins_outside"]:
        a.append(f"{fnum(d['logins_outside'])} admin logins came from outside the office network")
    for ap in d["aps"]:
        if (ap["u24"] or 0) > 0.6:
            a.append(f"{ap['name']} 2.4 GHz channel averaged {fpct(ap['u24'])} busy, clients there will feel slow")
    return a


# ---------------------------------------------------------------- build

def build(kind, end=None, start=None):
    end = end or period_end(kind, dt.datetime.now(TZ))
    start = start or period_start(kind, end)
    prev_start = period_start(kind, start, end - start)
    word = KINDS[kind]
    title, dates = period_label(kind, start, end)
    log.info("building %s report %s (%s)", kind, title, dates)

    cur, prev = Source(start, end), Source(prev_start, start)
    d, p = collect(cur), collect(prev)
    cov = prev.coverage()
    gap = 1 - cur.coverage()["prom"]
    covered = {k: v >= 0.95 for k, v in cov.items()}
    down, up, step = wan_series(cur, kind)
    ch = lambda key, src="prom": change(d.get(key), p.get(key), "", word, covered[src])

    env = Environment(loader=FileSystemLoader(HERE), autoescape=True)
    env.filters.update(bytes=fbytes, bits=fbits, num=fnum, pct=fpct)
    html_out = env.get_template("template.html").render(
        network=NETWORK, kind=kind, word=word, title=title, dates=dates,
        tzname=str(TZ), generated=dt.datetime.now(TZ), d=d, p=p, ch=ch, covered=covered,
        summary=summary(d, p, word, covered), attention=attention(d), events=events(cur),
        threats=threat_list(cur), chart=svg_chart(down, up, kind, start, end), fonts=(HERE / "fonts").as_uri(),
        errors=cur.errors + prev.errors, gap=gap, max_client=max([c["bytes"] for c in d["top_clients"]] or [1]),
    )
    OUT.mkdir(parents=True, exist_ok=True)
    pdf = report_path(kind, start, end)
    from weasyprint import HTML  # imported late: slow to load, not needed until a report is due
    tmp = pdf.with_suffix(".part")
    HTML(string=html_out, base_url=str(HERE)).write_pdf(tmp)
    tmp.replace(pdf)  # appears in the portal only once complete
    log.info("wrote %s (%d query errors)", pdf, len(cur.errors + prev.errors))
    name = f"{title} report" if kind != "custom" else f"report for {title}"
    return pdf, f"{NETWORK}: {name} ({dates})", summary(d, p, word, covered)


# ---------------------------------------------------------------- settings

SETTINGS = OUT / "settings.json"


def default_settings():
    """First-run values come from the environment; after that settings.json wins."""
    env = os.environ.get
    to = env("REPORT_TO", "")
    return {
        "smtp": {"host": env("SMTP_HOST", ""), "port": int(env("SMTP_PORT", 587)),
                 "security": env("SMTP_SECURITY", "starttls"), "user": env("SMTP_USER", ""),
                 "password": env("SMTP_PASSWORD", ""), "from": env("SMTP_FROM", "")},
        "recipients": {k: to for k in ("weekly", "monthly", "quarterly")},
        "schedule": {"enabled": True, "hour": int(env("SEND_HOUR", 7)),
                     "kinds": env("REPORTS", "weekly,monthly,quarterly").split(",")},
    }


def load_settings():
    s = default_settings()
    try:
        saved = json.loads(SETTINGS.read_text())
        for k in s:
            s[k].update(saved.get(k, {}))
    except FileNotFoundError:
        pass
    return s


def save_settings(s):
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS.with_suffix(".tmp")
    tmp.write_text(json.dumps(s, indent=2))
    os.chmod(tmp, 0o600)  # holds the SMTP password
    tmp.replace(SETTINGS)


def split_addresses(text):
    return [a.strip() for a in re.split(r"[,;\s]+", text or "") if a.strip()]


# ---------------------------------------------------------------- email

def send_mail(to, subject, text, html_body=None, attachment=None, smtp=None):
    smtp = smtp or load_settings()["smtp"]
    if not smtp.get("host"):
        raise RuntimeError("no SMTP server is set up")
    to = split_addresses(to) if isinstance(to, str) else to
    if not to:
        raise RuntimeError("no recipients")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, smtp.get("from") or smtp.get("user"), ", ".join(to)
    msg.set_content(text)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    if attachment:
        msg.add_attachment(attachment.read_bytes(), maintype="application", subtype="pdf", filename=attachment.name)
    port, sec = int(smtp.get("port") or 587), smtp.get("security", "starttls")
    cls = smtplib.SMTP_SSL if sec == "ssl" else smtplib.SMTP
    with cls(smtp["host"], port, timeout=60) as c:
        if sec == "starttls":
            c.starttls()
        if smtp.get("user"):
            c.login(smtp["user"], smtp.get("password", ""))
        c.send_message(msg)
    log.info("emailed %r to %s", subject, ", ".join(to))


def email_report(pdf, subject, lines, to):
    send_mail(to, subject, "\n\n".join(lines) + "\n\nThe full report is attached.",
              "".join(f"<p>{html.escape(x)}</p>" for x in lines)
              + "<p style='color:#6b6a66'>The full report is attached.</p>", pdf)


def run(kind, end=None, send=True, start=None, to=None):
    """Build a report; email it to `to`, or to the kind's recipients when send=True."""
    pdf, subject, lines = build(kind, end, start)
    if to is None and send:
        to = load_settings()["recipients"].get(kind, "")
    if to:
        try:
            email_report(pdf, subject, lines, to)
        except Exception:  # noqa: BLE001 - the PDF is saved either way
            log.exception("email failed; report kept at %s", pdf)
            raise
    return pdf


def report_path(kind, start, end=None):
    stem = f"{kind}-{start:%Y-%m-%d}"
    if kind == "custom":
        stem += f"-to-{end - dt.timedelta(days=1):%Y-%m-%d}"
    return OUT / f"{stem}.pdf"


def due_reports(now=None):
    """Scheduled reports whose period has closed, it's past the send hour, and no
    PDF exists yet. Only periods ending after the scheduler first started count,
    so a fresh install doesn't back-fill old periods it has little data for."""
    now = now or dt.datetime.now(TZ)
    st = load_settings()["schedule"]
    if not st.get("enabled"):
        return []
    OUT.mkdir(parents=True, exist_ok=True)
    since_file = OUT / ".scheduler-since"
    if not since_file.exists():
        since_file.write_text(now.isoformat())
    since = dt.datetime.fromisoformat(since_file.read_text().strip())
    due = []
    for kind in st.get("kinds", []):
        if kind not in ("weekly", "monthly", "quarterly"):
            continue
        end = period_end(kind, now)
        if end > since and now.hour >= int(st.get("hour", 7)) and not report_path(kind, period_start(kind, end)).exists():
            due.append((kind, end))
    return due


def serve():
    """Scheduler only (no portal): check every 10 minutes."""
    log.info("scheduler up, output %s", OUT)
    while True:
        for kind, end in due_reports():
            try:
                run(kind, end)
            except Exception:  # noqa: BLE001 - retry on the next tick
                log.exception("%s report failed, retrying in 10 minutes", kind)
        time.sleep(600)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("kind", choices=list(KINDS))
    r.add_argument("--end", help="last day to include, e.g. 2026-11-01; default: the last closed period")
    r.add_argument("--start", help="first day to include (custom reports only), e.g. 2026-11-01")
    r.add_argument("--no-email", action="store_true")
    sub.add_parser("serve")
    a = ap.parse_args()
    if a.cmd == "serve":
        serve()
    else:
        day = lambda x: dt.datetime.combine(dt.date.fromisoformat(x), dt.time(), TZ)
        if a.kind == "custom":
            if not a.start:
                ap.error("custom reports need --start (and optionally --end, default today)")
            end = day(a.end) + dt.timedelta(days=1) if a.end else dt.datetime.now(TZ)
            run("custom", end, send=False, start=day(a.start))
        else:
            # --end names the last day of the period; internally the end is exclusive
            end = day(a.end) + dt.timedelta(days=1) if a.end else None
            if end and end != period_end(a.kind, end):
                ap.error(f"--end for a {a.kind} report must be the last day of a {KINDS[a.kind]}")
            run(a.kind, end, send=not a.no_email)


if __name__ == "__main__":
    main()
