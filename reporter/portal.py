"""Reports portal: sign in with a Grafana account, generate and download reports,
and (Grafana admins) set up email and the schedule.

One process runs the web app, a single worker that builds reports one at a
time, and the scheduler, which drops due reports into the same queue.
"""
import base64
import datetime as dt
import itertools
import logging
import os
import queue
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
import json
from functools import wraps

from flask import (Flask, abort, flash, jsonify, redirect, render_template, request,
                   send_from_directory, session, url_for)

import report as R

GRAFANA = os.environ.get("GRAFANA_URL", "http://grafana:3000")
log = logging.getLogger("portal")

app = Flask(__name__, static_folder="fonts", static_url_path="/fonts")


def _secret():
    """Session key kept in the output folder so logins survive restarts."""
    f = R.OUT / ".portal-secret"
    if not f.exists():
        R.OUT.mkdir(parents=True, exist_ok=True)
        f.write_text(secrets.token_hex(32))
        os.chmod(f, 0o600)
    return f.read_text().strip()


app.config.update(SECRET_KEY=_secret(), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=12))


# ---------------------------------------------------------------- jobs

jobs = {}            # id -> job dict, newest kept
work = queue.Queue()
_ids = itertools.count(1)
_lock = threading.Lock()


def enqueue(kind, start, end, by, to=""):
    with _lock:
        jid = next(_ids)
        jobs[jid] = {"id": jid, "kind": kind, "start": start, "end": end, "by": by, "to": to,
                     "status": "queued", "file": None, "error": None, "queued_at": dt.datetime.now(R.TZ)}
        for old in sorted(jobs)[:-30]:
            jobs.pop(old)
    work.put(jid)
    return jid


def worker():
    while True:
        jid = work.get()
        job = jobs.get(jid)
        if not job:
            continue
        job["status"] = "running"
        try:
            pdf = R.run(job["kind"], job["end"], start=job["start"] if job["kind"] == "custom" else None,
                        send=False, to=job["to"] or None)
            job.update(status="done", file=pdf.name)
        except Exception as e:  # noqa: BLE001 - shown to the user, worker keeps going
            log.exception("job %s failed", jid)
            pdf = R.report_path(job["kind"], job["start"], job["end"])
            # the PDF may exist even when only the email failed
            job.update(status="failed", error=str(e) or e.__class__.__name__,
                       file=pdf.name if pdf.exists() else None)


def scheduler():
    while True:
        try:
            busy = {(j["kind"], j["end"]) for j in jobs.values() if j["status"] in ("queued", "running")}
            for kind, end in R.due_reports():
                if (kind, end) not in busy:
                    to = R.load_settings()["recipients"].get(kind, "")
                    enqueue(kind, R.period_start(kind, end), end, "schedule", to)
        except Exception:  # noqa: BLE001
            log.exception("scheduler tick failed")
        time.sleep(300)


# ---------------------------------------------------------------- auth

_fails = {}  # ip -> [timestamps]


def grafana_login(user, password):
    """Check the credentials against Grafana. Returns (name, is_admin) or None."""
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    def get(path):
        req = urllib.request.Request(GRAFANA + path, headers={"Authorization": f"Basic {token}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    try:
        me = get("/api/user")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return None
        raise
    orgs = get("/api/user/orgs")
    admin = bool(me.get("isGrafanaAdmin")) or any(o.get("role") == "Admin" for o in orgs)
    return me.get("name") or me.get("login") or user, admin


def login_required(admin=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if "user" not in session:
                return redirect(url_for("login", next=request.path))
            if admin and not session.get("admin"):
                abort(403)
            if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
                abort(400)
            return fn(*a, **kw)
        return wrapper
    return deco


@app.context_processor
def common():
    st = R.load_settings()
    return {"user": session.get("user"), "is_admin": session.get("admin"), "csrf": session.get("csrf"),
            "name": R.display_name(st), "custom_name": bool(st["general"]["name"].strip()), "tz": str(R.TZ)}


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr
        recent = [t for t in _fails.get(ip, []) if t > time.time() - 300]
        if len(recent) >= 5:
            error = "Too many failed attempts. Try again in 5 minutes"
        else:
            try:
                res = grafana_login(request.form.get("username", "").strip(), request.form.get("password", ""))
            except Exception:  # noqa: BLE001
                log.exception("grafana login check failed")
                res, error = None, "Can't reach Grafana to check your login. Try again shortly"
            if res:
                session.clear()
                session.permanent = True
                session.update(user=res[0], admin=res[1], csrf=secrets.token_hex(16))
                _fails.pop(ip, None)
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))
            if not error:
                _fails[ip] = recent + [time.time()]
                error = "Wrong username or password"
    return render_template("login.html", error=error)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- reports

NAME = re.compile(r"^(weekly|monthly|quarterly|custom)-(\d{4}-\d{2}-\d{2})(?:-to-(\d{4}-\d{2}-\d{2}))?\.pdf$")


def describe(kind, start, last):
    if kind == "custom":
        return "Custom", f"{start:%-d %b} – {last:%-d %b %Y}"
    end = last + dt.timedelta(days=1)
    s = dt.datetime.combine(start, dt.time(), R.TZ)
    e = dt.datetime.combine(end, dt.time(), R.TZ)
    title, dates = R.period_label(kind, s, e)
    return kind.capitalize(), f"{title} · {dates}"


def archive():
    out = []
    for f in R.OUT.glob("*.pdf"):
        m = NAME.match(f.name)
        if not m:
            continue
        kind, start = m[1], dt.date.fromisoformat(m[2])
        if m[3]:
            last = dt.date.fromisoformat(m[3])
        else:
            s = dt.datetime.combine(start, dt.time(), R.TZ)
            last = _period_last(kind, s)
        label, period = describe(kind, start, last)
        st = f.stat()
        out.append({"file": f.name, "kind": label, "period": period, "start": start,
                    "made": dt.datetime.fromtimestamp(st.st_mtime, R.TZ), "size": st.st_size})
    return sorted(out, key=lambda r: (r["start"], r["made"]), reverse=True)


def _period_last(kind, start):
    """Last day of the period that begins at `start`."""
    if kind == "weekly":
        return (start + dt.timedelta(days=6)).date()
    months = 1 if kind == "monthly" else 3
    m = start.month + months
    nxt = start.replace(year=start.year + (m - 1) // 12, month=(m - 1) % 12 + 1)
    return (nxt - dt.timedelta(days=1)).date()


def job_view(j):
    label, period = describe(j["kind"], j["start"].date(), (j["end"] - dt.timedelta(days=1)).date()) \
        if j["kind"] != "custom" or j["end"].time() == dt.time() else ("Custom", f"{j['start']:%-d %b} – now")
    return {"id": j["id"], "kind": label, "period": period, "status": j["status"], "file": j["file"],
            "error": j["error"], "by": j["by"], "to": j["to"], "queued_at": j["queued_at"].strftime("%H:%M")}


@app.get("/")
@login_required()
def index():
    s = R.load_settings()
    today = dt.datetime.now(R.TZ).date()
    return render_template("reports.html", reports=archive(), jobs=[job_view(j) for j in reversed(jobs.values())],
                           recipients=s["recipients"], today=today, schedule=schedule_text(s["schedule"]),
                           week_ago=today - dt.timedelta(days=7), mail_ready=bool(s["smtp"].get("host")))


def schedule_text(sch):
    when = {"weekly": "weekly reports every Monday", "monthly": "monthly reports on the 1st",
            "quarterly": "quarterly reports on the first day of each quarter"}
    parts = [when[k] for k in ("weekly", "monthly", "quarterly") if k in sch.get("kinds", [])]
    if not sch.get("enabled") or not parts:
        return "Automatic reports are off. You can make one yourself"
    text = parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]
    return f"Made automatically: {text}, at {int(sch.get('hour', 7)):02d}:00. You can also make one yourself"


@app.post("/generate")
@login_required()
def generate():
    f = request.form
    kind = f.get("kind")
    now = dt.datetime.now(R.TZ)
    day = lambda x: dt.datetime.combine(dt.date.fromisoformat(x), dt.time(), R.TZ)
    try:
        if kind == "custom":
            start, last = day(f["start"]), day(f["end"])
            if last < start:
                raise ValueError("the end date is before the start date")
            if (last - start).days > 366:
                raise ValueError("pick a range of a year or less")
            end = min(last + dt.timedelta(days=1), now)
        elif kind in ("weekly", "monthly", "quarterly"):
            end = R.period_end(kind, now)
            if f.get("which") == "previous":
                end = R.period_start(kind, end)
            start = R.period_start(kind, end)
        else:
            raise ValueError("unknown report type")
    except (KeyError, ValueError) as e:
        flash(f"Can't generate that report: {e}")
        return redirect(url_for("index"))
    to = f.get("to", "").strip() if f.get("email") else ""
    if to and not R.load_settings()["smtp"].get("host"):
        flash("Email isn't set up yet, so the report will only be saved here")
        to = ""
    enqueue(kind, start, end, session["user"], to)
    return redirect(url_for("index"))


@app.get("/jobs")
@login_required()
def jobs_json():
    return jsonify([job_view(j) for j in reversed(jobs.values())])


@app.get("/download/<name>")
@login_required()
def download(name):
    if not NAME.match(name) or not (R.OUT / name).exists():
        abort(404)
    return send_from_directory(R.OUT, name, as_attachment=request.args.get("view") is None)


@app.post("/delete/<name>")
@login_required(admin=True)
def delete(name):
    if NAME.match(name) and (R.OUT / name).exists():
        (R.OUT / name).unlink()
        flash(f"Deleted {name}")
    return redirect(url_for("index"))


# ---------------------------------------------------------------- settings

@app.route("/settings", methods=["GET", "POST"])
@login_required(admin=True)
def settings():
    s = R.load_settings()
    if request.method == "POST":
        f = request.form
        try:
            port = int(f.get("port") or 587)
            hour = int(f.get("hour") or 7)
            if not 0 <= hour <= 23:
                raise ValueError
        except ValueError:
            flash("Port and send hour must be numbers (hour 0 to 23)")
            return redirect(url_for("settings"))
        sections = {k: bool(f.get(f"sec_{k}")) for k, *_ in R.SECTIONS}
        if not any(sections.values()):
            flash("Pick at least one thing to include in the reports")
            return redirect(url_for("settings"))
        s["general"]["name"] = f.get("name", "").strip()[:60]
        s["sections"] = sections
        s["smtp"].update(host=f.get("host", "").strip(), port=port, security=f.get("security", "starttls"),
                         user=f.get("user", "").strip(), **{"from": f.get("from", "").strip()})
        if f.get("password"):  # blank keeps the saved password
            s["smtp"]["password"] = f["password"]
        if f.get("clear_password"):
            s["smtp"]["password"] = ""
        for k in ("weekly", "monthly", "quarterly"):
            s["recipients"][k] = ", ".join(R.split_addresses(f.get(f"to_{k}", "")))
        s["schedule"].update(enabled=bool(f.get("enabled")), hour=hour,
                             kinds=[k for k in ("weekly", "monthly", "quarterly") if f.get(f"auto_{k}")])
        R.save_settings(s)
        log.info("settings changed by %s", session["user"])
        flash("Settings saved")
        if f.get("action") == "test":
            to = f.get("test_to", "").strip()
            try:
                R.send_mail(to, f"{R.display_name()}: test email from the reports portal",
                            "This is a test from the reports portal. Email is working.")
                flash(f"Test email sent to {to}")
            except Exception as e:  # noqa: BLE001
                flash(f"Test email failed: {e}")
        return redirect(url_for("settings"))
    return render_template("settings.html", s=s, has_password=bool(s["smtp"].get("password")), sections=R.SECTIONS)


# ---------------------------------------------------------------- main

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s",
                        stream=sys.stdout)
    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=scheduler, daemon=True).start()
    from waitress import serve
    port = int(os.environ.get("PORTAL_PORT", 8088))
    log.info("portal on :%d, signing in through %s", port, GRAFANA)
    serve(app, host="0.0.0.0", port=port, threads=8)


if __name__ == "__main__":
    main()
