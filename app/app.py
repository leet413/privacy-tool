"""Privacy Scanner web app: multi-user dashboard around privacy_scanner.py.

Run with exactly ONE gunicorn worker (several threads are fine): the scan queue
and its background worker thread live inside the process.
"""
import hmac
import json
import os
import queue
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import privacy_scanner as ps

DB_PATH = os.environ.get("DATABASE_PATH", "app.db")
SCAN_DELAY = float(os.environ.get("SCAN_DELAY", "2.5"))
BRAVE_AVAILABLE = bool(os.environ.get("BRAVE_API_KEY"))
STATUSES = ("todo", "submitted", "removed")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=14),
    MAX_CONTENT_LENGTH=64 * 1024,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS profiles(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL, names TEXT NOT NULL, city TEXT, state TEXT, street TEXT,
  emails TEXT, phones TEXT);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  profile_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE, profile_label TEXT,
  status TEXT NOT NULL, deep INTEGER NOT NULL DEFAULT 0, engine TEXT NOT NULL DEFAULT 'ddg',
  total INTEGER NOT NULL DEFAULT 0, done INTEGER NOT NULL DEFAULT 0,
  started TEXT, finished TEXT, result TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS tracker(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, domain TEXT NOT NULL,
  status TEXT NOT NULL, updated TEXT, PRIMARY KEY(user_id, domain));
"""


# ---------------------------------------------------------------- database
def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")


def connect():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()


def init_db():
    con = connect()
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    # scans that were mid-flight when the service stopped cannot resume
    con.execute("UPDATE scans SET status='failed', error='Interrupted by restart', finished=? "
                "WHERE status IN ('queued','running')", (now(),))
    con.commit()
    con.close()


# ---------------------------------------------------------------- auth
def current_user():
    if "user" not in g:
        uid = session.get("uid")
        g.user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None
    return g.user


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not current_user()["is_admin"]:
            abort(403)
        return fn(*a, **kw)
    return wrapper


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("dashboard")


_fails = {}


def too_many_attempts(ip):
    t = time.time()
    _fails[ip] = [x for x in _fails.get(ip, []) if t - x < 600]
    return len(_fails[ip]) >= 10


def create_user(username, pw, confirm, admin=False):
    username = username.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,32}", username):
        return "Username must be 3-32 characters: letters, numbers, dot, dash, underscore."
    if len(pw) < 10:
        return "Password must be at least 10 characters."
    if pw != confirm:
        return "Passwords do not match."
    try:
        db().execute("INSERT INTO users(username,pw_hash,is_admin,created) VALUES(?,?,?,?)",
                     (username, generate_password_hash(pw), 1 if admin else 0, now()))
        db().commit()
    except sqlite3.IntegrityError:
        return "That username is already taken."
    return None


@app.before_request
def guard():
    if request.method == "POST":
        token = session.get("csrf", "")
        if not token or not hmac.compare_digest(token, request.form.get("csrf", "")):
            abort(400)
    if request.endpoint not in ("static", "healthz", "setup"):
        if not db().execute("SELECT 1 FROM users LIMIT 1").fetchone():
            return redirect(url_for("setup"))


@app.context_processor
def inject():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return {"csrf": session["csrf"], "user": current_user(), "brave_available": BRAVE_AVAILABLE}


@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/healthz")
def healthz():
    return "ok"


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if db().execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return redirect(url_for("login"))
    if request.method == "POST":
        err = create_user(request.form.get("username", ""), request.form.get("password", ""),
                          request.form.get("confirm", ""), admin=True)
        if err:
            flash(err, "err")
        else:
            flash("Admin account created. Sign in below.", "ok")
            return redirect(url_for("login"))
    return render_template("auth.html", title="First-run setup: create the admin account",
                           button="Create admin account", confirm=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if too_many_attempts(ip):
            flash("Too many attempts. Try again in a few minutes.", "err")
        else:
            u = db().execute("SELECT * FROM users WHERE username=?",
                             (request.form.get("username", "").strip().lower(),)).fetchone()
            if u and check_password_hash(u["pw_hash"], request.form.get("password", "")):
                session.clear()
                session["uid"] = u["id"]
                session.permanent = True
                return redirect(safe_next(request.args.get("next")))
            _fails.setdefault(ip, []).append(time.time())
            flash("Invalid username or password.", "err")
    return render_template("auth.html", title="Sign in", button="Sign in", confirm=False)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        u = current_user()
        new, confirm = request.form.get("new", ""), request.form.get("confirm", "")
        if not check_password_hash(u["pw_hash"], request.form.get("current", "")):
            flash("Current password is incorrect.", "err")
        elif len(new) < 10 or new != confirm:
            flash("New password must be 10+ characters and match the confirmation.", "err")
        else:
            db().execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new), u["id"]))
            db().commit()
            flash("Password changed.", "ok")
    return render_template("account.html")


# ---------------------------------------------------------------- data helpers
def split_lines(s):
    return [x.strip() for x in re.split(r"[\n,]", s or "") if x.strip()]


def to_profile(p):
    names = [n.strip() for n in (p["names"] or "").splitlines() if n.strip()]
    parts = names[0].split()
    return {"names": names, "first": parts[0], "last": parts[-1], "city": p["city"] or "",
            "state": p["state"] or "", "street": p["street"] or "",
            "emails": split_lines(p["emails"]), "phones": split_lines(p["phones"])}


def own_profile(pid):
    row = db().execute("SELECT * FROM profiles WHERE id=? AND user_id=?",
                       (pid, current_user()["id"])).fetchone()
    return row or abort(404)


def own_scan(sid):
    row = db().execute("SELECT * FROM scans WHERE id=? AND user_id=?",
                       (sid, current_user()["id"])).fetchone()
    return row or abort(404)


def tracker_map(uid):
    return {r["domain"]: r["status"] for r in
            db().execute("SELECT domain,status FROM tracker WHERE user_id=?", (uid,))}


def latest_found(uid):
    """domain -> best confidence, from the most recent finished scan of each profile."""
    out, seen = {}, set()
    for r in db().execute("SELECT profile_id,result FROM scans WHERE user_id=? AND status='done' "
                          "ORDER BY id DESC", (uid,)):
        if r["profile_id"] in seen:
            continue
        seen.add(r["profile_id"])
        for dom, e in json.loads(r["result"] or "{}").get("found", {}).items():
            if dom not in out or ps.CONF_ORDER[e["best"]] < ps.CONF_ORDER[out[dom]]:
                out[dom] = e["best"]
    return out


# ---------------------------------------------------------------- pages
@app.route("/")
@login_required
def dashboard():
    uid = current_user()["id"]
    profiles = db().execute("SELECT * FROM profiles WHERE user_id=? ORDER BY id", (uid,)).fetchall()
    scans = db().execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)).fetchall()
    found, tr = latest_found(uid), tracker_map(uid)
    stats = {"found": len(found),
             "todo": sum(1 for d in found if tr.get(d, "todo") == "todo"),
             "removed": sum(1 for s in tr.values() if s == "removed"),
             "relisted": sum(1 for d in found if tr.get(d) == "removed")}
    return render_template("dashboard.html", profiles=profiles, scans=scans, stats=stats)


def read_profile_form(f):
    names = [n.strip()[:100] for n in f.get("names", "").splitlines() if n.strip()]
    if not names or len(names[0].split()) < 2:
        return None, "The first line of Names must contain a first and last name."
    data = {"label": (f.get("label", "").strip() or names[0])[:60], "names": "\n".join(names[:5]),
            "city": f.get("city", "").strip()[:80], "state": f.get("state", "").strip()[:30],
            "street": f.get("street", "").strip()[:120],
            "emails": "\n".join(split_lines(f.get("emails", ""))[:5]),
            "phones": "\n".join(split_lines(f.get("phones", ""))[:5])}
    return data, None


@app.route("/profile/new", methods=["GET", "POST"])
@login_required
def profile_new():
    if request.method == "POST":
        data, err = read_profile_form(request.form)
        if err:
            flash(err, "err")
        else:
            db().execute("INSERT INTO profiles(user_id,label,names,city,state,street,emails,phones) "
                         "VALUES(?,?,?,?,?,?,?,?)",
                         (current_user()["id"], data["label"], data["names"], data["city"], data["state"],
                          data["street"], data["emails"], data["phones"]))
            db().commit()
            flash("Profile saved.", "ok")
            return redirect(url_for("dashboard"))
    return render_template("profile.html", p=request.form if request.method == "POST" else {}, editing=False)


@app.route("/profile/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def profile_edit(pid):
    p = own_profile(pid)
    if request.method == "POST":
        data, err = read_profile_form(request.form)
        if err:
            flash(err, "err")
            p = request.form
        else:
            db().execute("UPDATE profiles SET label=?,names=?,city=?,state=?,street=?,emails=?,phones=? WHERE id=?",
                         (data["label"], data["names"], data["city"], data["state"], data["street"],
                          data["emails"], data["phones"], pid))
            db().commit()
            flash("Profile updated.", "ok")
            return redirect(url_for("dashboard"))
    return render_template("profile.html", p=p, editing=True, pid=pid)


@app.post("/profile/<int:pid>/delete")
@login_required
def profile_delete(pid):
    own_profile(pid)
    db().execute("DELETE FROM profiles WHERE id=?", (pid,))  # cascades to its scans
    db().commit()
    flash("Profile and its scan history deleted.", "ok")
    return redirect(url_for("dashboard"))


@app.post("/profile/<int:pid>/scan")
@login_required
def scan_start(pid):
    p = own_profile(pid)
    engine = request.form.get("engine", "ddg")
    if engine not in ("ddg", "brave") or (engine == "brave" and not BRAVE_AVAILABLE):
        engine = "ddg"
    active = db().execute("SELECT id FROM scans WHERE profile_id=? AND status IN ('queued','running')",
                          (pid,)).fetchone()
    if active:
        return redirect(url_for("scan_view", sid=active["id"]))
    cur = db().execute("INSERT INTO scans(user_id,profile_id,profile_label,status,deep,engine,started) "
                       "VALUES(?,?,?,?,?,?,?)",
                       (current_user()["id"], pid, p["label"], "queued",
                        1 if request.form.get("deep") else 0, engine, now()))
    db().commit()
    scan_queue.put(cur.lastrowid)
    return redirect(url_for("scan_view", sid=cur.lastrowid))


@app.route("/scan/<int:sid>")
@login_required
def scan_view(sid):
    s = own_scan(sid)
    res = json.loads(s["result"]) if s["result"] else {"found": {}, "possible": {}, "errors": 0}
    found = sorted(res["found"].items(), key=lambda kv: (ps.CONF_ORDER[kv[1]["best"]], kv[1]["name"].lower()))
    possible = sorted(res["possible"].items())
    return render_template("scan.html", s=s, found=found, possible=possible, errors=res.get("errors", 0),
                           tr=tracker_map(current_user()["id"]))


@app.route("/scan/<int:sid>/status")
@login_required
def scan_status(sid):
    s = own_scan(sid)
    return jsonify(status=s["status"], done=s["done"], total=s["total"])


@app.post("/scan/<int:sid>/cancel")
@login_required
def scan_cancel(sid):
    own_scan(sid)
    db().execute("UPDATE scans SET status='cancelled', finished=? WHERE id=? AND status IN ('queued','running')",
                 (now(), sid))
    db().commit()
    return redirect(url_for("scan_view", sid=sid))


@app.post("/scan/<int:sid>/delete")
@login_required
def scan_delete(sid):
    own_scan(sid)
    db().execute("DELETE FROM scans WHERE id=? AND status NOT IN ('queued','running')", (sid,))
    db().commit()
    return redirect(url_for("dashboard"))


@app.route("/tracker")
@login_required
def tracker():
    uid = current_user()["id"]
    tr, found = tracker_map(uid), latest_found(uid)
    rows = [{"domain": d, "name": n, "optout": o, "note": note, "status": tr.get(d, "todo"),
             "found": found.get(d)} for d, (n, o, note) in ps.BROKERS.items()]
    rows.sort(key=lambda r: (r["found"] is None, r["status"] == "removed", r["name"].lower()))
    return render_template("tracker.html", rows=rows, extras=ps.EXTRA_RESOURCES)


@app.post("/tracker/set")
@login_required
def tracker_set():
    domain = request.form.get("domain", "").strip().lower()
    status = request.form.get("status", "")
    if status not in STATUSES or not re.fullmatch(r"[a-z0-9.-]{3,100}", domain):
        abort(400)
    db().execute("INSERT INTO tracker(user_id,domain,status,updated) VALUES(?,?,?,?) "
                 "ON CONFLICT(user_id,domain) DO UPDATE SET status=excluded.status, updated=excluded.updated",
                 (current_user()["id"], domain, status, now()))
    db().commit()
    return redirect(safe_next(request.form.get("next")))


# ---------------------------------------------------------------- admin (accounts only; admins cannot see others' data)
@app.route("/admin")
@admin_required
def admin():
    users = db().execute(
        "SELECT u.*, (SELECT COUNT(*) FROM profiles WHERE user_id=u.id) AS n_profiles, "
        "(SELECT COUNT(*) FROM scans WHERE user_id=u.id) AS n_scans FROM users u ORDER BY u.id").fetchall()
    return render_template("admin.html", users=users)


@app.post("/admin/users/create")
@admin_required
def admin_create():
    err = create_user(request.form.get("username", ""), request.form.get("password", ""),
                      request.form.get("password", ""), admin=bool(request.form.get("is_admin")))
    flash(err or "User created.", "err" if err else "ok")
    return redirect(url_for("admin"))


@app.post("/admin/users/<int:uid>/reset")
@admin_required
def admin_reset(uid):
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() or abort(404)
    temp = secrets.token_urlsafe(9)
    db().execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(temp), uid))
    db().commit()
    flash("Temporary password for %s: %s (shown once; ask them to change it)." % (u["username"], temp), "ok")
    return redirect(url_for("admin"))


@app.post("/admin/users/<int:uid>/delete")
@admin_required
def admin_delete(uid):
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() or abort(404)
    if uid == current_user()["id"]:
        flash("You cannot delete your own account.", "err")
    else:
        db().execute("DELETE FROM users WHERE id=?", (uid,))
        db().commit()
        flash("Deleted %s and all of their data." % u["username"], "ok")
    return redirect(url_for("admin"))


# ---------------------------------------------------------------- scan worker
scan_queue = queue.Queue()


def safe_search(engine, query):
    fn = ps.search_brave if engine == "brave" else ps.search_ddg
    for attempt in range(3):
        try:
            return fn(query, 20), False
        except Exception:
            time.sleep(3 * (attempt + 1))
    return [], True


def run_scan(sid):
    con = connect()
    try:
        s = con.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not s or s["status"] != "queued":
            return
        p = con.execute("SELECT * FROM profiles WHERE id=?", (s["profile_id"],)).fetchone()
        if not p:
            return
        profile = to_profile(p)
        queries = ps.build_queries(profile, bool(s["deep"]))
        con.execute("UPDATE scans SET status='running', total=?, done=0 WHERE id=?", (len(queries), sid))
        con.commit()

        found, possible, seen, errors = {}, {}, set(), 0
        for i, q in enumerate(queries, 1):
            cur = con.execute("SELECT status FROM scans WHERE id=?", (sid,)).fetchone()
            if not cur or cur["status"] != "running":
                return  # cancelled or deleted
            results, failed = safe_search(s["engine"], q)
            errors += failed
            for r in results:
                if not r["url"] or r["url"] in seen:
                    continue
                seen.add(r["url"])
                host = ps.hostname(r["url"])
                conf, pts = ps.score(r, profile)
                domain = ps.match_broker(host)
                if domain:
                    name, optout, note = ps.BROKERS[domain]
                    bucket, key = found, domain
                elif ps.looks_like_broker(host) and pts >= 2:
                    name, optout, note = host, None, "Unrecognized site that looks like a people-search broker."
                    bucket, key = possible, host
                else:
                    continue
                e = bucket.setdefault(key, {"name": name, "optout": optout, "note": note, "hits": [], "best": "low"})
                e["hits"].append({"title": r["title"], "url": r["url"], "conf": conf})
                if ps.CONF_ORDER[conf] < ps.CONF_ORDER[e["best"]]:
                    e["best"] = conf
            con.execute("UPDATE scans SET done=? WHERE id=?", (i, sid))
            con.commit()
            time.sleep(SCAN_DELAY)

        if errors >= len(queries):
            raise RuntimeError("Every search failed (rate-limited, or the container has no internet access).")
        if not s["deep"]:
            found = {d: e for d, e in found.items() if any(h["conf"] != "low" for h in e["hits"])}
        con.execute("UPDATE scans SET status='done', finished=?, result=? WHERE id=? AND status='running'",
                    (now(), json.dumps({"found": found, "possible": possible, "errors": errors}), sid))
        con.commit()
    except (Exception, SystemExit) as exc:
        con.execute("UPDATE scans SET status='failed', error=?, finished=? WHERE id=?",
                    (str(exc)[:500], now(), sid))
        con.commit()
    finally:
        con.close()


def worker():
    while True:
        sid = scan_queue.get()
        try:
            run_scan(sid)
        except Exception as exc:  # never let the worker die
            print("scan worker error:", exc)


init_db()
threading.Thread(target=worker, daemon=True, name="scan-worker").start()
