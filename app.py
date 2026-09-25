# language: Python 3.11+, file: app.py
# Kaze — GitHub OAuth + ZIP upload → auto push. Flask port of the Node version.
from __future__ import annotations

import os
import re
import io
import shutil
import secrets
import tempfile
import zipfile
from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from flask import (
    Flask, request, session, jsonify, redirect, send_file, abort
)
from git import Repo, Actor
from git.exc import GitCommandError

load_dotenv()

# ---------------- config ----------------

GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
SESSION_SECRET       = os.getenv("SESSION_SECRET") or secrets.token_hex(32)
PORT                 = int(os.getenv("PORT", "3000"))
BASE_URL             = (os.getenv("BASE_URL") or f"http://localhost:{PORT}").rstrip("/")

if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
    raise SystemExit(
        "\n[FATAL] GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET missing in .env\n"
        "  GitHub → Settings → Developer settings → OAuth Apps → New OAuth App\n"
    )

if not os.getenv("SESSION_SECRET"):
    print("[warn] SESSION_SECRET not set — sessions reset on restart.")

APP_DIR = Path(__file__).parent.resolve()

app = Flask(__name__, static_folder=None)
app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    SESSION_COOKIE_SECURE   = BASE_URL.startswith("https"),
    PERMANENT_SESSION_LIFETIME = timedelta(days=7),
    MAX_CONTENT_LENGTH      = 200 * 1024 * 1024,   # 200 MB
    JSON_SORT_KEYS          = False,
)

# ---------------- helpers ----------------

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("token"):
            return jsonify(ok=False, error="not_authenticated"), 401
        return f(*args, **kwargs)
    return wrapper


def gh_headers() -> dict:
    return {
        "Authorization": f"Bearer {session['token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "kaze-dashboard",
    }


def gh_paginate(url: str, params: dict | None = None) -> list:
    """Follow GitHub's Link: rel=next to fetch every page."""
    out = []
    cur_url, cur_params = url, params
    for _ in range(20):  # hard cap
        r = requests.get(cur_url, headers=gh_headers(), params=cur_params, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"GitHub API {r.status_code}: {r.text[:200]}")
        out.extend(r.json())
        link = r.headers.get("Link", "")
        nxt = None
        for part in link.split(","):
            if 'rel="next"' in part:
                nxt = part.split(";")[0].strip().strip("<>")
                break
        if not nxt:
            break
        cur_url, cur_params = nxt, None
    return out


def copy_tree(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True)
        else:
            shutil.copy2(item, target)


def safe_extract(zf: zipfile.ZipFile, target: Path) -> None:
    """Zip-slip-proof extraction."""
    target = target.resolve()
    for name in zf.namelist():
        dest = (target / name).resolve()
        if not str(dest).startswith(str(target) + os.sep) and dest != target:
            raise RuntimeError(f"Blocked unsafe path in zip: {name}")
    zf.extractall(target)


REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# ---------------- auth ----------------

@app.get("/auth/github")
def auth_github():
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/auth/github/callback",
        "scope": "repo read:user user:email",
        "allow_signup": "true",
    }
    return redirect(f"https://github.com/login/oauth/authorize?{urlencode(params)}")


@app.get("/auth/github/callback")
def auth_callback():
    err  = request.args.get("error")
    code = request.args.get("code")
    if err:
        return f"OAuth error: {err}", 400
    if not code:
        return "Missing code", 400

    try:
        token_r = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{BASE_URL}/auth/github/callback",
            },
            timeout=30,
        )
        data = token_r.json()
        token = data.get("access_token")
        if not token:
            return f"Token exchange failed: {data.get('error_description') or data.get('error')}", 400

        session.permanent = True
        session["token"] = token

        u = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "User-Agent": "kaze-dashboard"},
            timeout=30,
        ).json()

        session["user"] = {
            "login":        u.get("login"),
            "name":         u.get("name") or u.get("login"),
            "avatar":       u.get("avatar_url"),
            "html_url":     u.get("html_url"),
            "bio":          u.get("bio") or "",
            "public_repos": u.get("public_repos", 0),
            "followers":    u.get("followers", 0),
        }
        return redirect("/")
    except Exception as e:  # noqa: BLE001
        print("[oauth]", e)
        return f"OAuth failed: {e}", 500


@app.post("/auth/logout")
def auth_logout():
    session.clear()
    return jsonify(ok=True)


# ---------------- api ----------------

@app.get("/api/me")
@require_auth
def api_me():
    return jsonify(ok=True, user=session.get("user", {}))


@app.get("/api/repos")
@require_auth
def api_repos():
    try:
        raw = gh_paginate(
            "https://api.github.com/user/repos",
            params={"per_page": 100, "sort": "updated",
                    "affiliation": "owner,collaborator,organization_member"},
        )
        repos = [{
            "id":             r["id"],
            "full_name":      r["full_name"],
            "name":           r["name"],
            "owner":          r["owner"]["login"],
            "private":        r["private"],
            "default_branch": r.get("default_branch") or "main",
            "updated_at":     r.get("updated_at"),
            "language":       r.get("language"),
            "stars":          r.get("stargazers_count", 0),
            "forks":          r.get("forks_count", 0),
            "html_url":       r.get("html_url"),
        } for r in raw]
        return jsonify(ok=True, repos=repos)
    except Exception as e:  # noqa: BLE001
        print("[repos]", e)
        return jsonify(ok=False, error=str(e)), 500


@app.post("/api/repos/create")
@require_auth
def api_create_repo():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    desc = (body.get("description") or "").strip()
    private = bool(body.get("isPrivate", False))
    auto_init = bool(body.get("autoInit", True))

    if not REPO_NAME_RE.match(name):
        return jsonify(ok=False, error="invalid repo name"), 400

    try:
        r = requests.post(
            "https://api.github.com/user/repos",
            headers=gh_headers(),
            json={"name": name, "private": private,
                  "description": desc, "auto_init": auto_init},
            timeout=30,
        )
        if r.status_code >= 300:
            return jsonify(ok=False, error=r.json().get("message", r.text)), r.status_code

        repo = r.json()
        return jsonify(ok=True, repo={
            "full_name":      repo["full_name"],
            "name":           repo["name"],
            "owner":          repo["owner"]["login"],
            "default_branch": repo.get("default_branch") or "main",
            "private":        repo["private"],
            "html_url":       repo.get("html_url"),
            "language":       repo.get("language"),
            "stars":          repo.get("stargazers_count", 0),
            "forks":          repo.get("forks_count", 0),
            "updated_at":     repo.get("updated_at"),
        })
    except Exception as e:  # noqa: BLE001
        print("[create-repo]", e)
        return jsonify(ok=False, error=str(e)), 500


@app.get("/api/repos/<owner>/<repo>/branches")
@require_auth
def api_branches(owner: str, repo: str):
    try:
        r = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/branches",
            headers=gh_headers(), params={"per_page": 100}, timeout=30,
        )
        if r.status_code >= 300:
            return jsonify(ok=False, error=r.json().get("message", r.text)), r.status_code
        return jsonify(ok=True, branches=[b["name"] for b in r.json()])
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, error=str(e)), 500


@app.get("/api/repos/<owner>/<repo>/commits")
@require_auth
def api_commits(owner: str, repo: str):
    try:
        r = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/commits",
            headers=gh_headers(), params={"per_page": 8}, timeout=30,
        )
        if r.status_code >= 300:
            return jsonify(ok=False, error=r.json().get("message", r.text)), r.status_code

        out = []
        for c in r.json():
            sha = c["sha"]
            cm = c.get("commit", {})
            author_obj = c.get("author") or {}
            out.append({
                "sha":      sha,
                "short":    sha[:7],
                "message":  (cm.get("message") or "").split("\n")[0],
                "author":   (cm.get("author") or {}).get("name") or author_obj.get("login") or "unknown",
                "date":     (cm.get("author") or {}).get("date"),
                "avatar":   author_obj.get("avatar_url"),
                "html_url": c.get("html_url"),
            })
        return jsonify(ok=True, commits=out)
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, error=str(e)), 500


@app.post("/api/repos/<owner>/<repo>/star")
@require_auth
def api_star(owner: str, repo: str):
    try:
        base = f"https://api.github.com/user/starred/{owner}/{repo}"
        check = requests.get(base, headers=gh_headers(), timeout=30)
        if check.status_code == 204:
            requests.delete(base, headers=gh_headers(), timeout=30)
            return jsonify(ok=True, starred=False)
        requests.put(base, headers={**gh_headers(), "Content-Length": "0"}, timeout=30)
        return jsonify(ok=True, starred=True)
    except Exception as e:  # noqa: BLE001
        return jsonify(ok=False, error=str(e)), 500


# ---------------- upload → extract → push ----------------

@app.post("/api/upload")
@require_auth
def api_upload():
    file = request.files.get("zip")
    repo_name      = (request.form.get("repo") or "").strip()
    branch         = (request.form.get("branch") or "").strip() or "main"
    subfolder      = (request.form.get("subfolder") or "").strip()
    commit_message = (request.form.get("commitMessage") or "").strip()

    if not file:
        return jsonify(ok=False, error="zip file required"), 400
    if not REPO_RE.match(repo_name):
        return jsonify(ok=False, error='valid "owner/repo" required'), 400

    import time
    t0 = time.time()

    work_dir = Path(tempfile.mkdtemp(prefix="kaze-push-"))
    extract_dir = work_dir / "extract"
    clone_dir   = work_dir / "repo"
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        # 1) Save + extract ZIP
        buf = io.BytesIO(file.read())
        try:
            zf = zipfile.ZipFile(buf)
        except zipfile.BadZipFile:
            return jsonify(ok=False, error="Not a valid ZIP file"), 400
        safe_extract(zf, extract_dir)

        # flatten single-root folder
        source_dir = extract_dir
        top = list(extract_dir.iterdir())
        if len(top) == 1 and top[0].is_dir():
            source_dir = top[0]

        # 2) Clone target repo (token embedded in URL for auth)
        owner, repo_short = repo_name.split("/", 1)
        token = session["token"]
        clone_url = f"https://x-access-token:{token}@github.com/{owner}/{repo_short}.git"

        try:
            repo = Repo.clone_from(
                clone_url, clone_dir,
                branch=branch, depth=1, single_branch=True,
            )
        except GitCommandError as e:
            msg = str(e)
            if "Remote branch" in msg or "not found" in msg.lower():
                return jsonify(ok=False, error=f"Branch '{branch}' not found on {repo_name}"), 400
            if "Authentication failed" in msg or "403" in msg:
                return jsonify(ok=False, error="GitHub auth failed — token expired? Re-login."), 401
            raise

        # 3) Copy files into repo
        dest_root = (clone_dir / subfolder) if subfolder else clone_dir
        copy_tree(source_dir, dest_root)

        # 4) Stage + commit
        repo.git.add(A=True)

        if not repo.is_dirty(untracked_files=True) and not repo.index.diff("HEAD"):
            return jsonify(ok=False, error="No changes to commit — ZIP contents match repo."), 400

        author_name  = session["user"].get("name") or session["user"].get("login") or "kaze"
        author_email = f"{session['user']['login']}@users.noreply.github.com"
        actor = Actor(author_name, author_email)

        if not commit_message:
            from datetime import datetime, timezone
            commit_message = f"chore(kaze): upload {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"

        commit = repo.index.commit(commit_message, author=actor, committer=actor)

        # 5) Push (origin already has auth in URL)
        origin = repo.remote(name="origin")
        push_info = origin.push(refspec=f"{branch}:{branch}")

        # verify push actually landed
        for info in push_info:
            if info.flags & info.ERROR:
                return jsonify(ok=False, error=f"Push rejected: {info.summary.strip()}"), 500

        return jsonify(
            ok=True,
            commit=commit.hexsha,
            repo=repo_name,
            branch=branch,
            url=f"https://github.com/{repo_name}/tree/{branch}",
            duration_ms=int((time.time() - t0) * 1000),
        )

    except GitCommandError as e:
        print("[upload:git]", e)
        return jsonify(ok=False, error=str(e).strip()[:400]), 500
    except Exception as e:  # noqa: BLE001
        print("[upload]", e)
        return jsonify(ok=False, error=str(e)[:400]), 500
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


# ---------------- frontend ----------------

@app.get("/")
def index():
    return send_file(APP_DIR / "index.html")


@app.get("/favicon.ico")
def favicon():
    # inline SVG favicon is in index.html; return 204 to silence the request
    return ("", 204)


@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/") or request.path.startswith("/auth/"):
        return jsonify(ok=False, error="not_found"), 404
    return send_file(APP_DIR / "index.html")


if __name__ == "__main__":
    print(f"\n  風 Kaze — http://localhost:{PORT}")
    print(f"  Login:  {BASE_URL}/auth/github\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)
