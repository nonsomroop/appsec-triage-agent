"""Persistent dashboard projects and their scan reports."""
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

# Human review outcomes, kept separate from AI verdicts.
REVIEW_VERDICTS = {"confirmed": "Confirmed", "false_positive": "False positive",
                   "accepted_risk": "Accepted risk", "fixed": "Fixed"}


class History:
    def __init__(self, directory):
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / "history.sqlite3"
        # Only the dashboard holding this lease may recover unfinished runs.
        self.lease = sqlite3.connect(directory / "dashboard.lock", timeout=0)
        try:
            self.lease.execute("BEGIN EXCLUSIVE")
        except sqlite3.Error:
            self.lease.close()
            raise
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL,
                    target TEXT NOT NULL, branch TEXT NOT NULL, mount TEXT NOT NULL,
                    UNIQUE(name, source, target, branch, mount)
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id),
                    started TEXT NOT NULL, scanner TEXT NOT NULL, mode TEXT NOT NULL,
                    status TEXT NOT NULL, revision TEXT, error TEXT, report TEXT
                );
                CREATE INDEX IF NOT EXISTS runs_project ON runs(project_id, id);
                CREATE TABLE IF NOT EXISTS reviews (
                    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    finding_id TEXT NOT NULL, verdict TEXT NOT NULL, reviewer TEXT NOT NULL DEFAULT '',
                    updated TEXT NOT NULL, PRIMARY KEY(project_id, finding_id)
                );
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    finding_id TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'comment', author TEXT NOT NULL DEFAULT '',
                    body TEXT NOT NULL, created TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS comments_finding ON comments(project_id, finding_id, id);
            """)
            # Older databases predate saved run settings (finding limit, AI provider and model).
            if "settings" not in {row["name"] for row in db.execute("PRAGMA table_info(runs)")}:
                db.execute("ALTER TABLE runs ADD COLUMN settings TEXT")
            db.execute("UPDATE runs SET status='failed', error='Dashboard stopped before the scan finished.' WHERE status='running'")

    @contextmanager
    def connection(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            # Reports hold source excerpts; overwrite deleted content instead of leaving it in free pages.
            db.execute("PRAGMA secure_delete=ON")
            yield db

    def project(self, name, source, target, branch, mount):
        key = (name, source, target, branch, mount)
        with self.connection() as db:
            db.execute("INSERT OR IGNORE INTO projects(name,source,target,branch,mount) VALUES(?,?,?,?,?)", key)
            return db.execute("SELECT id FROM projects WHERE name=? AND source=? AND target=? AND branch=? AND mount=?", key).fetchone()[0]

    def projects(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT * FROM projects ORDER BY name, id")]

    def start(self, project, scanner, mode, settings=None):
        with self.connection() as db:
            return db.execute("INSERT INTO runs(project_id,started,scanner,mode,status,settings) VALUES(?,?,?,?,'running',?)",
                              (project, datetime.now(timezone.utc).isoformat(), scanner, mode,
                               json.dumps(settings) if settings else None)).lastrowid

    def finish(self, run, job, revision):
        report = job.get("report")
        status = report["scan"]["status"] if report else "cancelled" if job.get("status") == "cancelled" else "failed"
        with self.connection() as db:
            db.execute("UPDATE runs SET status=?,revision=?,error=?,report=? WHERE id=?",
                       (status, revision, job.get("error"), json.dumps(report) if report else None, run))
            return db.execute("SELECT project_id FROM runs WHERE id=?", (run,)).fetchone()[0]

    @staticmethod
    def _run(row):
        run = dict(row)
        run["settings"] = json.loads(run["settings"]) if run.get("settings") else {}
        return run

    def delete_project(self, project):
        """Delete a project and every saved scan of it. Returns the number of scans removed, or None."""
        with self.connection() as db:
            if not db.execute("SELECT 1 FROM projects WHERE id=?", (project,)).fetchone():
                return None
            removed = db.execute("DELETE FROM runs WHERE project_id=?", (project,)).rowcount
            db.execute("DELETE FROM comments WHERE project_id=?", (project,))
            db.execute("DELETE FROM reviews WHERE project_id=?", (project,))
            db.execute("DELETE FROM projects WHERE id=?", (project,))
            return removed

    def runs(self, project):
        with self.connection() as db:
            return [self._run(r) for r in db.execute(
                "SELECT id,started,scanner,mode,status,revision,error,settings FROM runs WHERE project_id=? ORDER BY id DESC",
                (project,))]

    def run(self, run):
        with self.connection() as db:
            row = db.execute("SELECT id,project_id,scanner,mode,status,settings FROM runs WHERE id=?", (run,)).fetchone()
            return self._run(row) if row else None

    def result(self, run):
        with self.connection() as db:
            row = db.execute("SELECT status,error,report FROM runs WHERE id=?", (run,)).fetchone()
            if row:
                return {"status": row["status"], "error": row["error"],
                        "report": json.loads(row["report"]) if row["report"] else None}

    # ---------- human review ----------
    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def reviews(self, project):
        """Human verdicts and comment threads for a project, keyed by finding ID."""
        with self.connection() as db:
            result = {}
            for row in db.execute("SELECT finding_id,verdict,reviewer,updated FROM reviews WHERE project_id=?", (project,)):
                result[row["finding_id"]] = {"verdict": row["verdict"], "reviewer": row["reviewer"],
                                             "updated": row["updated"], "comments": []}
            for row in db.execute("SELECT id,finding_id,kind,author,body,created FROM comments "
                                  "WHERE project_id=? ORDER BY id", (project,)):
                entry = result.setdefault(row["finding_id"], {"verdict": None, "reviewer": "", "updated": None, "comments": []})
                entry["comments"].append({key: row[key] for key in ("id", "kind", "author", "body", "created")})
            return result

    def set_review(self, project, finding, verdict, reviewer):
        """Set or clear a verdict and record the change in the finding's thread."""
        if verdict is not None and verdict not in REVIEW_VERDICTS:
            raise ValueError("Unknown review verdict")
        now = self._now()
        with self.connection() as db:
            previous = db.execute("SELECT verdict FROM reviews WHERE project_id=? AND finding_id=?",
                                  (project, finding)).fetchone()
            previous = previous["verdict"] if previous else None
            if previous == verdict:
                return False
            if verdict is None:
                db.execute("DELETE FROM reviews WHERE project_id=? AND finding_id=?", (project, finding))
                body = f"Cleared the review (was {REVIEW_VERDICTS[previous]})"
            else:
                db.execute("INSERT INTO reviews(project_id,finding_id,verdict,reviewer,updated) VALUES(?,?,?,?,?) "
                           "ON CONFLICT(project_id,finding_id) DO UPDATE SET verdict=excluded.verdict,"
                           "reviewer=excluded.reviewer,updated=excluded.updated",
                           (project, finding, verdict, reviewer, now))
                body = f"Marked as {REVIEW_VERDICTS[verdict]}" + (f" (was {REVIEW_VERDICTS[previous]})" if previous else "")
            db.execute("INSERT INTO comments(project_id,finding_id,kind,author,body,created) VALUES(?,?,'event',?,?,?)",
                       (project, finding, reviewer, body, now))
            return True

    def add_comment(self, project, finding, author, body):
        now = self._now()
        with self.connection() as db:
            comment = db.execute("INSERT INTO comments(project_id,finding_id,kind,author,body,created) "
                                 "VALUES(?,?,'comment',?,?,?)", (project, finding, author, body, now)).lastrowid
        return {"id": comment, "kind": "comment", "author": author, "body": body, "created": now}

    def delete_comment(self, comment):
        """Delete a written comment. Review events stay as the audit trail."""
        with self.connection() as db:
            row = db.execute("SELECT project_id FROM comments WHERE id=? AND kind='comment'", (comment,)).fetchone()
            if not row:
                return None
            db.execute("DELETE FROM comments WHERE id=?", (comment,))
            return row["project_id"]
