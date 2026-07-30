import os
import sys

from flask import Flask

# make the top-level engine/ and ml/ packages importable, and ensure the
# joblib bundle can unpickle its encoder (defined in ml/preprocess.py)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "ml")):
    if path not in sys.path:
        sys.path.insert(0, path)

from config import Config  # noqa: E402
from .extensions import csrf, db, login_manager  # noqa: E402
from .models import DEFAULT_SETTINGS, Setting, User  # noqa: E402

monitor = None


def create_app(config_class=Config, start_monitor=True):
    app = Flask(
        __name__,
        template_folder=os.path.join(ROOT, "templates"),
        static_folder=os.path.join(ROOT, "static"),
    )
    app.config.from_object(config_class)

    os.makedirs(os.path.join(ROOT, "instance"), exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    _enable_sqlite_concurrency()

    from .auth import auth_bp
    from .views import views_bp
    from .api import api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)  # dashboard polling uses JSON; guarded by login instead

    with app.app_context():
        db.create_all()
        _seed_settings()
        _seed_admin(app)

    if start_monitor:
        _launch_monitor(app)

    return app


def _enable_sqlite_concurrency():
    """WAL + busy timeout so the capture thread and web requests can write to
    the same SQLite file without tripping over each other."""
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    @event.listens_for(Engine, "connect")
    def _set_pragmas(dbapi_conn, _record):  # noqa: ANN001
        try:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()
        except Exception:
            pass


def _seed_settings():
    for key, value in DEFAULT_SETTINGS.items():
        if not db.session.get(Setting, key):
            db.session.add(Setting(key=key, value=value))
    db.session.commit()


def _seed_admin(app):
    if not User.query.first():
        admin = User(username="admin", email="admin@smartfw.local", role="admin")
        admin.set_password(os.environ.get("ADMIN_PASSWORD", "admin123"))
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Seeded default admin account (admin / admin123)")


def _launch_monitor(app):
    global monitor
    from .monitor import Monitor
    monitor = Monitor(app)
    monitor.configure_enforcement()
    app.monitor = monitor
    return monitor
