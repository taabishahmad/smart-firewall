import json
import os

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from .extensions import db
from .models import (ActivityLog, BlockedIP, Setting, ThreatAlert,
                     TrafficEvent)

views_bp = Blueprint("views", __name__)

METRICS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ml", "artifacts", "metrics.json")


def _metrics():
    try:
        with open(METRICS_PATH) as fh:
            return json.load(fh)
    except Exception:
        return None


@views_bp.route("/")
def landing():
    if current_user.is_authenticated:
        return redirect(url_for("views.dashboard"))
    return render_template("landing.html")


@views_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@views_bp.route("/traffic")
@login_required
def traffic():
    return render_template("traffic.html", active="traffic")


@views_bp.route("/threats")
@login_required
def threats():
    alerts = (ThreatAlert.query.order_by(ThreatAlert.ts.desc())
              .limit(100).all())
    return render_template("threats.html", active="threats", alerts=alerts)


@views_bp.route("/blocked")
@login_required
def blocked():
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return render_template("blocked.html", active="blocked", rows=rows)


@views_bp.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html", active="analytics",
                           metrics=_metrics())


@views_bp.route("/logs")
@login_required
def logs():
    rows = ActivityLog.query.order_by(ActivityLog.ts.desc()).limit(200).all()
    return render_template("logs.html", active="logs", rows=rows)


@views_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        keys = ["block_threshold", "min_confidence", "auto_block",
                "whitelist", "capture_interface", "enforcement_mode"]
        for key in keys:
            if key in request.form:
                row = db.session.get(Setting, key)
                if row:
                    row.value = request.form.get(key)
                else:
                    db.session.add(Setting(key=key, value=request.form.get(key)))
        # checkbox: unchecked means absent
        auto = db.session.get(Setting, "auto_block")
        if auto:
            auto.value = "on" if request.form.get("auto_block") else "off"
        db.session.commit()
        flash("Settings saved.", "success")
        return redirect(url_for("views.settings"))

    values = {s.key: s.value for s in Setting.query.all()}
    mon = getattr(current_app, "monitor", None)
    return render_template("settings.html", active="settings",
                           values=values,
                           enforcement=mon.firewall.mode if mon and mon.firewall else "-")


@views_bp.route("/about")
@login_required
def about():
    return render_template("about.html", active="about")
