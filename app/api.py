from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
from flask_login import login_required
from sqlalchemy import func

from .extensions import db
from .models import BlockedIP, ThreatAlert, TrafficEvent

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _monitor():
    return getattr(current_app, "monitor", None)


@api_bp.route("/overview")
@login_required
def overview():
    mon = _monitor()
    snap = mon.snapshot() if mon else {}

    since = datetime.utcnow() - timedelta(hours=24)
    total = TrafficEvent.query.count()
    blocked = TrafficEvent.query.filter_by(verdict="block").count()
    flagged = TrafficEvent.query.filter_by(verdict="flag").count()
    active_blocks = BlockedIP.query.filter_by(active=True).count()
    unack = ThreatAlert.query.filter_by(acknowledged=False).count()

    breakdown = (db.session.query(TrafficEvent.attack_type,
                                  func.count(TrafficEvent.id))
                 .filter(TrafficEvent.attack_type.isnot(None))
                 .group_by(TrafficEvent.attack_type).all())

    protocols = (db.session.query(TrafficEvent.protocol,
                                  func.count(TrafficEvent.id))
                 .group_by(TrafficEvent.protocol).all())

    return jsonify({
        "snapshot": snap,
        "totals": {
            "events": total, "blocked": blocked, "flagged": flagged,
            "active_blocks": active_blocks, "open_alerts": unack,
        },
        "attack_breakdown": [{"type": t or "Unknown", "count": c}
                             for t, c in breakdown],
        "protocols": [{"protocol": p or "?", "count": c} for p, c in protocols],
    })


@api_bp.route("/events")
@login_required
def events():
    verdict = request.args.get("verdict")
    q = TrafficEvent.query.order_by(TrafficEvent.id.desc())
    if verdict in ("allow", "flag", "block"):
        q = q.filter_by(verdict=verdict)
    rows = q.limit(60).all()
    return jsonify([r.as_dict() for r in rows])


@api_bp.route("/alerts")
@login_required
def alerts():
    rows = ThreatAlert.query.order_by(ThreatAlert.ts.desc()).limit(50).all()
    return jsonify([r.as_dict() for r in rows])


@api_bp.route("/blocked")
@login_required
def blocked():
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).limit(100).all()
    return jsonify([r.as_dict() for r in rows])


@api_bp.route("/capture/start", methods=["POST"])
@login_required
def capture_start():
    mon = _monitor()
    if not mon:
        return jsonify({"ok": False, "message": "Engine not ready."}), 503
    data = request.get_json(silent=True) or {}
    iface = data.get("interface") or None
    ok, msg = mon.start_capture(iface)
    return jsonify({"ok": ok, "message": msg})


@api_bp.route("/capture/stop", methods=["POST"])
@login_required
def capture_stop():
    mon = _monitor()
    if mon:
        mon.stop_capture()
    return jsonify({"ok": True, "message": "Capture stopped."})


@api_bp.route("/simulate", methods=["POST"])
@login_required
def simulate():
    mon = _monitor()
    if not mon:
        return jsonify({"ok": False, "message": "Engine not ready."}), 503
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "mixed")
    count = mon.inject_scenario(scenario)
    return jsonify({"ok": True, "message": f"Injected {count} {scenario} flows.",
                    "count": count})


@api_bp.route("/blocked/<int:block_id>/unblock", methods=["POST"])
@login_required
def unblock(block_id):
    mon = _monitor()
    row = db.session.get(BlockedIP, block_id)
    if not row:
        return jsonify({"ok": False, "message": "Not found."}), 404
    if mon and mon.firewall:
        mon.firewall.unblock(row.ip)
        mon.blocked_ips.discard(row.ip)
        mon.mal_counts[row.ip] = 0
    row.active = False
    row.unblocked_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True, "message": f"Unblocked {row.ip}."})


@api_bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
@login_required
def ack(alert_id):
    row = db.session.get(ThreatAlert, alert_id)
    if not row:
        return jsonify({"ok": False}), 404
    row.acknowledged = True
    db.session.commit()
    return jsonify({"ok": True})
