from flask import Blueprint, render_template, jsonify
from models import Scheme

schemes = Blueprint('schemes', __name__)

@schemes.route("/api/schemes", methods=["GET"])
def get_schemes():
    all_schemes = (
        Scheme.query
        .order_by(Scheme.created_at.desc())
        .all()
    )

    data = [{
        "name": s.name,
        "state": s.state or "Central Government",
        "category": s.category,
        "description": s.description,
        "source": s.source,
        "scheme_url": s.scheme_url
    } for s in all_schemes]

    return jsonify({
        "count": len(data),
        "data": data
    }), 200


@schemes.route("/schemes")
def schemes_page():
    return render_template("schemes.html")
