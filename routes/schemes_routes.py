from flask import Blueprint, render_template, jsonify
from models import db, Scheme

schemes = Blueprint('schemes', __name__)

@schemes.route("/api/schemes", methods=["GET"])
def get_schemes():
    try:
        all_schemes = Scheme.query.order_by(Scheme.id.desc()).all()

        result = [{
            "id": s.id,
            "name": s.name,
            "launch_year": s.launch_year,
            "ministry": s.ministry,
            "type": s.type,
            "status": s.status,
            "objective": s.objective,
            "benefit": s.benefit,
            "eligibility": s.eligibility,
            "category": s.category
        } for s in all_schemes]

        return jsonify({
            "success": True,
            "count": len(result),
            "data": result
        }), 200

    except Exception as e:
        print("DB Error:", e)
        return jsonify({"success": False, "message": "DB fetch error"}), 500


@schemes.route("/schemes")
def schemes_page():
    all_schemes = Scheme.query.order_by(Scheme.id.desc()).all()
    return render_template("schemes.html", schemes=all_schemes)
