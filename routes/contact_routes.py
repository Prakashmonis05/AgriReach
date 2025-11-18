from flask import Blueprint, render_template, request, jsonify,session
from models import db, ChatMessage

contact = Blueprint('contact', __name__)

@contact.route("/contact", methods=["GET", "POST"])
def contact_page():

    if request.method == "GET":
        print("ROUTE HIT: GET")
        return render_template("contact.html")

    print("ROUTE HIT: POST")

    data = request.get_json()
    print("RAW JSON:", data)

    if not data or "message" not in data:
        print("ERROR: No message in JSON")
        return jsonify({"success": False, "error": "No message sent"}), 400

    message = data["message"]

    # GET REAL USER FROM SESSION
    user_id = session.get("user_id")
    user_name = session.get("user_name")

    print("SESSION USER:", user_id, user_name)

    if not user_id:
        print("ERROR: User not logged in")
        return jsonify({"success": False, "error": "User not logged in"}), 401

    new_msg = ChatMessage(
        user_id=user_id,
        sender="user",
        message=message
    )

    db.session.add(new_msg)
    db.session.commit()

    print("Message saved for user:", user_id)
    return jsonify({"success": True, "message": "Message stored"})




@contact.route("/contact/messages")
def get_chat_history():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"messages": []})

    msgs = ChatMessage.query.filter_by(user_id=user_id).order_by(ChatMessage.created_at).all()

    data = [
        {
            "sender": m.sender,
            "message": m.message,
            "time": m.created_at.strftime("%H:%M")
        }
        for m in msgs
    ]

    return jsonify({"messages": data})

@contact.route("/contact/clear", methods=["POST"])
def clear_chat():
    user_id = session.get("user_id")

    if not user_id:
        return jsonify({"success": False, "error": "User not logged in"}), 401

    ChatMessage.query.filter_by(user_id=user_id).delete()
    db.session.commit()

    return jsonify({"success": True, "message": "Chat cleared"})

