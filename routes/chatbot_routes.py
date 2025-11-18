from flask import Blueprint, render_template, request, jsonify,session
import requests
from models import db, ChatMemory

chatbot = Blueprint('chatbot', __name__)

API_KEY = "sk-or-your-key"
BASE_URL = "https://openrouter.ai/api/v1/chat/completions"


def clean_output(text):
    bad_tokens = [
        "<｜begin▁of▁sentence｜>",
        "<｜end▁of▁sentence｜>",
        "<|im_end|>",
        "<|im_start|>"
    ]
    for t in bad_tokens:
        text = text.replace(t, "")
    return text.strip()


def get_bot_response(user_message):
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": "deepseek/deepseek-chat-v3.1:free",
        "messages": [
            {"role": "system", "content": "You are AgriBot..."},
            {"role": "user", "content": user_message}
        ]
    }

    response = requests.post(BASE_URL, headers=headers, json=data)

    if response.status_code == 200:
        output = response.json()["choices"][0]["message"]["content"]
        return clean_output(output)

    return f"API Error {response.status_code}"


@chatbot.route("/chatbot")
def chatbot_page():
    user_id = session.get("user_id", "guest")

    history = ChatMemory.query.filter_by(user_id=user_id)\
             .order_by(ChatMemory.timestamp.asc()).all()

    return render_template("chatbot.html", history=history)



@chatbot.route("/chat", methods=["POST"])
def chatbot_api():
    data = request.get_json()
    user_message = data.get("message", "")

    if not user_message:
        return jsonify({"reply": "⚠️ No message received."})

    # 🔐 Get current user ID (assuming login session stores it)
    user_id = session.get("user_id", "guest")   # fallback

    # 📝 Store user message
    user_entry = ChatMemory(
        user_id=user_id,
        role="user",
        message=user_message
    )
    db.session.add(user_entry)
    db.session.commit()

    # 🤖 Get bot reply
    bot_reply = get_bot_response(user_message)

    # 📝 Store bot reply
    bot_entry = ChatMemory(
        user_id=user_id,
        role="assistant",
        message=bot_reply
    )
    db.session.add(bot_entry)
    db.session.commit()

    return jsonify({"reply": bot_reply})
