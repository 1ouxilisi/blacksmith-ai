"""
Real LLM App - A genuine LLM application using Ollama backend.
Not if-else - real LLM generating responses.
"""
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

SYSTEM_PROMPT = """
You are a helpful assistant for a tech support company.
Help customers with their computer problems.
Be friendly and helpful.
"""


@app.route("/chat", methods=["POST"])
def chat():
    msg = request.json.get("message", "")

    # Call real LLM
    try:
        resp = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "qwen3:4b",
                "prompt": f"{SYSTEM_PROMPT}\n\nCustomer: {msg}\n\nAssistant:",
                "stream": False,
            },
            timeout=60,
        )
        if resp.status_code == 200:
            response = resp.json().get("response", "")
        else:
            response = "Sorry, I'm having trouble."
    except Exception as e:
        response = f"Error: {e}"

    return jsonify({"response": response})


@app.route("/health")
def health():
    return jsonify({"status": "running"})


if __name__ == "__main__":
    print("=== Real LLM App (Ollama Backend) ===")
    print("Running on http://localhost:9994")
    print()
    app.run(host="0.0.0.0", port=9994, debug=False)
