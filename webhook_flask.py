from flask import Flask, request, abort
import hmac
import hashlib
import os

app = Flask(__name__)
WEBHOOK_SECRET = os.environ.get('WEBHOOK_SECRET', 'fe7e01289ca5ce6c5aa0529c3fd79bea5cb998cd')

def verify_signature(signature, data):
    if not signature:
        return False
    digest = hmac.new(WEBHOOK_SECRET.encode(), data, hashlib.sha256).hexdigest()
    expected = 'sha256=' + digest
    return hmac.compare_digest(signature, expected)

@app.route('/')
def home():
    return "Välkommen till min Flask-app!"

@app.route('/webhook', methods=['POST'])
def webhook():
    signature = request.headers.get('X-Hub-Signature-256', '')
    payload = request.get_data()
    if not verify_signature(signature, payload):
        abort(401, 'Invalid signature')
    event = request.headers.get('X-GitHub-Event', '')
    delivery = request.headers.get('X-GitHub-Delivery', '')
    print(f'Received event: {event}, delivery: {delivery}')
    return 'OK', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3002, debug=True)
