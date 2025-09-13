# web.py
from flask import Flask, request, render_template, jsonify
import asyncio, os, json, time
from db import init_db, save_fingerprint
import aiohttp

app = Flask(__name__)
asyncio.get_event_loop().run_until_complete(init_db())

async def lookup_ip_info(ip):
    # placeholder heuristics for demo (no external API)
    # treat local addresses as safe
    return {'is_datacenter': False, 'is_vpn': False, 'asn': 'AS-LOCAL'}

@app.route('/start/<token>')
def start(token):
    return render_template('verify.html', token=token)

@app.route('/submit', methods=['POST'])
def submit():
    data = request.json or {}
    token = data.get('token')
    fp = data.get('fp', '')
    dna = data.get('dna', {})
    honeypot = data.get('honeypot', False)
    ip = request.headers.get('X-Real-IP') or request.remote_addr
    ua = request.headers.get('User-Agent')
    asn_info = asyncio.get_event_loop().run_until_complete(lookup_ip_info(ip))
    # Save fingerprint; we store the fp JSON with dna for demo convenience
    payload_fp = json.dumps({'fp': fp, 'dna': dna})
    asyncio.get_event_loop().run_until_complete(save_fingerprint(token, payload_fp, ip, asn_info.get('asn'), ua, int(bool(honeypot))))
    return jsonify({'status': 'ok'}), 200

@app.route('/')
def index():
    return 'AegisX-S verification server (demo).'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
