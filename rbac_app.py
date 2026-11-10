#!/usr/bin/env python3
"""Control de acceso por roles (RBAC) reactivo sobre ONOS.

1. Un switch envía un PACKET_IN de IPv4 a ONOS.
2. packet-bridge (app Java dentro de ONOS) lo reenvía por HTTP a
   POST http://127.0.0.1:5000/packet-in y descarta el paquete.
3. Esta app consulta policy.yaml y decide:
   - permitido: crea un HostToHostIntent entre ambos hosts;
   - denegado: instala una regla DROP temporal en el switch de ingreso.

Uso: python3 rbac_app.py   (Ctrl+C para detener)
"""
import base64
import json
import os
import threading
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

ONOS = os.getenv('ONOS_URL', 'http://127.0.0.1:8181') + '/onos/v1'
AUTH = 'Basic ' + base64.b64encode(b'onos:rocks').decode()
APP_ID = 'edu.pucp.sdn.packetbridge'   # appId registrado por packet-bridge
HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = os.path.join(HERE, 'policy.yaml')
DROP_TIMEOUT = 30                      # segundos de vida de una regla DROP

policy = yaml.safe_load(open(POLICY))
hosts = policy['hosts']                # IP -> {name, role}
lock = threading.Lock()
decided = {}                           # (ip_src, ip_dst) -> decisión


def log(msg):
    print(f'{datetime.now():%H:%M:%S}  {msg}', flush=True)


def onos(method, path, body=None):
    """Llama a la API REST de ONOS; devuelve (código, Location)."""
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        ONOS + path, method=method, data=data,
        headers={'Authorization': AUTH,
                 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.headers.get('Location', '')


def decide(src_ip, dst_ip):
    """Devuelve (permitido, motivo) según los roles de origen y destino."""
    src, dst = hosts.get(src_ip), hosts.get(dst_ip)
    if not src or not dst:
        return False, 'host desconocido'
    roles = f"{src['role']} -> {dst['role']}"
    for rule in policy['rules']:
        if rule['src'] == src['role'] and rule['dst'] == dst['role']:
            return rule['allow'], roles
    return False, roles + ' (sin regla: denegado por defecto)'


def name(ip):
    return hosts.get(ip, {}).get('name', ip)


def allow(p, why):
    """Permitido: HostToHostIntent entre las MAC del PACKET_IN."""
    _, loc = onos('POST', '/intents', {
        'type': 'HostToHostIntent', 'appId': APP_ID,
        'one': f"{p['eth_src']}/None", 'two': f"{p['eth_dst']}/None"})
    with lock:   # el intent es bidireccional: vale también para la vuelta
        decided[(p['dst_ip'], p['src_ip'])] = 'ALLOW'
    key = loc.rsplit('/', 1)[-1]
    log(f'[ALLOW]     {why}: HostToHostIntent key={key}')


def deny(p, why):
    """Denegado: regla DROP temporal en el switch de ingreso."""
    dev = p['device_id']
    onos('POST', f'/flows/{dev}?appId={APP_ID}', {
        'priority': 40001, 'timeout': DROP_TIMEOUT,
        'isPermanent': False, 'deviceId': dev,
        'selector': {'criteria': [
            {'type': 'ETH_TYPE', 'ethType': '0x0800'},
            {'type': 'IPV4_SRC', 'ip': p['src_ip'] + '/32'},
            {'type': 'IPV4_DST', 'ip': p['dst_ip'] + '/32'}]},
        'treatment': {'instructions': []}})   # sin acciones = descartar
    log(f'[DENY]      {why}: regla DROP en {dev} por {DROP_TIMEOUT} s')
    pair = (p['src_ip'], p['dst_ip'])
    threading.Timer(DROP_TIMEOUT, decided.pop, (pair, None)).start()


def handle(p):
    pair = (p['src_ip'], p['dst_ip'])
    log(f"[PACKET_IN] {p['device_id']} puerto {p['in_port']}  "
        f"{name(pair[0])} ({pair[0]}) -> {name(pair[1])} ({pair[1]})  "
        f"proto={p['ip_proto']}")
    with lock:
        if pair in decided:
            log(f'            decisión ya aplicada: {decided[pair]}')
            return
        ok, why = decide(*pair)
        decided[pair] = 'ALLOW' if ok else 'DENY'
    try:
        allow(p, why) if ok else deny(p, why)
    except urllib.error.HTTPError as e:
        log(f'[ERROR]     ONOS respondió HTTP {e.code}: '
            f'{e.read().decode()[:200]}')
        with lock:
            decided.pop(pair, None)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/packet-in':
            self.send_response(404)
            self.end_headers()
            return
        size = int(self.headers.get('Content-Length', 0))
        p = json.loads(self.rfile.read(size))
        self.send_response(200)        # responde rápido a packet-bridge
        self.end_headers()
        threading.Thread(target=handle, args=(p,), daemon=True).start()

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    log(f'RBAC escuchando en http://127.0.0.1:5000/packet-in')
    log(f'Política: {POLICY}')
    for ip, h in hosts.items():
        log(f"            {h['name']:3} {ip:10} rol={h['role']}")
    ThreadingHTTPServer(('127.0.0.1', 5000), Handler).serve_forever()


