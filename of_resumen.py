#!/usr/bin/env python3
"""Resume los mensajes OpenFlow de un ping en una captura .pcap.

Muestra, en orden, cada PACKET_IN y PACKET_OUT que transporta un paquete
ICMP (el ping) y cada FLOW_MOD, con sus campos principales. Ignora las
sondas LLDP/BDDP y el resto del tráfico de control.

Uso: python3 of_resumen.py captura.pcap
"""
import json
import subprocess
import sys

SWITCH = {'192.168.0.11': 'sw1', '192.168.0.12': 'sw2',
          '192.168.0.13': 'sw3'}
HOST = {'10.0.0.1': 'h1', '10.0.0.2': 'h2', '10.0.0.3': 'h3',
        '10.0.0.4': 'h4'}
TYPE = {'10': 'PACKET_IN', '13': 'PACKET_OUT', '14': 'FLOW_MOD'}
REASON = {'0': 'NO_MATCH (ninguna regla)',
          '1': 'ACTION (regla con salida CONTROLLER)'}
COMMAND = {'0': 'ADD', '1': 'MODIFY', '2': 'MODIFY_STRICT',
           '3': 'DELETE', '4': 'DELETE_STRICT'}
OXM = {'0': 'in_port', '3': 'eth_dst', '4': 'eth_src', '5': 'eth_type',
       '10': 'ip_proto', '11': 'ipv4_src', '12': 'ipv4_dst'}
PORT = {'4294967293': 'CONTROLLER', '4294967291': 'FLOOD',
        '4294967289': 'TABLE', '4294967292': 'ALL'}


def as_list(x):
    return x if isinstance(x, list) else [x]


def find(node, key):
    """Devuelve todos los valores de 'key' dentro de node (recursivo)."""
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                out += as_list(v)
            else:
                out += find(v, key)
    elif isinstance(node, list):
        for v in node:
            out += find(v, key)
    return out


def port(p):
    return PORT.get(p, p)


def match(msg):
    fields = []
    for oxm in find(msg.get('Match', {}), 'OXM field'):
        name = OXM.get(oxm.get('openflow_v4.oxm.field'), 'campo')
        value = next((v for k, v in oxm.items()
                      if k.startswith('openflow_v4.oxm.value')), '?')
        fields.append(f'{name}={value}')
    return ' '.join(fields) or '(vacío)'


def actions(node):
    outs = find(node, 'openflow_v4.action.output.port')
    return ', '.join('output:' + port(p) for p in outs) or 'ninguna (drop)'


def ping(msg):
    data = msg.get('Data', {})
    ip, icmp = data.get('ip'), data.get('icmp')
    if not ip or not icmp:
        return None
    kind = {'8': 'echo request', '0': 'echo reply'}.get(
        icmp.get('icmp.type'), 'icmp')
    src, dst = ip.get('ip.src'), ip.get('ip.dst')
    return (f"{HOST.get(src, src)} -> {HOST.get(dst, dst)} {kind} "
            f"seq={icmp.get('icmp.seq')}")


def main(pcap):
    out = subprocess.run(
        ['tshark', '-r', pcap, '-Y', 'icmp || openflow_v4.type == 14',
         '-T', 'json', '--no-duplicate-keys'],
        capture_output=True, text=True, check=True).stdout
    frames = json.loads(out or '[]')
    total = {'PACKET_IN': 0, 'FLOW_MOD': 0, 'PACKET_OUT': 0}
    t0 = None
    print(f'{"t (s)":>7}  {"switch":6} {"mensaje":10}  detalle')
    for f in frames:
        layers = f['_source']['layers']
        t = float(layers['frame']['frame.time_relative'])
        t0 = t if t0 is None else t0
        ips = as_list(layers['ip'])[0]
        sw = SWITCH.get(ips['ip.src']) or SWITCH.get(ips['ip.dst'], '?')
        for msg in as_list(layers.get('openflow_v4', [])):
            kind = TYPE.get(msg.get('openflow_v4.type'))
            if kind == 'PACKET_IN' and ping(msg):
                why = msg.get('openflow_v4.packet_in.reason')
                detail = (f"{ping(msg)} | reason={REASON.get(why, why)}"
                          f" | {match(msg)}")
            elif kind == 'PACKET_OUT' and ping(msg):
                act = actions(msg.get('Action', {}))
                detail = f'{ping(msg)} | acción: {act}'
            elif kind == 'FLOW_MOD':
                g = lambda k: msg.get('openflow_v4.flowmod.' + k)
                detail = (f"{COMMAND.get(g('command'), g('command'))} | "
                          f"match: {match(msg)} | acción: "
                          f"{actions(msg.get('Instruction', {}))} | "
                          f"prioridad={g('priority')} "
                          f"idle_timeout={g('idle_timeout')} "
                          f"hard_timeout={g('hard_timeout')}")
            else:
                continue
            total[kind] += 1
            print(f'{t - t0:7.3f}  {sw:6} {kind:10}  {detail}')
    print('\nTotal (solo mensajes del ping y FLOW_MOD): '
          + ', '.join(f'{k}={v}' for k, v in total.items()))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Uso: python3 of_resumen.py captura.pcap')
    main(sys.argv[1])