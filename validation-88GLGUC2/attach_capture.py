from pathlib import Path
import argparse
import json
import time
import frida

ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--pid',type=int,required=True)
parser.add_argument('--remote',default='127.0.0.1:37043')
args = parser.parse_args()
device = frida.get_device_manager().add_remote_device(args.remote)
session = device.attach(args.pid)
script = session.create_script((ROOT/'PlayerProfileCapture.js').read_text(encoding='utf-8'))
script.on('message',lambda m,d: print(json.dumps(m,ensure_ascii=False),flush=True))
try:
    script.load()
    while not (ROOT/'STOP').exists():
        time.sleep(1)
finally:
    try:
        print(script.exports_sync.stop(),flush=True)
    finally:
        session.detach()
