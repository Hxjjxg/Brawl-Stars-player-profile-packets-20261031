"""Read-only comparison of optional-code ranges; no hooks, game calls or UI actions."""
from pathlib import Path
from datetime import datetime,timezone,timedelta
import argparse,hashlib,json,threading
import frida

ROOT=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--pid',type=int,required=True)
p.add_argument('--remote',default='127.0.0.1:37043');a=p.parse_args()
ranges=[(0x18bdd9c,0x18be0b0),(0x18be0b0,0x18be280),(0x18be810,0x18be920)]
reference=Path(r'F:\cn-bs-lib_v69\migration-v69\artifacts\device\libg-runtime-code.so').read_bytes()
session=frida.get_device_manager().add_remote_device(a.remote).attach(a.pid)
script=session.create_script(r'''
if(Process.arch!=='arm64')throw new Error('Wrong architecture');
const cmd=new Uint8Array(File.readAllBytes('/proc/self/cmdline'));
const nul=cmd.indexOf(0);const name=String.fromCharCode(...cmd.subarray(0,nul<0?cmd.length:nul));
if(name!=='com.tencent.tmgp.supercell.brawlstars')throw new Error('Wrong process');
const m=Process.getModuleByName('libg.so');
const ranges=RANGES;
function hex(p,n){return Array.from(new Uint8Array(p.readByteArray(n)),b=>b.toString(16).padStart(2,'0')).join('');}
send({pid:Process.id,arch:Process.arch,module:{base:m.base.toString(),size:m.size,path:m.path},
 ranges:ranges.map(([start,end])=>({start,end,hex:hex(m.base.add(start),end-start)}))});
'''.replace('RANGES',json.dumps(ranges)))
event=threading.Event();messages=[]
def message(m,d):messages.append(m);event.set()
script.on('message',message)
try:
 script.load()
 if not event.wait(8):raise TimeoutError('No readback result')
 if messages[0]['type']!='send':raise RuntimeError(messages[0])
 result=messages[0]['payload']
 result.update(captured_at_china=datetime.now(timezone(timedelta(hours=8))).isoformat(),hooks=0,
               game_calls=0,target_memory_writes=0,ui_actions=0,client_frida=frida.__version__)
 for r in result['ranges']:
  raw=bytes.fromhex(r['hex']);r['sha256']=hashlib.sha256(raw).hexdigest()
  r['equal_previous_runtime_copy']=raw==reference[r['start']:r['end']]
 result['passed']=all(r['equal_previous_runtime_copy'] for r in result['ranges'])
 (ROOT/'live-optional-context.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'passed':result['passed'],'pid':result['pid'],
 'ranges':[{'start':hex(r['start']),'bytes':r['end']-r['start'],'equal':r['equal_previous_runtime_copy']} for r in result['ranges']],
 'hooks':0,'game_calls':0,'target_memory_writes':0,'ui_actions':0}))
finally:session.detach()
