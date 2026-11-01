"""Open the requested profile through the next normal profile UI action."""
import argparse,json,time,threading
from pathlib import Path
import frida
from tag_id import tag_to_id

ROOT=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('tag');p.add_argument('--pid',required=True,type=int)
a=p.parse_args();high,low=tag_to_id(a.tag)
session=frida.get_device_manager().add_remote_device('127.0.0.1:37043').attach(a.pid)
source=r'''
const m=Process.getModuleByName('libg.so');
if(m.base.add(0xc32850).readU32()!==0xd10543ff)throw new Error('Unsupported profile UI constructor');
let used=false;
const h=Interceptor.attach(m.base.add(0xc32850),{
 onEnter(args){
  this.changed=false;
  if(used)return;
  used=true;this.changed=true;
  // The profile constructor takes ownership of this freshly allocated LogicLong.
  // Keep its native allocation and change only the target values.
  args[1].writeU32(HIGH);args[1].add(4).writeU32(LOW);
 },
 onLeave(){if(this.changed)send({event:'profile-ui-target-set',high:HIGH,low:LOW});}
});
rpc.exports={stop(){h.detach();return used;}};
'''.replace('HIGH',str(high)).replace('LOW',str(low))
script=session.create_script(source)
done=threading.Event()
errors=[]
def message(m,d):
 print(json.dumps(m,ensure_ascii=False),flush=True)
 if m.get('type')=='error':errors.append(m)
 if m.get('type') in ('send','error'):done.set()
script.on('message',message)
try:
 script.load();print('READY',flush=True)
 if not done.wait(45):raise TimeoutError('Open a player profile within 45 seconds')
 if errors:raise RuntimeError(errors[0].get('description','UI hook failed'))
 time.sleep(2)
finally:
 script.exports_sync.stop();session.detach()
