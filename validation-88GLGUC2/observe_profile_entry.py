"""Record native profile-entry arguments and caller, without changing them."""
from pathlib import Path
import argparse,json,time
import frida
ROOT=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--pid',required=True,type=int);a=p.parse_args()
s=frida.get_device_manager().add_remote_device('127.0.0.1:37043').attach(a.pid)
source=r'''
const m=Process.getModuleByName('libg.so');
if(m.base.add(0xc32850).readU32()!==0xd10543ff)throw new Error('Unsupported constructor');
const h=Interceptor.attach(m.base.add(0xc32850),{onEnter(args){
 try{send({time:new Date().toISOString(),caller:this.returnAddress.sub(m.base).toString(),
 high:args[1].readU32(),low:args[1].add(4).readU32(),viewKind:args[2].toInt32(),
 hasBattleEntry:!args[3].isNull(),queryParameter:args[4].toInt32(),hasContext12:!args[5].isNull(),
 battleEntryType:args[3].isNull()?null:args[3].readS32()});}
 catch(e){send({error:String(e)});}
}});
rpc.exports={stop(){h.detach();}};
'''
script=s.create_script(source)
def message(m,d):
 with (ROOT/'native-entry-observations.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(m,ensure_ascii=False)+'\n')
 print(json.dumps(m,ensure_ascii=True),flush=True)
script.on('message',message)
try:
 script.load();print('READY',flush=True)
 while not (ROOT/'STOP').exists():time.sleep(1)
finally:
 try:script.exports_sync.stop()
 finally:s.detach()
