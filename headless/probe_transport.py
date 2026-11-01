"""Temporarily observe profile encoder stacks and network record metadata."""
from pathlib import Path
import argparse,json,time,threading
import frida
ROOT=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--pid',type=int,required=True);p.add_argument('--seconds',type=int,default=90);a=p.parse_args()
session=frida.get_device_manager().add_remote_device('127.0.0.1:37043').attach(a.pid)
detached=threading.Event()
def on_detached(reason,crash):
    print(json.dumps({'kind':'detached','reason':reason}),flush=True)
    detached.set()
session.on('detached',on_detached)
source=r'''
const m=Process.getModuleByName('libg.so');
const relative=p=>p.compare(m.base)>=0&&p.compare(m.base.add(m.size))<0?p.sub(m.base).toString():DebugSymbol.fromAddress(p).toString();
const hooks=[];
function bt(context){return Thread.backtrace(context,Backtracer.ACCURATE).map(relative);}
send({kind:'modules',modules:Process.enumerateModules().filter(x=>/g\.so|ssl|crypto|sodium/.test(x.name)).map(x=>({name:x.name,base:x.base.toString(),size:x.size}))});
hooks.push(Interceptor.attach(m.base.add(0x18d1974),{onEnter(args){send({kind:'profile_encode',stack:bt(this.context)});}}));
for(const name of ['send','sendto','recv','recvfrom','write','read']){
 const address=Module.findGlobalExportByName(name);if(!address)continue;
 hooks.push(Interceptor.attach(address,{onEnter(args){this.fd=args[0].toInt32();this.buffer=args[1];this.count=args[2].toInt32();this.caller=this.returnAddress;},onLeave(ret){
  const n=ret.toInt32();if(n<7||n>4*1024*1024||this.caller.compare(m.base)<0||this.caller.compare(m.base.add(m.size))>=0)return;
  try{const b=new Uint8Array(this.buffer.readByteArray(7));const id=(b[0]<<8)|b[1],len=(b[2]<<16)|(b[3]<<8)|b[4];
   const row={kind:'io',name,fd:this.fd,bytes:n,id,length:len,header:Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(''),caller:relative(this.caller)};
   if(id===15081)row.profileWire=Array.from(new Uint8Array(this.buffer.readByteArray(n))).map(x=>x.toString(16).padStart(2,'0')).join('');
   send(row);
  }catch(e){send({kind:'error',error:String(e)});}
 }}));
}
rpc.exports={stop(){for(const h of hooks)h.detach();}};
'''
script=session.create_script(source)
def message(m,d):
    with (ROOT/'transport-observations.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(m,ensure_ascii=False)+'\n')
    print(json.dumps(m,ensure_ascii=True),flush=True)
script.on('message',message)
try:
    script.load();print('READY',flush=True);detached.wait(a.seconds)
finally:
    if not detached.is_set():
        try:script.exports_sync.stop()
        finally:session.detach()
