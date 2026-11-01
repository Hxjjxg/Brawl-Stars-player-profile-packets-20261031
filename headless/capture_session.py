"""Observe only the game's transport and store session material locally, never stdout."""
from pathlib import Path
import argparse,json,threading,time
import frida

ROOT=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--pid',required=True,type=int)
p.add_argument('--seconds',type=int,default=600);p.add_argument('--reconnect',action='store_true');a=p.parse_args()
private=ROOT/'private';private.mkdir(exist_ok=True)
output=private/f'session-{int(time.time())}.jsonl'
session=frida.get_device_manager().add_remote_device('127.0.0.1:37043').attach(a.pid)
detached=threading.Event()
session.on('detached',lambda reason,crash:(print(json.dumps({'detached':reason}),flush=True),detached.set()))
source=r'''
const m=Process.getModuleByName('libg.so'),hooks=[],current=new Map();let fd=-1;
const hex=(p,n)=>Array.from(new Uint8Array(p.readByteArray(n))).map(x=>x.toString(16).padStart(2,'0')).join('');
const expected={'0xb09078':'ff8302d1fd7b04a9fb2b00f9fa6706a9','0xb08634':'fd7bbaa9fc0b00f9fa6702a9f85f03a9','0x9d8f08':'fd7bbba9fa6701a9f85f02a9f65703a9','0x18d1974':'fd7bbea9f44f01a9fd030091f30300aa','0xad3efc':'6f028052'};
for(const [offset,bytes] of Object.entries(expected))if(hex(m.base.add(ptr(offset)),bytes.length/2)!==bytes)throw new Error('Unsupported native fingerprint at '+offset);
const rel=p=>p.sub(m.base).toString();
const emit=d=>send({...d,time:new Date().toISOString()});
hooks.push(Interceptor.attach(m.base.add(0xb09078),{onEnter(args){
 this.tid=Process.getCurrentThreadId();const msg=args[1];
 const type=new NativeFunction(msg.readPointer().add(40).readPointer(),'int',['pointer'])(msg);
 current.set(this.tid,type);
 if(type===15081||type===10100||type===10101)emit({kind:'outgoing',id:type,messaging:args[0].toString(),
    stream:hex(msg.add(8),64)});
},onLeave(){current.delete(this.tid);}}));
hooks.push(Interceptor.attach(m.base.add(0x18d1974),{onEnter(args){this.msg=args[0];},onLeave(){
 const s=this.msg.add(8),n=s.add(20).readU32();if(n<4096)emit({kind:'profile_plain',body:hex(s.add(56).readPointer(),n)});
}}));
hooks.push(Interceptor.attach(m.base.add(0x9d8f08),{onEnter(args){
 this.n=args[1].toInt32();this.out=args[2];this.overhead=args[6].toInt32();
 if(this.n<0||this.n>2*1024*1024)return;
 this.row={kind:'secretbox',id:current.get(Process.getCurrentThreadId()),length:this.n,
   caller:rel(this.returnAddress),plain:hex(args[0],this.n),nonce:hex(args[4],24),key:hex(args[5],32),overhead:this.overhead};
},onLeave(ret){if(this.row){this.row.result=ret.toInt32();if(this.row.result===0)this.row.cipher=hex(this.out,this.n+this.overhead);emit(this.row);}}}));
hooks.push(Interceptor.attach(m.base.add(0xb08634),{onEnter(args){this.owner=args[0];},onLeave(){
 emit({kind:'login_state',messaging:this.owner.toString(),clientNonce:hex(this.owner.add(440),24),serverPublic:hex(this.owner.add(488),32),clientPublic:hex(this.owner.add(520),32),clientSecret:hex(this.owner.add(552),32)});
}}));
for(const name of ['sendto','recvfrom']){
 const address=Module.findGlobalExportByName(name);
 hooks.push(Interceptor.attach(address,{onEnter(args){this.fd=args[0].toInt32();this.buf=args[1];this.caller=this.returnAddress;},onLeave(ret){
  const n=ret.toInt32();if(n<=0||n>4*1024*1024||this.caller.compare(m.base)<0||this.caller.compare(m.base.add(m.size))>=0)return;
  if(name==='sendto'&&this.caller.equals(m.base.add(0xb16c20)))fd=this.fd;
  if(this.fd===fd)emit({kind:'wire',direction:name==='sendto'?'send':'receive',fd:this.fd,data:hex(this.buf,n)});
 }}));
}
rpc.exports={stop(){for(const h of hooks)h.detach();},reconnect(){if(fd<0)throw new Error('No game transport observed');
 const shutdown=new NativeFunction(Module.findGlobalExportByName('shutdown'),'int',['int','int']);return {fd,result:shutdown(fd,2)};}};
'''
script=session.create_script(source)
counts={}
def message(m,data):
    if m.get('type')!='send':
        print(json.dumps({'instrumentation_error':m.get('description','unknown')}),flush=True);return
    d=m['payload'];kind=d.get('kind');counts[kind]=counts.get(kind,0)+1
    with output.open('a',encoding='utf-8') as f:f.write(json.dumps(d,ensure_ascii=False)+'\n')
    if kind in {'profile_plain','outgoing','login_state'}:
        print(json.dumps({'captured':kind,'id':d.get('id'),'body_bytes':len(d.get('body',''))//2}),flush=True)
script.on('message',message)
try:
    script.load();print('READY: session material stays in ignored private directory.',flush=True)
    if a.reconnect:
        time.sleep(3);print(json.dumps({'reconnect':script.exports_sync.reconnect()}),flush=True)
    deadline=time.monotonic()+a.seconds
    while not detached.is_set() and time.monotonic()<deadline and not (ROOT/'STOP.session').exists():
        detached.wait(1)
finally:
    if not detached.is_set():
        try:script.exports_sync.stop()
        finally:session.detach()
    print(json.dumps({'counts':counts,'private_file':output.name}),flush=True)
