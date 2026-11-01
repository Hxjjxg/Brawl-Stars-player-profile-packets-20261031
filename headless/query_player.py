"""Query a CN v69 player with a standalone TCP/NaCl client; no ADB or Frida."""
from pathlib import Path
import argparse,hashlib,json,secrets,socket,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from protocol import decode_response,frame,request_body
from tag_id import tag_to_id,id_to_tag
from crypto_cn import increment,secretbox,secretbox_open,shared_key

MAX_BODY=4*1024*1024

class ProtocolError(RuntimeError):pass

class Client:
    def __init__(self,credentials,timeout=20):
        self.credentials=credentials
        self.timeout=timeout
        self.socket=None
        self.session_key=None
        self.sent=[];self.received=[]
        self.last_send=0

    def close(self):
        if self.socket is not None:
            self.socket.close();self.socket=None
        self.session_key=None

    def _send_raw(self,mid,body,version=0):
        if len(body)>MAX_BODY:raise ProtocolError('Outgoing record too large')
        self.socket.sendall(frame(mid,body,version))
        self.sent.append({'id':mid,'length':len(body),'version':version})
        self.last_send=time.monotonic()

    def _exact(self,length,deadline):
        result=bytearray()
        while len(result)<length:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('Server response deadline exceeded')
            self.socket.settimeout(remaining)
            chunk=self.socket.recv(length-len(result))
            if not chunk:raise ConnectionError('Server closed the connection')
            result.extend(chunk)
        return bytes(result)

    def _receive_raw(self,deadline):
        head=self._exact(7,deadline)
        mid=int.from_bytes(head[:2],'big');length=int.from_bytes(head[2:5],'big');version=int.from_bytes(head[5:],'big')
        if length>MAX_BODY:raise ProtocolError('Incoming record too large')
        body=self._exact(length,deadline)
        self.received.append({'id':mid,'length':length,'version':version})
        return mid,body,version

    def login(self):
        from nacl.bindings import crypto_scalarmult_base
        c=self.credentials
        server_public=bytes.fromhex(c['server_public'])
        if len(server_public)!=32:raise ValueError('server_public must contain 32 bytes')
        self.socket=socket.create_connection((c['host'],int(c.get('port',9339))),timeout=self.timeout)
        self.socket.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        deadline=time.monotonic()+self.timeout
        self._send_raw(10100,bytes.fromhex(c['client_hello']),int(c.get('hello_version',0)))
        mid,body,_=self._receive_raw(deadline)
        if mid!=20100:raise ProtocolError(f'Expected server hello 20100; received {mid} ({len(body)} bytes)')
        if len(body)<4:raise ProtocolError('Truncated server hello')
        token_len=int.from_bytes(body[:4],'big',signed=True)
        if token_len!=24 or len(body)!=4+token_len:raise ProtocolError('Unexpected server hello token format')
        secret=secrets.token_bytes(32);public=crypto_scalarmult_base(secret)
        client_nonce=bytearray(secrets.token_bytes(24));client_nonce[0]&=254;client_nonce=bytes(client_nonce)
        exchange_key=shared_key(server_public,secret)
        nonce=hashlib.blake2b(public+server_public,digest_size=24).digest()
        payload=body[4:]+client_nonce+bytes.fromhex(c['login_body'])
        self._send_raw(10101,public+secretbox(payload,nonce,exchange_key),int(c.get('login_version',0)))
        mid,body,_=self._receive_raw(deadline)
        if mid!=20104:raise ProtocolError(f'Login rejected or unexpected response: {mid} ({len(body)} bytes)')
        nonce=hashlib.blake2b(client_nonce+public+server_public,digest_size=24).digest()
        plain=secretbox_open(body,nonce,exchange_key)
        if len(plain)<56:raise ProtocolError('Truncated authenticated login response')
        self.receive_nonce=plain[:24];self.session_key=plain[24:56];self.send_nonce=client_nonce
        # The remainder is LoginOk data. It is intentionally neither printed nor persisted.

    def send(self,mid,body,version=0):
        if self.session_key is None:raise ProtocolError('Client is not logged in')
        self.send_nonce=increment(self.send_nonce)
        self._send_raw(mid,secretbox(body,self.send_nonce,self.session_key),version)

    def receive(self,deadline):
        mid,body,version=self._receive_raw(deadline)
        self.receive_nonce=increment(self.receive_nonce)
        return mid,secretbox_open(body,self.receive_nonce,self.session_key),version

    def query(self,tag):
        target=id_to_tag(*tag_to_id(tag))
        body=request_body(target)
        self.send(15081,body)
        deadline=time.monotonic()+self.timeout
        while time.monotonic()<deadline:
            mid,payload,version=self.receive(deadline)
            if mid==24113:
                decoded=decode_response(payload)
                if decoded['profile']['tag']==target:
                    return decoded,{'request_body_hex':body.hex(),'response_body_hex':payload.hex(),
                                    'response_version':version,'sent':list(self.sent),'received':list(self.received)}
            if mid==20103:raise ProtocolError('Server returned login failure during query')
            if time.monotonic()-self.last_send>8:self.send(10108,b'')
        raise TimeoutError(f'No matching 24113 response for {target}')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('tag')
    p.add_argument('--credentials',type=Path,default=Path(__file__).resolve().parent/'private'/'login-material.json')
    p.add_argument('--timeout',type=float,default=20)
    p.add_argument('--output',type=Path,help='Save the complete decoded public profile as JSON')
    p.add_argument('--evidence',type=Path,help='Save only profile request/response and record metadata; no login credentials')
    a=p.parse_args()
    client=None
    try:
        tag_to_id(a.tag)
        if not 0<a.timeout<=120:raise ValueError('timeout must be between 0 and 120 seconds')
        credentials=json.loads(a.credentials.read_text(encoding='utf-8'))
        client=Client(credentials,a.timeout);client.login();decoded,evidence=client.query(a.tag)
        profile=decoded['profile'];stats={x['key']:x['value'] for x in profile['stats']}
        result={'tag':profile['tag'],'name':profile['display']['name'],'trophies':stats.get(3),
                'highest_trophies':stats.get(4),'heroes':len(profile['heroes']),
                'transport':'standalone-python-tcp','response_id':24113}
        if a.output:a.output.write_text(json.dumps(decoded,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        if a.evidence:
            evidence.update(result=result,time_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()))
            a.evidence.write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    except (OSError,ValueError,KeyError,ProtocolError) as error:
        print(f'Query failed: {error}',file=sys.stderr);return 1
    finally:
        if client:client.close()

if __name__=='__main__':raise SystemExit(main())
