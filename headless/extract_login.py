"""Extract reusable own-account login material from an ignored session capture."""
from pathlib import Path
import argparse,hashlib,json
from crypto_cn import shared_key,secretbox_open

ROOT=Path(__file__).resolve().parent

def records(data):
    offset=0;out=[]
    while offset+7<=len(data):
        mid=int.from_bytes(data[offset:offset+2],'big')
        size=int.from_bytes(data[offset+2:offset+5],'big')
        if size>4*1024*1024:raise ValueError('Invalid transport record length')
        if offset+7+size>len(data):break
        out.append({'id':mid,'version':int.from_bytes(data[offset+5:offset+7],'big'),
                    'body':data[offset+7:offset+7+size]})
        offset+=7+size
    return out

def extract(capture,host='game.brawlstars.cn',port=9339):
    rows=[json.loads(s) for s in Path(capture).read_text(encoding='utf-8').splitlines()]
    states=[r for r in rows if r['kind']=='login_state']
    fds={r['fd'] for r in rows if r['kind']=='wire'}
    for fd in fds:
        streams={d:records(b''.join(bytes.fromhex(r['data']) for r in rows
                   if r['kind']=='wire' and r['fd']==fd and r['direction']==d))
                 for d in ('send','receive')}
        for login in (r for r in streams['send'] if r['id']==10101):
            state=next((s for s in states if bytes.fromhex(s['clientPublic'])==login['body'][:32]),None)
            if not state:continue
            hello=next((r for r in streams['send'] if r['id']==10100),None)
            response=next((r for r in streams['receive'] if r['id']==20100),None)
            ok=next((r for r in streams['receive'] if r['id']==20104),None)
            if not (hello and response and ok):continue
            public=bytes.fromhex(state['clientPublic']);server=bytes.fromhex(state['serverPublic'])
            key=shared_key(server,bytes.fromhex(state['clientSecret']))
            nonce=hashlib.blake2b(public+server,digest_size=24).digest()
            plain=secretbox_open(login['body'][32:],nonce,key)
            token_length=int.from_bytes(response['body'][:4],'big')
            if token_length!=24 or len(response['body'])!=28:raise ValueError('Unexpected server challenge')
            if plain[:24]!=response['body'][4:]:raise ValueError('Server challenge does not match encrypted login')
            client_nonce=plain[24:48]
            if client_nonce!=bytes.fromhex(state['clientNonce']):raise ValueError('Client nonce mismatch')
            ok_plain=secretbox_open(ok['body'],hashlib.blake2b(client_nonce+public+server,digest_size=24).digest(),key)
            if len(ok_plain)<56:raise ValueError('Authenticated LoginOk is truncated')
            return {'host':host,'port':port,'game_version':'69.114.1',
                    'client_hello':hello['body'].hex(),'hello_version':hello['version'],
                    'server_public':server.hex(),'login_body':plain[48:].hex(),
                    'login_version':login['version']}
    raise ValueError('No complete, authenticated login exchange found')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('capture',type=Path)
    p.add_argument('--host',default='game.brawlstars.cn');p.add_argument('--port',type=int,default=9339)
    p.add_argument('--output',type=Path,default=ROOT/'private'/'login-material.json')
    a=p.parse_args()
    private=(ROOT/'private').resolve();target=a.output.resolve()
    if not target.is_relative_to(private):p.error('Credentials must be saved under the ignored headless/private directory')
    config=extract(a.capture,a.host,a.port);target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
    print('Authenticated reusable login material saved locally; credential contents are not printed.')
