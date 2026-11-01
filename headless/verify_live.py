"""Validate several live profile queries in one new authenticated Python session."""
from pathlib import Path
import argparse,datetime,hashlib,json,subprocess,sys,time
from query_player import Client
from phone_network import PhoneNetwork
from protocol import decode_response

ROOT=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--via-phone-network',action='store_true');p.add_argument('--serial')
a=p.parse_args()
config=json.loads((ROOT/'private'/'login-material.json').read_text(encoding='utf-8'))
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
directory=ROOT/'validation'/stamp;directory.mkdir(parents=True)
relay=None;client=None
def game_running(serial):
    r=subprocess.run(['adb','-s',serial,'shell','pidof','com.tencent.tmgp.supercell.brawlstars'],capture_output=True,timeout=8)
    if r.returncode not in (0,1):raise RuntimeError('Could not verify phone process state')
    return bool(r.stdout.strip())
try:
    if a.via_phone_network:
        relay=PhoneNetwork(config['host'],config['port'],a.serial).__enter__()
        if game_running(relay.serial):raise RuntimeError('Stop the game before this independent-client test')
        config={**config,'host':'127.0.0.1','port':relay.local_port}
    client=Client(config);client.login()
    rows=[]
    for index,tag in enumerate(['LUY2YJP','88GLGUC2','89V9YJ0RJ'],1):
        decoded,evidence=client.query(tag)
        fields=[];body=bytes.fromhex(evidence['response_body_hex'])
        again=decode_response(body,fields)
        assert again['consumed_bytes']==len(body)
        assert {i for f in fields for i in range(f['offset'],f['end_offset'])}==set(range(len(body)))
        assert len(bytes.fromhex(evidence['request_body_hex']))==11
        profile=decoded['profile'];stats={x['key']:x['value'] for x in profile['stats']}
        row={'tag':profile['tag'],'name':profile['display']['name'],'trophies':stats.get(3),
             'highest_trophies':stats.get(4),'heroes':len(profile['heroes']),
            'request_bytes':11,'response_bytes':len(body),'response_sha256':hashlib.sha256(body).hexdigest(),
             'all_bytes_traced':True,'fully_parsed':True}
        stem=f'{index:02d}-{tag}'
        (directory/(stem+'-decoded.json')).write_text(json.dumps(decoded,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        (directory/(stem+'-evidence.json')).write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        rows.append(row)
    absent_after=not game_running(relay.serial) if relay else None
    if relay:assert absent_after
    result={'passed':True,'time_utc':stamp,'network':'phone-tcp-relay' if relay else 'direct-tcp',
            'authentication':'one new connection, one fresh handshake, three queries',
            'game_process_absent_before':True if relay else None,'game_process_absent_after':absent_after,
            'frida_imported':any(x=='frida' or x.startswith('frida.') for x in sys.modules),
            'queries':rows,'sent':client.sent,'received':client.received,
            'artifacts':directory.relative_to(ROOT).as_posix()}
    assert result['frida_imported'] is False
    (directory/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (ROOT/'live-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'game_stayed_closed':absent_after,'queries':rows},ensure_ascii=False))
except Exception as error:
    failure={'passed':False,'error':type(error).__name__,'message':str(error),
             'sent':client.sent if client else [],'received':client.received if client else []}
    (directory/'failure.json').write_text(json.dumps(failure,indent=2)+'\n',encoding='utf-8')
    raise
finally:
    if client:client.close()
    if relay:relay.__exit__(None,None,None)
