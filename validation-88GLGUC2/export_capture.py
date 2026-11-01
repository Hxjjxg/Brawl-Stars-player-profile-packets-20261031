"""Export and verify captured profile frames without interacting with the game."""
from pathlib import Path
import argparse,csv,hashlib,json,sys,time

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from protocol import decode_request,decode_response,request_body,frame
from tag_id import id_to_tag
from datetime import datetime

def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def export(announce=False,seen=None):
    index=[];coverage={'requests':0,'responses':0,'context12_true':0,'battle_log_true':0,'errors':[]}
    observations=[];views={}
    obs=ROOT/'native-entry-observations.jsonl'
    if obs.exists():
        for line in obs.read_text(encoding='utf-8').splitlines():
            try:
                m=json.loads(line)
                if m.get('type')=='send' and 'high' in m['payload']:observations.append(m['payload'])
            except json.JSONDecodeError:continue
    for log in (ROOT/'captures').rglob('*.jsonl'):
        for line in log.read_text(encoding='utf-8').splitlines():
            try:record=json.loads(line)
            except json.JSONDecodeError:continue  # A live append may end mid-record.
            if record.get('kind')!='frame':continue
            body=bytes.fromhex(record['bodyHex']);mid=record['id'];seq=record['sequence']
            stem=f'{seq:02d}-{record["direction"]}-{mid}'
            (ROOT/(stem+'.body.bin')).write_bytes(body)
            (ROOT/(stem+'.frame.bin')).write_bytes(frame(mid,body,record['version']))
            save(ROOT/(stem+'.json'),record)
            row={'sequence':seq,'id':mid,'length':len(body),'time':record['time'],'body_sha256':hashlib.sha256(body).hexdigest()}
            try:
                fields=[];spans=[]
                d=(decode_request if mid==15081 else decode_response)(body,fields,spans)
                covered={i for f in fields for i in range(f['offset'],f['end_offset'])}
                assert covered==set(range(len(body)))
                row.update(decoded=True,fields=len(fields),fully_covered=True)
                if mid==15081:
                    coverage['requests']+=1
                    row.update(tag=d['tag'],context12_present=d['context12'] is not None,battle_log_present=d['has_battle_log_entry'],source=d['source'])
                    coverage['context12_true']+=int(row['context12_present'])
                    coverage['battle_log_true']+=int(row['battle_log_present'])
                    assert request_body(d['tag'],d['source'],d['context12'],d.get('battle_log_entry'))==body
                    row['reencoded_exact']=True
                    current=datetime.fromisoformat(record['time'].replace('Z','+00:00'))
                    matches=[o for o in observations if o['high']==d['player_id']['high'] and o['low']==d['player_id']['low']
                        and 0<=(current-datetime.fromisoformat(o['time'].replace('Z','+00:00'))).total_seconds()<0.5]
                    if matches:
                        o=matches[-1];kind=o['viewKind']
                        row.update(view_kind=kind,native_entry_type=o['battleEntryType'],
                           display_tag=id_to_tag(o['high']+100 if kind==7 else o['high'],o['low']))
                        views[d['tag']]={k:row[k] for k in ('view_kind','native_entry_type','display_tag')}
                else:
                    coverage['responses']+=1;p=d['profile']
                    row.update(tag=p['tag'],name=p['display']['name'],heroes=len(p['heroes']),
                       trophies=dict((x['key'],x['value']) for x in p['stats']).get(3),
                       highest_trophies_candidate=dict((x['key'],x['value']) for x in p['stats']).get(4),
                       alliance_present=d['alliance'] is not None,collection_present=p['collection_128'] is not None,
                       optional_int_present=p['optional_int_56'] is not None)
                    if p['tag'] in views:row.update(views[p['tag']])
                    assert d['consumed_bytes']==len(body)
                save(ROOT/(stem+'-decoded.json'),d)
                save(ROOT/(stem+'-fields.json'),{'fields':fields,'spans':spans})
                with (ROOT/(stem+'-fields.csv')).open('w',encoding='utf-8-sig',newline='') as handle:
                    w=csv.DictWriter(handle,fieldnames=['path','encoding','offset','end_offset','length','bit','hex','value']);w.writeheader()
                    for f in fields:w.writerow({**f,'value':json.dumps(f['value'],ensure_ascii=False)})
            except Exception as e:
                row.update(decoded=False,error=f'{type(e).__name__}: {e}')
                coverage['errors'].append({'sequence':seq,'error':row['error']})
            index.append(row)
            if announce and (seen is None or seq not in seen):
                print(json.dumps(row,ensure_ascii=True),flush=True)
                if seen is not None:seen.add(seq)
    save(ROOT/'index.json',index);save(ROOT/'coverage.json',coverage)
    return coverage

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--watch',action='store_true');a=p.parse_args()
    seen=set()
    while True:
        result=export(True,seen)
        if not a.watch or (ROOT/'STOP').exists():break
        time.sleep(1)
