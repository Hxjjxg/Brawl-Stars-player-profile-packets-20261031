"""Verify against real captured requests, responses and visible player profiles."""
from pathlib import Path
import json
import subprocess
from protocol import Reader, decode_request, decode_response, request_body, vint, iter_frames
from tag_id import tag_to_id, id_to_tag

ROOT=Path(__file__).resolve().parent
checks=[]

expected={
 '#LUY2YJP':{'high':108,'low':202449,'name':'胡须局锦绣谷','trophies':54278},
 '#2V9UJL9QR':{'high':103,'low':11232845,'name':'🌧️清雨QINGYU💫','trophies':99116},
}
requests=responses=0
for meta in sorted((ROOT/'samples').glob('[0-9][0-9]-*.json')):
 record=json.loads(meta.read_text(encoding='utf-8'));body=bytes.fromhex(record['bodyHex'])
 assert len(body)==record['length']
 raw_body=(meta.with_suffix('.body.bin')).read_bytes()
 assert raw_body==body
 binary=list((ROOT/'capture/captures').rglob(record['binaryFile']))
 assert len(binary)==1
 at=record['binaryOffset'];raw=binary[0].read_bytes()[at:at+record['binaryLength']]
 parsed=list(iter_frames(raw));assert len(parsed)==1
 assert parsed[0]['id']==record['id'] and parsed[0]['version']==record['version'] and parsed[0]['body']==body
 if record['id']==15081:
  decoded=decode_request(body)
  assert request_body(decoded['tag'],decoded['source'])==body
  requests+=1
 else:
  fields=[];spans=[]
  decoded=decode_response(body,fields,spans);p=decoded['profile'];exp=expected[p['tag']]
  assert p['player_id']=={'high':exp['high'],'low':exp['low']}
  assert p['display']['name']==exp['name']
  assert dict((s['key'],s['value']) for s in p['stats'])[3]==exp['trophies']
  assert len(p['heroes'])==107
  assert decoded['consumed_bytes']==len(body)
  covered={i for f in fields for i in range(f['offset'],f['end_offset'])}
  assert covered==set(range(len(body)))
  responses+=1
assert requests>=3 and responses>=2
checks.append({'check':'real request byte-for-byte regeneration','passed':True,'samples':requests})
checks.append({'check':'real complete response parsing and UI identity/name/trophies/hero-count comparison','passed':True,'samples':responses})
checks.append({'check':'original framed BIN / JSON sample / body export consistency and complete byte tracing','passed':True,'samples':requests+responses})

# Independently transcribed native wire order; optional branches have no real capture here.
display={'name':'A','string_48':None,'bool_64':False,**{f'int_{off}':0 for off in (16,20,24,28,32,36,40,68,72)}}
battle={'int_0':7,'player_id':{'high':108,'low':202449},'int_16':-1,'bool_20':True,
 'members':[{'data':{'table':16,'instance':10},'int_40':1,'int_56':2,'int_72':3}],
 'int_88':4,'display':display,'optional_long_104':{'high':1,'low':2},
 'data_112':{'table':16,'instance':0},'data_120':None,'data_128':{'table':28,'instance':1},'list_136':[1,-1]}
gold=bytes.fromhex('01'+'00'*12+'00'+'0000006c000316d1'+'01'+
 '07'+'0000006c000316d1'+'7f'+'01'+'01'+'100a'+'010203'+'04'+
 '0000000141'+'00'*5+'ffffffff'+'0000'+'00'+'0000'+
 '01'+'0000000100000002'+'1000'+'00'+'1c01'+'02'+'017f')
assert request_body('LUY2YJP',context12=[0]*12,battle_log=battle)==gold
optional=decode_request(gold)
assert optional['battle_log_entry']==battle and optional['context12']==[0]*12
try:decode_request(gold[:-1])
except ValueError:pass
else:raise AssertionError('Accepted truncated optional structure')
checks.append({'check':'optional context and battle-log native wire-order fixture plus truncation rejection','passed':True,'evidence':'offline synthetic fixture; not a real-device branch capture'})

# LogicLong stores two uint32 words although the wire primitive is signed VInt.
original=(ROOT/'samples/05-s2c-24113.body.bin').read_bytes()
unsigned_low=vint(108)+vint(-1)+original[5:]
synthetic=decode_response(unsigned_low)
assert synthetic['profile']['player_id']=={'high':108,'low':0xffffffff}
assert synthetic['profile']['tag']==id_to_tag(108,0xffffffff)
checks.append({'check':'unsigned player-ID low word carried by a signed VInt','passed':True,'evidence':'offline boundary fixture'})
live=json.loads((ROOT/'live-optional-context.json').read_text(encoding='utf-8'))
assert live['passed'] and all(r['equal_previous_runtime_copy'] for r in live['ranges'])
assert live['hooks']==live['game_calls']==live['target_memory_writes']==live['ui_actions']==0
checks.append({'check':'optional structure code identity against saved current-device readback','passed':True,
 'bytes':sum(r['end']-r['start'] for r in live['ranges']),'evidence':'read-only code identity, not a triggered optional packet'})

vectors=[{'high':0,'low':0},{'high':0,'low':1},{'high':108,'low':202449},
 {'high':103,'low':11232845},{'high':255,'low':0xffffffff},
 {'high':255,'low':0x80000000},{'high':0,'low':0x7fffffff}]
for v in vectors:
 tag=id_to_tag(**v);assert tag_to_id(tag)==(v['high'],v['low']);v['tag']=tag
js="const fs=require('fs');const c=require('./tag-id.js');const v=JSON.parse(fs.readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(v.map(x=>({tag:c.idToTag(x.high,x.low),...c.tagToId(x.tag)}))));"
result=subprocess.run(['node','-e',js],input=json.dumps(vectors),text=True,capture_output=True,cwd=ROOT,check=True)
assert json.loads(result.stdout)==[{'tag':v['tag'],'high':v['high'],'low':v['low']} for v in vectors]
for invalid in ('','#','#ABC','##2PP','2 PP'):
 try:tag_to_id(invalid)
 except (ValueError,TypeError):pass
 else:raise AssertionError(f'Accepted invalid tag: {invalid}')
assert tag_to_id('  #luy2yjp  ')==(108,202449)
checks.append({'check':'standalone Python / JavaScript conversions, real vectors, unsigned boundaries and invalid tags','passed':True,'vectors':len(vectors)})

for value in [0,1,63,64,8191,8192,-1,-63,-64,-65,-8191,-8192,-8193,-1048576,-134217728,-2147483648,2147483647]:
 b=vint(value);r=Reader(b);assert r.vint()==value and r.pos==len(b)
checks.append({'check':'signed VInt boundary round-trips','passed':True})
for path in (ROOT/'tag-id.js',ROOT/'capture/PlayerProfileCapture.js'):
 subprocess.run(['node','--check',str(path)],check=True,capture_output=True)
checks.append({'check':'JavaScript syntax','passed':True})
logs=list((ROOT/'capture/captures').rglob('*.jsonl'))
assert len(logs)==1
records=[json.loads(line) for line in logs[0].read_text(encoding='utf-8').splitlines()]
stop=[r for r in records if r.get('kind')=='stop'][-1]
summary=json.loads((logs[0].parent/'summary.json').read_text(encoding='utf-8'))
assert summary['closed'] and summary['lastPhase']=='stopped' and summary['lastError'] is None
assert stop['frames']==stop['sentFrames']==stop['receiverFlushedFrames']==requests+responses
assert stop['errors']==0 and stop['skipped']==0
result={'passed':True,'checks':checks,'capture':{'frames':stop['frames'],'sent_frames':stop['sentFrames'],
 'receiver_flushed_frames':stop['receiverFlushedFrames'],'errors':stop['errors'],
 'historical_stop_phase':stop['phase'],'receiver_session_closed':summary['closed'],
 'source_log':str(logs[0].relative_to(ROOT))}}
(ROOT/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
