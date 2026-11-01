"""Verify every real frame collected in the additional validation session."""
from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT.parent))
from export_capture import export
from protocol import iter_frames

coverage=export()
assert not coverage['errors'],coverage['errors']
index=json.loads((ROOT/'index.json').read_text(encoding='utf-8'))
assert index and len(index)==coverage['requests']+coverage['responses']
frames={}
for p in (ROOT/'captures').rglob('*.jsonl'):
 for line in p.read_text(encoding='utf-8').splitlines():
  r=json.loads(line)
  if r.get('kind')=='frame':frames[r['sequence']]=r
for row in index:
 assert row['decoded'] and row['fully_covered']
 r=frames[row['sequence']]
 source=list((ROOT/'captures').rglob(r['binaryFile']));assert len(source)==1
 start=r['binaryOffset'];wire=source[0].read_bytes()[start:start+r['binaryLength']]
 parsed=list(iter_frames(wire));assert len(parsed)==1
 assert parsed[0]['id']==r['id'] and parsed[0]['version']==r['version']
 assert parsed[0]['body']==bytes.fromhex(r['bodyHex'])
target=[row for row in index if row.get('name')=='TIG丨初夏']
assert target and target[0]['tag']=='#88GLGUC2' and target[0]['heroes']==108 and target[0]['trophies']==234527
highest=[row for row in index if row.get('name')=='余念安']
assert highest and highest[0]['trophies']==93313 and highest[0]['highest_trophies_candidate']==93329
assert coverage['context12_true']==2 and coverage['battle_log_true']==2
extended=[r for r in index if r['id']==15081 and r['context12_present']]
assert [r['length'] for r in extended]==[88,100]
assert all(r['battle_log_present'] and r['view_kind']==7 and r['native_entry_type']==2 and r['reencoded_exact'] for r in extended)
for row in extended:
 d=json.loads((ROOT/f"{row['sequence']:02d}-c2s-15081-decoded.json").read_text(encoding='utf-8'))
 assert d['query_parameter']==sum(m['int_40'] for m in d['battle_log_entry']['members'])
assert {r['display_tag'] for r in extended}=={'#LJPGGC88','#LJ90RG2P'}
responses=[r for r in index if r['id']==24113]
for key in ('alliance_present','collection_present','optional_int_present'):
 assert {r[key] for r in responses}=={False,True}
summary={'passed':True,'frames':len(index),'coverage':coverage,'target':target[0],
 'checks':['all real frame bodies fully decoded','all bytes traced','requests re-encode byte-for-byte',
           'original BIN and JSONL agree','88GLGUC2 ID/name/108 heroes/234527 trophies match observed UI',
           'current vs highest trophies distinguished by unequal sample and native UI consumer',
           'both request optional branches triggered twice by unmodified game actions',
           '88-byte and 100-byte extended requests re-encode exactly',
           'viewKind 7 display tags use native high+100 rendering',
           'response alliance/collection/optional-int presence and absence both covered']}
log=list((ROOT/'captures').rglob('*.jsonl'))[0]
records=[json.loads(x) for x in log.read_text(encoding='utf-8').splitlines()]
stops=[r for r in records if r.get('kind')=='stop']
summary['session_closed']=bool(stops)
if stops:
 last=stops[-1];assert last['frames']==last['sentFrames']==last['receiverFlushedFrames']==len(index)
 assert last['errors']==0
 summary['stop']={k:last[k] for k in ('frames','sentFrames','receiverFlushedFrames','errors','skipped','phase')}
(ROOT/'verification.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'frames':len(index),'coverage':coverage,'session_closed':bool(stops)}))
