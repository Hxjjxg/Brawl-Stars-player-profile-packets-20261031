"""Recheck the complete Nov 1 device capture against its raw receiver files."""
from pathlib import Path
import json,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT.parent))
from export_capture import export
from protocol import iter_frames

coverage=export()
assert coverage=={'requests':5,'responses':5,'context12_true':3,'battle_log_true':3,
                 'optional_long_104_nonnull':2,'errors':[]},coverage
index=json.loads((ROOT/'index.json').read_text(encoding='utf-8'))
assert [r['sequence'] for r in index]==list(range(1,11))
records=[json.loads(line) for p in (ROOT/'captures').rglob('*.jsonl')
         for line in p.read_text(encoding='utf-8').splitlines()]
raw={r['sequence']:r for r in records if r.get('kind')=='frame'}
for row in index:
    assert row['decoded'] and row['fully_covered']
    r=raw[row['sequence']]
    files=list((ROOT/'captures').rglob(r['binaryFile']));assert len(files)==1
    chunk=files[0].read_bytes()[r['binaryOffset']:r['binaryOffset']+r['binaryLength']]
    assert chunk==(ROOT/f"{row['sequence']:02d}-{r['direction']}-{r['id']}.frame.bin").read_bytes()
    frames=list(iter_frames(chunk));assert len(frames)==1
    f=frames[0]
    assert f['id']==r['id'] and f['version']==r['version']==0
    assert f['body']==bytes.fromhex(r['bodyHex'])
for request,response in zip(index[::2],index[1::2]):
    assert request['id']==15081 and response['id']==24113
    assert request['tag']==response['tag'] and request['reencoded_exact']
    assert request['display_tag']==response['display_tag']
assert [r['length'] for r in index[::2]]==[11,11,100,120,100]
assert [r['length'] for r in index[1::2]]==[3143,3316,687,703,679]
assert [(r['view_kind'],r['native_entry_type']) for r in index[::2]]==[(6,None),(6,None),(7,2),(7,2),(7,2)]
assert [r['name'] for r in index[1::2]]==['ATG.早点见面','李星云','恭喜你，不能','哔哩哔哩～～志气凌云','Brawl Stars']
long_fields=[]
for seq,expected in [(5,None),(7,{'high':103,'low':167892}),(9,{'high':111,'low':577840})]:
    stem=f'{seq:02d}-c2s-15081'
    d=json.loads((ROOT/(stem+'-decoded.json')).read_text(encoding='utf-8'))
    b=d['battle_log_entry']
    assert b['optional_long_104']==expected
    assert d['player_id']==b['player_id']
    assert d['query_parameter']==sum(m['int_40'] for m in b['members'])
    fields=json.loads((ROOT/(stem+'-fields.json')).read_text(encoding='utf-8'))['fields']
    selected=[f for f in fields if 'long_104' in f['path']]
    assert len(selected)==(1 if expected is None else 3)
    long_fields.append({'sequence':seq,'value':expected,'fields':selected})
for key in ('alliance_present','collection_present','optional_int_present'):
    assert {r[key] for r in index[1::2]}=={False,True}
stops=[r for r in records if r.get('kind')=='stop'];assert stops
stop=stops[-1]
assert stop['frames']==stop['sentFrames']==stop['receiverFlushedFrames']==10
assert stop['errors']==stop['skipped']==0
result={'passed':True,'frames':10,'coverage':coverage,'session_closed':True,
        'checks':['all bytes traced and bodies fully consumed','all requests re-encode exactly',
                  'raw BIN / JSONL / exported frames agree','all five response IDs match requests',
                  'native entry observations distinguish viewKind 6 and 7',
                  'optional_long_104 absent once and non-null twice in actual outgoing requests',
                  'response optional structures present and absent','receiver acknowledged all 10 frames'],
        'optional_long_104':long_fields,
        'stop':{k:stop[k] for k in ('frames','sentFrames','receiverFlushedFrames','errors','skipped','phase')}}
(ROOT/'verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'frames':10,'coverage':coverage,'session_closed':True}))
