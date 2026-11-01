"""Refresh artifact hashes from Git-visible files, excluding local runtime secrets."""
from pathlib import Path
import hashlib,json,subprocess

ROOT=Path(__file__).resolve().parent
path=ROOT/'交付清单.json'
manifest=json.loads(path.read_text(encoding='utf-8'))
names=subprocess.check_output(['git','-C',str(ROOT),'ls-files','-z','--cached','--others','--exclude-standard'])
paths=sorted({x for x in names.decode('utf-8').split('\0') if x and x!='交付清单.json'})
files=[]
for name in paths:
    p=ROOT/name
    if not p.is_file():continue
    data=p.read_bytes()
    files.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
manifest['files']=files
live=ROOT/'headless'/'live-verification.json'
if live.exists():
    result=json.loads(live.read_text(encoding='utf-8'))
    manifest['headless']={'passed':result['passed'],'queries_in_one_session':len(result['queries']),
        'game_process_absent':result['game_process_absent_before'] and result['game_process_absent_after'],
        'network':result['network'],'phone_free_pc_transport_verified':False,
        'verification':'headless/live-verification.json'}
path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'files':len(files),'archived_frames':manifest['combined_frames'],
                  'headless':manifest.get('headless')},ensure_ascii=True))
