"""Create local capture credentials and JS from versioned templates."""
from pathlib import Path
import argparse,json,secrets

ROOT=Path(__file__).resolve().parent
SESSIONS={
    'capture':'PlayerProfileCapture',
    'validation-88GLGUC2':'PlayerProfileCapture',
    'validation-real-20261101':'PlayerProfileCapture',
    'original/arm64-socket':'LaserCn69_SocketCapture',
}

def initialize(directory,stem):
    directory=Path(directory)
    config_path=directory/'receiver-config.json'
    script_path=directory/(stem+'.js')
    if config_path.exists() or script_path.exists():
        raise FileExistsError('Local capture files already exist; preserve them or move them before initializing.')
    config=json.loads((directory/'receiver-config.example.json').read_text(encoding='utf-8'))
    source=(directory/(stem+'.template.js')).read_text(encoding='utf-8')
    if source.count('__LOCAL_CAPTURE_TOKEN__')!=1:
        raise ValueError('Expected exactly one capture token placeholder')
    token=secrets.token_hex(32)
    config['token']=token
    source=source.replace('__LOCAL_CAPTURE_TOKEN__',token)
    config_path.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
    script_path.write_text(source,encoding='utf-8')
    return config['port']

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session',choices=SESSIONS,default='capture',nargs='?')
    args=parser.parse_args()
    try:
        port=initialize(ROOT/args.session,SESSIONS[args.session])
    except (FileExistsError,ValueError) as error:
        parser.exit(1,str(error)+'\n')
    print(f'Local configuration ready for {args.session}, port {port}; token is not printed.')
