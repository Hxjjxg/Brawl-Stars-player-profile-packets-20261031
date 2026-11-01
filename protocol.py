"""CN Brawl Stars 69.114.1: offline profile packet codec (standard library)."""
from pathlib import Path
import argparse
import json
import struct
from tag_id import tag_to_id, id_to_tag

def vint(value):
    if not -0x80000000<=value<=0x7fffffff:raise ValueError('VInt outside int32 range')
    negative=value<0
    rest=value if value>=0 else value+0x100000000
    out=bytearray([(rest&63)|(64 if negative else 0)])
    rest>>=6
    # Sign-extension termination follows the six-bit first group.
    remaining=value>>6
    while remaining not in (0,-1):
        out[-1]|=128
        out.append(rest&127)
        rest>>=7;remaining>>=7
    if value in (-64,-8192,-1048576,-134217728):
        # The native writer uses strict lower comparisons for negative groups.
        out[-1]|=128;out.append(rest&127)
    return bytes(out)

class Reader:
    def __init__(self,data,trace=None,spans=None):
        self.data=data;self.pos=0;self.bit=0;self.trace=trace;self.spans=spans;self.path=[]
    def field(self,name,operation):
        start=self.pos;start_bit=self.bit
        self.path.append(str(name))
        try:
            value=operation()
            if self.spans is not None:
                self.spans.append({'path':'.'.join(self.path).replace('.[','['),'start_cursor':start,
                    'start_bit_cursor':start_bit,'end_cursor':self.pos,'end_bit_cursor':self.bit})
            return value
        finally:self.path.pop()
    def array(self,name,operation):
        return self.field(name,lambda:[self.field(f'[{i}]',operation) for i in range(self.count('count'))])
    def record(self,kind,name,start,bit,value):
        if self.trace is not None:
            path='.'.join(self.path+([str(name)] if name is not None else [])).replace('.[','[')
            actual_start=start-1 if kind=='Bool' and bit else start
            row={'path':path,'encoding':kind,'offset':actual_start,'end_offset':self.pos,
                 'length':self.pos-actual_start,'hex':self.data[actual_start:self.pos].hex(),'value':value}
            if kind=='Bool':row['bit']=bit
            self.trace.append(row)
        return value
    def take(self,n):
        if n<0 or self.pos+n>len(self.data):raise ValueError(f'Truncated packet at {self.pos}, need {n}')
        b=self.data[self.pos:self.pos+n];self.pos+=n;return b
    def boolean(self,name=None):
        start,bit=self.pos,self.bit
        if self.bit==0:self.take(1)
        value=bool((self.data[self.pos-1]>>self.bit)&1)
        self.bit=(self.bit+1)&7
        return self.record('Bool',name,start,bit,value)
    def int32(self,name=None):
        start=self.pos;self.bit=0
        return self.record('Int32BE',name,start,0,struct.unpack('>i',self.take(4))[0])
    def uint32(self,name=None):
        start=self.pos;self.bit=0
        return self.record('UInt32BE',name,start,0,struct.unpack('>I',self.take(4))[0])
    def long(self,name=None):
        return self.field(name or 'long',lambda:{'high':self.uint32('high'),'low':self.uint32('low')})
    def vint(self,name=None):
        start=self.pos
        self.bit=0;b=self.take(1)[0];value=b&63;negative=bool(b&64);shift=6
        for _ in range(4):
            if not b&128:break
            b=self.take(1)[0];value|=(b&127)<<shift;shift+=7
        else:
            if b&128:raise ValueError('VInt longer than five bytes')
        if negative:value|=-(1<<shift)
        value&=0xffffffff
        value=value-0x100000000 if value&0x80000000 else value
        return self.record('VInt',name,start,0,value)
    def count(self,name=None):
        n=self.vint(name)
        if not 0<=n<=10000:raise ValueError(f'Invalid count {n} at {self.pos}')
        return n
    def string(self,name=None):
        start=self.pos;self.bit=0;n=struct.unpack('>i',self.take(4))[0]
        if n==-1:return self.record('String',name,start,0,None)
        if not 0<=n<=900000:raise ValueError(f'Invalid string length {n} at {self.pos}')
        return self.record('String',name,start,0,self.take(n).decode('utf-8'))
    def ref(self,name=None):
        def read():
            table=self.vint('table')
            return {'table':table,'instance':self.vint('instance')} if table else None
        return self.field(name or 'ref',read)
    def optional_ref(self,name=None):
        return self.field(name or 'optional_ref',lambda:self.ref('value') if self.boolean('present') else None)

class Writer:
    def __init__(self):self.data=bytearray();self.bit=0
    def boolean(self,value):
        if type(value) is not bool:raise TypeError('Bool requires True or False')
        if not self.bit:self.data.append(0)
        self.data[-1]|=int(value)<<self.bit
        self.bit=(self.bit+1)&7
    def raw(self,value):self.bit=0;self.data.extend(value)
    def vint(self,value):self.raw(vint(value))
    def int32(self,value):self.raw(struct.pack('>i',value))
    def long(self,value):self.raw(struct.pack('>II',value['high'],value['low']))
    def string(self,value):
        if value is None:self.int32(-1)
        else:
            encoded=value.encode('utf-8')
            if len(encoded)>900000:raise ValueError('String too large')
            self.int32(len(encoded));self.raw(encoded)
    def ref(self,value):
        if value is None:self.vint(0)
        else:
            if not value['table']:raise ValueError('Non-null DataReference needs a nonzero table')
            self.vint(value['table']);self.vint(value['instance'])

def write_display(w,d):
    w.string(d['name'])
    for off in (16,20,24,28,32):w.vint(d[f'int_{off}'])
    w.string(d['string_48'])
    for off in (36,40):w.vint(d[f'int_{off}'])
    w.boolean(d['bool_64'])
    for off in (68,72):w.vint(d[f'int_{off}'])

def write_battle_log(w,d):
    w.vint(d['int_0']);w.long(d['player_id']);w.vint(d['int_16']);w.boolean(d['bool_20'])
    w.vint(len(d['members']))
    for member in d['members']:
        w.ref(member['data'])
        for off in (40,56,72):w.vint(member[f'int_{off}'])
    w.vint(d['int_88']);write_display(w,d['display'])
    w.boolean(d['optional_long_104'] is not None)
    if d['optional_long_104'] is not None:w.long(d['optional_long_104'])
    for off in (112,120,128):w.ref(d[f'data_{off}'])
    w.vint(len(d['list_136']))
    for value in d['list_136']:w.vint(value)

def request_body(tag,source=0,context12=None,battle_log=None):
    high,low=tag_to_id(tag);w=Writer();w.boolean(context12 is not None)
    if context12 is not None:
        if len(context12)!=12:raise ValueError('context12 needs exactly 12 VInts')
        for value in context12:w.vint(value)
    w.vint(source);w.long({'high':high,'low':low});w.boolean(battle_log is not None)
    if battle_log is not None:write_battle_log(w,battle_log)
    return bytes(w.data)

def frame(mid,body,version=0):
    if len(body)>0xffffff:raise ValueError('Body too large')
    return mid.to_bytes(2,'big')+len(body).to_bytes(3,'big')+version.to_bytes(2,'big')+body

def iter_frames(data):
    """Read the receiver's concatenated seven-byte-header BIN records."""
    offset=0
    while offset<len(data):
        if len(data)-offset<7:raise ValueError(f'Truncated record header at {offset}')
        mid=int.from_bytes(data[offset:offset+2],'big')
        length=int.from_bytes(data[offset+2:offset+5],'big')
        version=int.from_bytes(data[offset+5:offset+7],'big')
        end=offset+7+length
        if end>len(data):raise ValueError(f'Truncated body at {offset+7}: need {length} bytes')
        yield {'offset':offset,'id':mid,'version':version,'length':length,'body':data[offset+7:end]}
        offset=end

def decode_request(body,trace=None,spans=None):
    r=Reader(body,trace,spans)
    context=r.field('context12',lambda:[r.vint(f'[{i}]') for i in range(12)]) if r.boolean('has_context12') else None
    source=r.vint('query_parameter');player=r.long('player_id')
    has_battle_log=r.boolean('has_battle_log_entry')
    result={'id':15081,'context12':context,'source':source,'query_parameter':source,'player_id':player,'tag':id_to_tag(**player),'has_battle_log_entry':has_battle_log}
    if has_battle_log:
        result['battle_log_entry']=r.field('battle_log_entry',lambda:battle_log(r))
    if r.pos!=len(body):raise ValueError('Unexpected request trailing bytes')
    return result

def hero(r):
    d={'data_0':r.ref('data_0'),'data_8':r.ref('data_8')}
    for off in (16,20,24,28):d[f'int_{off}']=r.vint(f'int_{off}')
    for off in (40,48,56):d[f'data_{off}']=r.optional_ref(f'data_{off}')
    d['int_64']=r.vint('int_64')
    for off in (72,80,88):d[f'data_{off}']=r.optional_ref(f'data_{off}')
    for off in (96,104,112,120,128,136):d[f'list_{off}']=r.array(f'list_{off}',r.ref)
    d['int_152']=r.vint('int_152')
    d['list_144']=r.array('list_144',r.vint)
    for off in (160,168,176,184,192):d[f'data_{off}']=r.optional_ref(f'data_{off}')
    d['list_200']=r.array('list_200',r.ref)
    for off in (208,216,224):d[f'data_{off}']=r.optional_ref(f'data_{off}')
    return d

def display(r):
    d={'name':r.string('name')}
    for off in (16,20,24,28,32):d[f'int_{off}']=r.vint(f'int_{off}')
    d['string_48']=r.string('string_48')
    for off in (36,40):d[f'int_{off}']=r.vint(f'int_{off}')
    d['bool_64']=r.boolean('bool_64')
    for off in (68,72):d[f'int_{off}']=r.vint(f'int_{off}')
    return d

def battle_log(r):
    # Native decode 0x18BDD9C / encode 0x18BE0B0; semantic names remain provisional.
    d={'int_0':r.vint('int_0'),'player_id':r.long('player_id'),
       'int_16':r.vint('int_16'),'bool_20':r.boolean('bool_20')}
    def member():
        m={'data':r.ref('data')}
        for off in (40,56,72):m[f'int_{off}']=r.vint(f'int_{off}')
        return m
    d['members']=r.array('members',member)
    d['int_88']=r.vint('int_88');d['display']=r.field('display',lambda:display(r))
    d['optional_long_104']=r.long('long_104') if r.boolean('has_long_104') else None
    for off in (112,120,128):d[f'data_{off}']=r.ref(f'data_{off}')
    d['list_136']=r.array('list_136',r.vint)
    return d

def collection(r):
    entries=r.array('entries',lambda:{'key':r.vint('key'),'data':r.ref('data'),
        'int_12':r.vint('int_12'),'int_16':r.int32('int_16')})
    return {'entries':entries,'int_40':r.vint('int_40'),'int_44':r.vint('int_44')}

def profile(r):
    player=r.field('player_id',lambda:{'high':r.vint('high') & 0xffffffff,'low':r.vint('low') & 0xffffffff})
    d={'player_id':player,'tag':id_to_tag(**player),'data_8':r.ref('data_8'),'data_16':r.ref('data_16')}
    d['heroes']=r.array('heroes',lambda:hero(r))
    d['stats']=r.array('stats',lambda:{'key':r.vint('key'),'value':r.vint('value')})
    d['display']=r.field('display',lambda:display(r))
    d['optional_int_56']=r.vint('optional_int_56') if r.boolean('has_optional_int_56') else None
    d['string_64']=r.string('string_64')
    for off in (72,76,80):d[f'int_{off}']=r.vint(f'int_{off}')
    for off in (88,96,104,112,120):d[f'data_{off}']=r.ref(f'data_{off}')
    d['collection_128']=r.field('collection_128',lambda:collection(r)) if r.boolean('has_collection_128') else None
    d['data_136']=r.ref('data_136');d['data_144']=r.ref('data_144');d['int_152']=r.vint('int_152')
    d['string_160']=r.string('string_160');d['string_168']=r.string('string_168')
    return d

def alliance(r):
    d={'id':r.long('id'),'name':r.string('name'),'data_16':r.ref('data_16')}
    for off in (24,28,32,36):d[f'int_{off}']=r.vint(f'int_{off}')
    d['data_56']=r.ref('data_56');d['string_64']=r.string('string_64')
    d['int_40']=r.vint('int_40');d['int_44']=r.vint('int_44');d['bool_72']=r.boolean('bool_72');d['int_52']=r.vint('int_52')
    for off in (76,88):
        n=r.vint(f'int_{off}');d[f'int_{off}']=n
        if n>=1:d[f'int_{off+4}']=r.vint(f'int_{off+4}');d[f'int_{off+8}']=r.vint(f'int_{off+8}')
    return d

def decode_response(body,trace=None,spans=None):
    r=Reader(body,trace,spans);d={'id':24113,'profile':r.field('profile',lambda:profile(r))}
    d['alliance']=r.field('alliance',lambda:alliance(r)) if r.boolean('has_alliance') else None
    d['data_160']=r.ref('data_160');d['int_168']=r.vint('int_168')
    d['consumed_bytes']=r.pos;d['body_length']=len(body)
    if r.pos!=len(body):raise ValueError(f'Trailing bytes: parsed {r.pos} of {len(body)}')
    return d

def main():
    p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='command',required=True)
    q=s.add_parser('encode');q.add_argument('tag');q.add_argument('--query-parameter','--source',dest='source',type=int,default=0)
    q=s.add_parser('decode');q.add_argument('id',type=int,choices=[15081,24113]);q.add_argument('file',type=Path);q.add_argument('--output',type=Path);q.add_argument('--trace',type=Path)
    q=s.add_parser('decode-stream');q.add_argument('file',type=Path);q.add_argument('--output',type=Path)
    a=p.parse_args()
    if a.command=='encode':
        b=request_body(a.tag,a.source);print(json.dumps({'tag':a.tag,'id':15081,'version':0,'body_hex':b.hex(),'frame_hex':frame(15081,b).hex()},indent=2));return
    if a.command=='decode-stream':
        d=[]
        for record in iter_frames(a.file.read_bytes()):
            mid=record['id'];body=record.pop('body')
            if mid not in (15081,24113):raise ValueError(f'Unsupported message {mid}')
            record['decoded']=(decode_request if mid==15081 else decode_response)(body)
            d.append(record)
    else:
        trace=[] if a.trace else None;spans=[] if a.trace else None
        d=(decode_request if a.id==15081 else decode_response)(a.file.read_bytes(),trace,spans)
        if a.trace:a.trace.write_text(json.dumps({'fields':trace,'spans':spans},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    text=json.dumps(d,ensure_ascii=False,indent=2)
    if a.output:a.output.write_text(text+'\n',encoding='utf-8')
    else:print(text)

if __name__=='__main__':main()
