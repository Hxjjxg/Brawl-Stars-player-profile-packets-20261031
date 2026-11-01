"""The captured CN v69 NaCl variant: 19 Salsa single rounds, standard Poly1305."""
import hmac,struct

MASK=0xffffffff
SIGMA=b'expand 32-byte k'

def _rot(value,bits):
    value&=MASK
    return ((value<<bits)|(value>>(32-bits)))&MASK

def salsa_core(key,block,*,hsalsa=False,rounds=19):
    if len(key)!=32 or len(block)!=16:
        raise ValueError('Salsa core requires a 32-byte key and 16-byte input')
    k=struct.unpack('<8I',key);b=struct.unpack('<4I',block);c=struct.unpack('<4I',SIGMA)
    initial=[c[0],*k[:4],c[1],*b,c[2],*k[4:],c[3]]
    x=initial[:]
    for _ in range(rounds):
        w=[0]*16
        for j in range(4):
            t=[x[(5*j+4*m)%16] for m in range(4)]
            t[1]^=_rot(t[0]+t[3],7)
            t[2]^=_rot(t[1]+t[0],9)
            t[3]^=_rot(t[2]+t[1],13)
            t[0]^=_rot(t[3]+t[2],18)
            for m in range(4):w[4*j+(j+m)%4]=t[m]
        x=w
    if hsalsa:
        return struct.pack('<8I',*(x[i] for i in [0,5,10,15,6,7,8,9]))
    return struct.pack('<16I',*((a+b)&MASK for a,b in zip(x,initial)))

def stream(key,nonce,length,*,rounds=19):
    if len(nonce)!=24 or length<0:raise ValueError('Invalid XSalsa nonce or length')
    subkey=salsa_core(key,nonce[:16],hsalsa=True,rounds=rounds)
    return b''.join(salsa_core(subkey,nonce[16:]+i.to_bytes(8,'little'),rounds=rounds)
                    for i in range((length+63)//64))[:length]

def poly1305(message,key):
    if len(key)!=32:raise ValueError('Poly1305 requires a 32-byte key')
    r=int.from_bytes(key[:16],'little')&0x0ffffffc0ffffffc0ffffffc0fffffff
    acc=0
    for start in range(0,len(message),16):
        acc=((acc+int.from_bytes(message[start:start+16]+b'\x01','little'))*r)%((1<<130)-5)
    return ((acc+int.from_bytes(key[16:],'little'))% (1<<128)).to_bytes(16,'little')

def secretbox(message,nonce,key,*,rounds=19):
    pad=stream(key,nonce,len(message)+32,rounds=rounds)
    cipher=bytes(a^b for a,b in zip(message,pad[32:]))
    return poly1305(cipher,pad[:32])+cipher

def secretbox_open(ciphertext,nonce,key,*,rounds=19):
    if len(ciphertext)<16:raise ValueError('Truncated secretbox')
    tag,cipher=ciphertext[:16],ciphertext[16:]
    pad=stream(key,nonce,len(cipher)+32,rounds=rounds)
    if not hmac.compare_digest(tag,poly1305(cipher,pad[:32])):
        raise ValueError('Secretbox authentication failed')
    return bytes(a^b for a,b in zip(cipher,pad[32:]))

def shared_key(public,secret):
    from nacl.bindings import crypto_scalarmult
    return salsa_core(crypto_scalarmult(secret,public),bytes(16),hsalsa=True)

def increment(nonce,step=2):
    if len(nonce)!=24:raise ValueError('Nonce must be 24 bytes')
    value=int.from_bytes(nonce,'little')+step
    if value>=1<<192:raise OverflowError('Nonce exhausted')
    return value.to_bytes(24,'little')
