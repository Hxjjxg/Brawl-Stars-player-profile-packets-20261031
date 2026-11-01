"""Non-secret native crypto vectors and fragmented transport regression checks."""
from pathlib import Path
import json,time,unittest
from unittest.mock import patch
from nacl.secret import SecretBox
from crypto_cn import secretbox,secretbox_open,increment
from query_player import Client,ProtocolError

ROOT=Path(__file__).resolve().parent

class FragmentSocket:
    def __init__(self,data):self.data=data
    def settimeout(self,value):pass
    def recv(self,length):
        chunk=self.data[:min(1,length)];self.data=self.data[len(chunk):];return chunk
    def close(self):pass

class HeadlessTests(unittest.TestCase):
    def test_actual_native_vectors(self):
        data=json.loads((ROOT/'native-crypto-vectors.json').read_text(encoding='utf-8'))
        key=bytes.fromhex(data['key_hex']);nonce=bytes.fromhex(data['nonce_hex'])
        for vector in data['vectors']:
            with self.subTest(length=vector['length']):
                message=bytes(range(vector['length']));cipher=bytes.fromhex(vector['cipher'])
                self.assertEqual(secretbox(message,nonce,key),cipher)
                self.assertEqual(secretbox_open(cipher,nonce,key),message)

    def test_standard_rounds_independent_oracle(self):
        key=bytes(range(32));nonce=bytes(range(24))
        for length in [0,1,31,32,63,64,65,128,4096]:
            with self.subTest(length=length):
                message=bytes(i%256 for i in range(length))
                self.assertEqual(secretbox(message,nonce,key,rounds=20),SecretBox(key).encrypt(message,nonce).ciphertext)

    def test_reject_tampered_tag_or_payload(self):
        key=bytes(range(32));nonce=bytes(range(24));cipher=secretbox(b'profile request',nonce,key)
        for index in [0,15,16,len(cipher)-1]:
            bad=bytearray(cipher);bad[index]^=1
            with self.assertRaises(ValueError):secretbox_open(bytes(bad),nonce,key)
        with self.assertRaises(ValueError):secretbox_open(cipher[:15],nonce,key)

    def test_counter_carry_and_overflow(self):
        self.assertEqual(increment(b'\xff'+bytes(23)),b'\x01\x01'+bytes(22))
        with self.assertRaises(OverflowError):increment(b'\xff'*24)

    def test_one_byte_transport_reads(self):
        client=Client({});client.socket=FragmentSocket(bytes.fromhex('3ae90000030000')+b'abc')
        self.assertEqual(client._receive_raw(time.monotonic()+1),(15081,b'abc',0))

    def test_reject_closed_or_oversized_transport(self):
        client=Client({});client.socket=FragmentSocket(bytes.fromhex('3ae90000030000')+b'ab')
        with self.assertRaises(ConnectionError):client._receive_raw(time.monotonic()+1)
        client.socket=FragmentSocket(bytes.fromhex('3ae94000010000'))
        with self.assertRaises(ProtocolError):client._receive_raw(time.monotonic()+1)

    def test_reject_expired_receive_deadline(self):
        client=Client({});client.socket=FragmentSocket(b'payload')
        with self.assertRaises(TimeoutError):client._exact(1,time.monotonic()-1)

    def test_repeat_query_waits_after_previous_response(self):
        body=(ROOT.parent/'samples'/'05-s2c-24113.body.bin').read_bytes()
        client=Client({});client.last_profile_response=9
        client.send=lambda *args:None
        def receive(deadline):
            client.received.append({'id':24113,'length':len(body),'version':0})
            return 24113,body,0
        client.receive=receive
        with patch('query_player.time.monotonic',return_value=10),patch('query_player.time.sleep') as sleep:
            decoded,_=client.query('LUY2YJP')
        sleep.assert_called_once_with(1)
        self.assertEqual(decoded['profile']['tag'],'#LUY2YJP')

if __name__=='__main__':unittest.main()
