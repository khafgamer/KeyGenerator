"""import random
bits = random.getrandbits(256)
# 30848827712021293731208415302456569301499384654877289245795786476741155372082
bits_hex = hex(bits)
# 0x4433d156e8c53bf5b50af07aa95a29436f29a94e0ccc5d58df8e57bdc8583c32
private_key = bits_hex[2:]
# 4433d156e8c53bf5b50af07aa95a29436f29a94e0ccc5d58df8e57bdc8583c32
print(private_key)
"""
import base58
import codecs
import ecdsa
import hashlib
#-----------------------------------------------------------------------
#generate Private Key
import secrets
bits = secrets.randbits(256)
bits_hex = hex(bits)
private_key = bits_hex[2:]
private_key='60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2'

private_key='1054f7fe5781b61b5a69fdff2f9b6533b6249875274380897a23dac0a5cd04ca'
print("private_key=",private_key)
#-----------------------------------------------------------------------c
#Private Key Base58
print("Private_Key_Base58(Text Format)=",base58.b58encode(private_key))
unencoded_string = bytes.fromhex((private_key))
encoded_string= base58.b58encode(unencoded_string)
print("Private_Key_Base58(HEX Format)=",encoded_string)
#-----------------------------------------------------------------------
#generate Full public key from PrivateKey
p=codecs.decode(private_key,'hex')
key=(ecdsa.SigningKey.from_string(p,curve=ecdsa.SECP256k1).verifying_key)
key_byte=key.to_string()
PublicKey=codecs.encode(key_byte,'hex')
FullPublicKey=b'04'+PublicKey
print("FullPublicKey",FullPublicKey)
#print(len(FullPublicKey))
#-----------------------------------------------------------------------
#Public key pressed from Full public key
PressedPublicKey=PublicKey[0:int(len(PublicKey)/2)]
#print("PressedPublicKey=",PressedPublicKey)
#print(PressedPublicKey.hex())
#print(PressedPublicKey[len(PressedPublicKey)-1])
q=PressedPublicKey[len(PressedPublicKey)-1]
if (((q<58)and(q%2==0))or((q>57)and((q-1)%2==0))):
    PressedPublicKey=b'03'+PressedPublicKey
else:
   PressedPublicKey=b'02'+PressedPublicKey
print("PressedPublicKey=",PressedPublicKey)
print(type(PressedPublicKey))
#-----------------------------------------------------------------------

"""m = hashlib.sha256()
m.update(PressedPublicKey)
t=(m.digest())
h = hashlib.new('ripemd160')
h.update(t)
print(h.hexdigest())"""