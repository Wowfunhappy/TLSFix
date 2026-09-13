#!/usr/bin/python
# Independent decoding of synthetic output from the native-framework probes.
import base64, ctypes, hashlib, json, math, os, struct, sys, time
from urlparse import urlsplit, parse_qs

def fields(data):
    result=[]; i=0
    def varint(pos):
        v=0; shift=0
        while True:
            b=ord(data[pos]); pos+=1; v|=(b&127)<<shift
            if not b&128: return v,pos
            shift+=7; assert shift<70
    while i<len(data):
        start=i; key,i=varint(i); tag,wire=key>>3,key&7
        if wire==0: value,i=varint(i)
        elif wire in (1,5):
            size=8 if wire==1 else 4; value=data[i:i+size]; i+=size
        else:
            assert wire==2
            n,i=varint(i); value=data[i:i+n]; i+=n
        assert i<=len(data)
        result.append((tag,wire,value,data[start:i]))
    return result

def value(data, tag):
    values=[x[2] for x in fields(data) if x[0]==tag]
    assert len(values)==1
    return values[0]

def validate_url(url):
    parsed=urlsplit(url)
    assert parsed.scheme=='https' and parsed.hostname.startswith('gspe') and parsed.hostname.endswith('-ssl.ls.apple.com')
    pairs=parse_qs(parsed.query)
    assert not set(('tk','mapkey')).intersection(pairs)
    if parsed.hostname=='gspe35-ssl.ls.apple.com':
        assert not set(('sid','accessKey')).intersection(pairs)
        return
    assert pairs['sid']==['6942069420694206942069420694206942067676']
    access,=pairs['accessKey']; stamp,nonce,ciphertext=access.split('_',2)
    assert len(nonce)==16 and nonce.isalnum() and abs(int(stamp)-time.time()-4200)<300
    key=hashlib.sha256('4cjLaD4jGRwlQ9U72xIzEBe0vHBmf9'+nonce).digest()
    encrypted=base64.b64decode(ciphertext)
    out=ctypes.create_string_buffer(len(encrypted)); size=ctypes.c_size_t()
    crypt=ctypes.CDLL('/usr/lib/libSystem.B.dylib').CCCrypt
    crypt.argtypes=[ctypes.c_uint,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
    assert crypt(1,0,1,key,len(key),'\0'*16,encrypted,len(encrypted),out,len(encrypted),ctypes.byref(size))==0
    clean='&'.join(p for p in parsed.query.split('&') if not p.startswith(('sid=','accessKey=')))
    expected=parsed.path+('?' + clean + '&' if clean else '?')+'sid='+pairs['sid'][0]+stamp+nonce
    assert out.raw[:size.value]==expected

root=sys.argv[1]
for arch in ('x86_64','i386'):
    load=lambda name:json.load(open(os.path.join(root,name+'-'+arch+'.json')))
    for mode in ('urls','private-urls'):
        urls=load(mode)
        for url in urls['urls']:
            p=urlsplit(url); assert p.path=='/tile%2Fpart%20one' and p.fragment=='frag'
            q=parse_qs(p.query); assert q['x']==['1','2'] and q['q']==['a+b']
            validate_url(url)
        validate_url(urls['emptyPath']); validate_url(urls['rawURL'])
    baseline=load('disabled-eta')
    assert baseline['moduleLoaded'] is False
    for mode in ('eta','eta-startup'):
        fixed=load(mode); assert fixed['moduleLoaded'] is True
        for field in ('invalid','unsupported'): assert fixed[field]==baseline[field]
        old=base64.b64decode(baseline['directions']); new=base64.b64decode(fixed['directions'])
        assert [f[3] for f in fields(old) if f[0]!=2]==[f[3] for f in fields(new) if f[0]!=22]
        assert not [f for f in fields(new) if f[0]==2]
        waypoints=[f[2] for f in fields(new) if f[0]==22]; assert len(waypoints)==2
        assert value(waypoints[0],1)==4 and value(waypoints[0],5)==1
        assert value(value(waypoints[0],4),1)==base64.b64decode(fixed['location'])
        assert value(waypoints[1],1)==2
        identifier=value(waypoints[1],2); assert value(identifier,7)==16
        coordinate=value(identifier,3)
        lat=struct.unpack('<d',value(coordinate,1))[0]; lng=struct.unpack('<d',value(coordinate,2))[0]
        assert abs(lat-39)<1e-10 and abs(abs(lng)-180)<1e-10
for mode in ('urls','private-urls'):
    gc=json.load(open(os.path.join(root,mode+'-gc.json')))
    for url in gc['urls']+[gc['emptyPath'],gc['rawURL']]: validate_url(url)
print('PASS: independent URL signature and native ETA protobuf validation (both architectures and GC URLs)')
