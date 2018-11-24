# python-fido2-client
WebAuthn API FIDO2 client implementation in Python

Simple implementation in Python, slightly tested against https://github.com/Yubico/python-fido2/tree/master/examples/server.
As of today, it is instrumented for interactivity. Tested on python3.6, requires fido2, cbor2, requests.

Calling this example:
```python
import fido2client
c = fido2client.Fido2HttpClient()
c.ssl_verify = False
c.verbose = True

c.authenticate_to(
  'https://localhost:5000',
  '/api/authenticate/begin',
  '/api/authenticate/complete',
)
```

Will lead to:
```
$ python test.py
('BEGIN RESPONSE: ', {'publicKey': {'rpId': 'localhost', 'timeout': 30000, 'challenge': b'\x1d\n\xa0!?  \x8a\xcd\xca\x1a\xdb\xa2}\xe2\xf7\x9e\x8dyvC{\x83\x08\xa2>o;\x17\x11\x1e\x945\xb3', 'allowCredentials': [{'id': b'\x1e.\xd8c\xcd*\x8a\xebI!\t\x9d\x9d\x99-\xb6\x7f\xfbf\xf5\xa0\xab\xa4@\xbc\xe9\x0e\xf6\xf2^\xbaG:\x07\xdcef\xef\xcf\x0e\xf6\xda\xa9\xbf\x06\x84O\xfb\x00e\x88\x7f\xa7\x11\x00g\x90`\xdf\x85\x97\x95Rf', 'type': 'public-key'}], 'userVerification': 'preferred'}})

Touch your authenticator device...

('ASSERTION: ', AssertionResponse(credential: {'id': b'\x1e.\xd8c\xcd*\x8a\xebI!\t\x9d\x9d\x99-\xb6\x7f\xfbf\xf5\xa0\xab\xa4@\xbc\xe9\x0e\xf6\xf2^\xbaG:\x07\xdcef\xef\xcf\x0e\xf6\xda\xa9\xbf\x06\x84O\xfb\x00e\x88\x7f\xa7\x11\x00g\x90`\xdf\x85\x97\x95Rf', 'type': 'public-key'}, auth_data: AuthenticatorData(rp_id_hash: h'49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763', flags: 0x01, counter: 63), signature: h'3046022100c9080974ae855029e00d2d770ae78cb1f524d9953d1f3c5e73e1055ea0ac6a5902210082edf3c9f339e78b3d21ee96bba7b677e7c98542ab4191676cc2f840fa7514b2'))
('CLIENT DATA: ', {"type": "webauthn.get", "clientExtensions": {}, "challenge":   "HQqgIT+Kzcoa26J94veejXl2Q3uDCKI+bzsXER6UNbM=", "origin": "https://localhost:5000"})
('COMPLETE RESPONSE: ', {'status': 'OK'})
Authenticated
$
```

TODO
+ error handling
+ define details of the state machine for interactive and programmatical use cases
+ tests
+ support for credential registration
