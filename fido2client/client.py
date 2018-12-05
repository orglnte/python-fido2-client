import urllib
import base64
import getpass
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import base64

import simplejson
import requests
import cbor2 as cbor
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client



class Fido2HttpClient(object):
    session = None
    server = None
    dev = None
    ssl_verify = True
    begin_url = None
    complete_url = None
    is_authenticated = False
    verbose = False

    def authenticate_to(self,
            server, begin_endpoint, complete_endpoint,
            session=None, append_to_data=None, append_to_headers=None):
        self.server = server
        self.init_dev()
        begin_url = urllib.parse.urljoin(server, begin_endpoint)
        complete_url = urllib.parse.urljoin(server, complete_endpoint)

        if self.dev:
            # assign or create session
            if session:
                self.session = session
            if not self.session:
                self.session = requests.session()

            self.begin(begin_url,
                append_to_headers=append_to_headers)
            self.complete(complete_url,
                append_to_data=append_to_data,
                append_to_headers=append_to_headers)
        return self.is_authenticated

    def log(self, *args):
        if self.verbose: print(args)

    def ask_for_interaction(self):
        print('Touch your authenticator device...')

    def say_no_device_found(self):
        print('No FIDO device found')

    def say_authenticated(self):
        print('Authenticated')

    def say_not_authenticated(self, data):
        print('Not Authenticated')

    def init_dev(self):
        self.dev = next(CtapHidDevice.list_devices(), None)
        if not self.dev:
            self.say_no_device_found()            

    def begin(self, begin_url, append_to_headers=None):
        headers = {}
        if append_to_headers:
            for k in append_to_headers:
                headers[k] = append_to_headers[k]

        r = self.session.post(begin_url,
            verify=self.ssl_verify,
            headers=headers)

        self.begin_data = cbor.loads(r.content)
        self.log('BEGIN RESPONSE: ', self.begin_data)

    def complete(self, complete_url, append_to_data=None, append_to_headers=None):
        fido2_client = Fido2Client(self.dev, self.server)

        pubkey = self.begin_data['publicKey']
        challenge = base64.b64encode(pubkey['challenge'])
        challenge = challenge.decode('utf-8')
        allow_list = [{
            'type': 'public-key',
            'id': pubkey['allowCredentials'][0]['id'],
        }]

        # get Assertion
        self.ask_for_interaction()
        try:
            assertions, client_data = fido2_client.get_assertion(
                pubkey['rpId'],
                challenge,
                allow_list)
        except ValueError:
            assertions, client_data = fido2_client.get_assertion(
                pubkey['rpId'],
                challenge,
                allow_list,
                pin=getpass.getpass('Please enter PIN:'))

        assertion = assertions[0]
        self.log('ASSERTION: ', assertion)
        self.log('CLIENT DATA: ', client_data)

        user_data = {}
        if append_to_data:
            user_data = append_to_data
        user_data = base64.b64encode(simplejson.dumps(user_data).encode('utf-8'))

        data = {
            'credentialId': assertion.credential['id'],
            'authenticatorData': assertion.auth_data,
            'clientDataJSON': client_data,
            'signature': assertion.signature,
            'user_data': user_data,
        }
        body = cbor.dumps(data)
        headers = {'content-type': 'application/cbor'}
        if append_to_headers:
            for k in append_to_headers:
                headers[k] = append_to_headers[k]

        r = self.session.post(complete_url,
            verify=self.ssl_verify,
            headers=headers,
            data=body
        )
        self._last_response = r

        data = cbor.loads(r.content)
        self.log('COMPLETE RESPONSE: ', data)
        if 'status' in data and data['status'] == 'OK':
            self.is_authenticated = True
        else:
            self.is_authenticated = False

        if self.is_authenticated: self.say_authenticated()
        else: self.say_not_authenticated(data)
        return self.is_authenticated

    def get_last_response(self):
        return self._last_response

