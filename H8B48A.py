import requests
import base64
import json
import hashlib
import urllib.parse as parse
import re
import sys

class H8B48A:
    
    def __init__(self, ip_addr, username, password):
        """
            Initializing the connection here, the decision was made to create and authenticate a session during init so it takes in the data needed for that and
            authenicates a sesison

        Args:
            ip_addr:str this should be the ip address (or hostname) of the PDU
            username:str username to log into the PDU
            password:str password to log into the PDU
        Returns:
            none

        """
        self.ports = [{} for x in range(0,24)]
        self.ip_addr = ip_addr
        self.username = username
        self.password = password
        self.create_session_id()

    def create_session_id(self):
        """
            Creates a session and gets a SessionID. then authenticates that sessionID with the server.

        Args:
            none
        Returns:
            none: raises exceptions to deal with issues.

        """
        print("Creating session")
        response = requests.get(f'http://{self.ip_addr}/config/gateway?page=cgi_authentication&login={parse.quote(base64.b64encode(self.username.encode("ascii")).decode())}')
        if (response.status_code == 200):
            success_resp = response.text[1:response.text.index('data')-2]
            success_resp = success_resp.strip()
            success_resp = '{\"' + success_resp[:success_resp.index(':')] + '\": \"' +  success_resp[success_resp.index(':')+1:success_resp.index(',')] +'\", \"' + success_resp[success_resp.index('status'):success_resp.index('status')+6] + '\": \"' + success_resp[success_resp.index('status') + 7:] + '\"}'
            success_resp_formatted = json.loads(success_resp)
            response_data = '{' + response.text[response.text.index('data'):]
            response_data = response_data.replace('\'','\"')
            response_data = response_data.replace('data','\"data\"')
            response_data_formatted = json.loads(response_data)
            if success_resp_formatted['success'] == 'true' and response_data_formatted['data'][3] != 0 and response_data_formatted['data'][5] != 'password' and response_data_formatted['data'][5] != 'challenge' and response_data_formatted['data'][5] != 'radiusChallenge':
                self.sessionID = response_data_formatted['data'][0]
            elif success_resp_formatted['success'] == 'true' and response_data_formatted['data'][3] == 0 and response_data_formatted['data'][5] != 'password' and response_data_formatted['data'][5] != 'challenge' and response_data_formatted['data'][5] != 'radiusChallenge':
                raise Exception("User is authenticated but does not have permission.")
            elif success_resp_formatted['success'] == 'true' and response_data_formatted['data'][5] == 'password':
                raise NotImplementedError("This is an undefined state.")
            elif success_resp_formatted['success'] == 'true' and response_data_formatted['data'][5] == 'challenge':
                self.sessionID = response_data_formatted['data'][0]
                print(f"Session ID received: {self.sessionID}.")
                self.responseChallenge(response_data_formatted['data'][6])
            elif success_resp_formatted['success'] == 'true' and response_data_formatted['data'][5] == 'radiusChallenge':
                raise NotImplementedError("Radius is not implimented")
            else:
                raise NotImplementedError("This state is undefined or otherwise not implimented")
        else:
            raise Exception(f'http response {response.status_code}')

    def responseChallenge(self, data):
        """
            The bulk of the authentication happens in this function. The authentication request is a pretty gnarly format string but should be relatively easy to parse.
            Lots of bit manipulation going on here. Once this completes, our sessionID is authenticated and ready to be used to conduct transactions.

        Args:
            data:list data should be passed in from the session creation response as ['data'][6]
        Returns:
            none, but it raises exceptions to handle issues with the connection
        """
        szRealm = data[0]
        szNonce = data[1]
        szCnonce = data[2]
        szUri = data[3]
        szQop = data[4]
        uiNcValue = "00000001"
        sessionKey = self.generate_session_key(szRealm,szNonce,szCnonce)
        print(f"Sesison key generated: {sessionKey}")
        a2Client = "AUTHENTICATE:" + szUri 
        if (szQop != "auth"): 
            a2Client = "AUTHENTICATE:" + szUri + ":00000000000000000000000000000000"
        s2Client = hashlib.md5(a2Client.encode()).hexdigest()
        szResponse = hashlib.md5(f"{sessionKey}:{szNonce}:{uiNcValue}:{szCnonce}:{szQop}:{s2Client}".encode()).hexdigest()
        a2Server = f":{szUri}"
        if szQop != "auth":
            a2Server = ":" + szUri + ":00000000000000000000000000000000"
        s2Server = hashlib.md5(a2Server.encode()).hexdigest()
        szResponseValue = f"{sessionKey}:{szNonce}:{uiNcValue}:{szCnonce}:{szQop}:{s2Server}"
        szResponseValue = hashlib.md5(szResponseValue.encode()).hexdigest()
        response = requests.get(f"http://{self.ip_addr}/config/gateway?page=cgi_authenticationChallenge&sessionId={self.sessionID}&login={parse.quote(base64.b64encode(self.username.encode()).decode())}&sessionKey={sessionKey}&szResponse={szResponse}&szResponseValue={szResponseValue}")
        if response.status_code == 200:
            response_text = response.text
            response_text = response_text.replace("'", '"')
            response_text = re.sub(r'\btrue\b', 'true', response_text)
            response_text = re.sub(r'\bfalse\b', 'false', response_text)
            response_text = re.sub(r'(\w+):', r'"\1":', response_text)
            resp_json = json.loads(response_text)
            if('error' in resp_json):
                match resp_json['error']:
                    case 3336:
                        raise Exception(f"HP Error:{resp_json['error']} Same User")
                    case 3332:
                        raise Exception(f"HP Error:{resp_json['error']} Session Expired")
                    case 3334:
                        raise Exception("HP Error: 3334 too many connections")
                    case 3337 | 3338 | 3341 | 3347 | 3348 | 3351 | 3352 | 3407 | 3442 | 3443: 
                        raise Exception(f"HP Error:{resp_json['error']} Permission error")
                    case 3353 | 3444:
                        raise Exception(f"HP Error:{resp_json['error']} Authentication configuration error")
                    case 3342 | 3354 | 3355 | 3356 | 3372 | 3376 | 3441 | 3447 | 3452:
                        raise Exception(f"HP Error:{resp_json['error']} Server conneciton error")
                    case 11:
                        raise Exception(f"HP Error:{resp_json['error']} Session expired")
                    case _:
                        raise Exception(f"HP error:{resp_json['error']}")
            if([5] in resp_json['data']):
                if(resp_json['data'][5] == 'challenge'):
                    raise Exception('Invalid username or password')
                    #possible to retry here: responseChallenge(loginUser, passwordUser, resp_json['data'][0], resp_json['data'][6])
            elif(resp_json['success'] and resp_json['data'][3] != 0):
                print(f"Challenge finished and authentication successful. SessionID: {self.sessionID}")
            else:
                raise Exception('Data mangled.')

    def generate_session_key(self, realm, nonce, cnonce):
        """
            This function is largely evil, I didn't like writing it and I dont like looking at it. but it works and mangles the right
            bits to make authentication work with the server.
        Args:
            realm:str should be passed directly from what is received from the server during auth
            nonce:str should be passed directly from what is received from the server during auth
            cnonce:str should be passed directly from what is received from the server during auth
        Returns:
            the session key which we need to complete authentication
        """
        #these are just here to support internationalization
        login_challenge = self.convert_to_iso8859_1(self.username)
        if login_challenge is None:
            login_challenge = self.username.encode('utf-8')

        realm_challenge = self.convert_to_iso8859_1(realm)
        if realm_challenge is None:
            realm_challenge = realm.encode('utf-8')

        password_challenge = self.convert_to_iso8859_1(self.password)
        if password_challenge is None:
            password_challenge = self.password.encode('utf-8')

        #---Don't change anything between here and the next break, this is a house of cards to make the authentication happy---#
        #needs to be bytes, NOT a format string
        combined = login_challenge + b':' + realm_challenge + b':' + password_challenge
        #extremely critical this is just digest, we need the raw binary
        md5_hash = hashlib.md5(combined).digest()
        #we have to do things the "javascript way" 
        #or the hash will fail and it will not auth
        md5_binary_string = ''.join(chr(byte) for byte in md5_hash)     
        a1 = f"{md5_binary_string}:{nonce}:{cnonce}"
        #need to use latin1 so we can properly handle the non-printing chars
        session_key = hashlib.md5(a1.encode('latin1')).hexdigest()  
        #the session key is what we use to authenticate the session, once it's passed the session is auth'd and we no longer need the key
        #and we can just use the sessionID. definitely a possible attack vector here
        return session_key
        #----------------------------------------------------------------------------------------------------------------------#

    def convert_to_iso8859_1(self, data):
        """
            This function is used internally to check if a string can be encoded as iso-8859-1, does so if it can. If it can't, it returns none and the system
            comes crashing down. this is a feature not a bug as the server can not handle chars that are not latin-1 encoded.
        Args:
            data:str
        Returns:
            iso-8851-1 encoded strings or none if its not possible to convert
        """
        try:
            return data.encode('iso-8859-1')
        except UnicodeEncodeError:
            return None

    def set_outlet_state(self, outlet, state):
        """
            Pulls down the current outlet states. Does a bit of formatting on them and dumps them to stdout. Handles some errors
            in response from the server. More error handling needed. 
        Args:
            outlet:int|str  [1-9][1-9] (1-24)
            state:str       either 'on' or 'off'
        Returns:
            TODO: build a return system so this data is actualy useful
        """
        try:
            outlet = int(outlet)
        except:
            raise Exception(f"Invalid outlet: {outlet}. The only valid outlets are 1-24.")
        if(outlet < 1 or outlet > 24):
            sys.exit(f'{outlet} is not a valid port id')
            raise Exception(f"Invalid outlet: {outlet}. The only valid outlets are 1-24.")
        elif(state == 'on'):
            requests.post(f'http://{self.ip_addr}/config/set_object_mass.xml?sessionId={self.sessionID}', f"<SET_OBJECT><OBJECT name='PDU.OutletSystem.Outlet[{outlet}].DelayBeforeStartup'>0</OBJECT></SET_OBJECT>")
        elif(state == 'off'):
            requests.post(f'http://{self.ip_addr}/config/set_object_mass.xml?sessionId={self.sessionID}', f"<SET_OBJECT><OBJECT name='PDU.OutletSystem.Outlet[{outlet}].DelayBeforeShutdown'>0</OBJECT></SET_OBJECT>")
        else:
            raise Exception(f"Invalid outlet state: {state}. The only valid states are 'off' and 'on'")

    def get_outlet_states(self):
        """
            Pulls down the current outlet states. Does a bit of formatting on them and dumps them to stdout. Handles some errors
            in response from the server. More error handling needed
        Args:
            none
        Returns:
            TODO: build a return system so this data is actualy useful
        """
        print(f"Getting outlet states for sessionID: {self.sessionID}")
        response = requests.get(f"http://{self.ip_addr}/config/gateway?page=cgi_pdu_outlets&sessionId={self.sessionID}")
        response_text = response.text
        response_text = response_text.replace("'", '"')
        response_text = re.sub(r'\btrue\b', 'true', response_text)
        response_text = re.sub(r'\bfalse\b', 'false', response_text)
        response_text = re.sub(r'(\w+):', r'"\1":', response_text)
        resp_json = json.loads(response_text)
        if 'error' in resp_json:
            match resp_json['error']:
                case 3335:
                    raise Exception(f"SessionID does not exist: {self.sessionID}")
        else:
            print(f"outlet l1-3{resp_json['data'][0][2][0]}")
            print(f"outlet l1-4{resp_json['data'][0][3][0]}")
            n = 0
            for i in self.ports:
                i['HPname'] = resp_json['data'][0][n][0][0]
                i['attacheDevice'] = resp_json['data'][0][n][0][1]
                i['powerState'] = 'on' if resp_json['data'][0][n][0][3] == 1 else 'off'
                print(f'outlet {n}, is {i}')
                n += 1

    def get_overview(self):
        """
            Pulls down overview data from the overview API on the server. currently just passing it out to stdout as a python dict. Handles some errors
            in response from the server. More error handling needed for non-200 status codes and other failures.
        Args:
            none
        Returns:
            TODO: build a return system so this data is actualy useful
        """
        print(f"Getting overview for sessionID: {self.sessionID}")
        response = requests.get(f"http://{self.ip_addr}/config/gateway?page=cgi_overview&sessionId={self.sessionID}")
        response_text = response.text
        response_text = response_text.replace("'", '"')
        response_text = re.sub(r'\btrue\b', 'true', response_text)
        response_text = re.sub(r'\bfalse\b', 'false', response_text)
        response_text = re.sub(r'(\w+):', r'"\1":', response_text)
        response_text = response_text.replace(',,','') #python /really/ doesn't like the double comma. json.loads barfs if it is passed.
        resp_json = json.loads(response_text)
        if 'error' in resp_json:
            match resp_json['error']:
                case 3335:
                    raise Exception(f"SessionID does not exist: {self.sessionID}")
        else:
            print(resp_json)

    def logout(self):
        """
            Passes the current sessionID up to the server to sever the connection. If we don't do this, the server will quickly stop accepting new connections. Raises
            an exception if it gets any response but 200 from the server.
        Args:
            none
        Returns:
            none
        """
        response = requests.get(f'http://{self.ip_addr}/config/gateway?page=cgi_logout&sessionId={self.sessionID}')
        if response.status_code == 200:
            print(f'Cleaned up Session {self.sessionID}')
        else:
            raise Exception('failed to terminate session')

if __name__ == "__main__":
    pdu = H8B48A('10.0.5.22', 'admin', 'admin')
    match sys.argv[1]:
        case 'set_outlet_state':
            pdu.set_outlet_state(sys.argv[2], sys.argv[3]) #outlet number[1-24], state[on,off]
        case 'get_outlet_states':
            pdu.get_outlet_states() 
        case 'get_overview':
            pdu.get_overview() 
    pdu.logout()
sys.exit(0)