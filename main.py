import requests
import base64
import json
import hashlib
import urllib.parse as parse
import re
import sys

def convert_to_iso8859_1(data):
    try:
        return data.encode('iso-8859-1')
    except UnicodeEncodeError:
        return None


def logout(sessionID, ip_addr):
    response = requests.get(f'http://{ip_addr}/config/gateway?page=cgi_logout&sessionId={sessionID}')
    if response.status_code == 200:
        #print(f'Cleaned up Session {sessionID}')
        return 'logout'
    else:
        sys.exit('failed to terminate session')

def generate_session_key(login_user, realm, password_user, nonce, cnonce):
    #these are just here to support internationalization
    login_challenge = convert_to_iso8859_1(login_user)
    if login_challenge is None:
        login_challenge = login_user.encode('utf-8')
        
    realm_challenge = convert_to_iso8859_1(realm)
    if realm_challenge is None:
        realm_challenge = realm.encode('utf-8')
        
    password_challenge = convert_to_iso8859_1(password_user)
    if password_challenge is None:
        password_challenge = password_user.encode('utf-8')

    #--------------Don't change anything between here and the next break, this is a house of cards to make the authentication happy---#
    #needs to be bytes, NOT a format string
    combined = login_challenge + b':' + realm_challenge + b':' + password_challenge
    #extremely critical this is just digest, we need the raw binary
    md5_hash = hashlib.md5(combined).digest()
    #yes, there are 100 more 'python' ways to do this, but it has to do things the "javascript way" 
    #or the hash will fail and it will not auth
    md5_binary_string = ''.join(chr(byte) for byte in md5_hash)     
    a1 = f"{md5_binary_string}:{nonce}:{cnonce}"
    #need to use latin1 so we can properly handle the non-printing chars
    session_key = hashlib.md5(a1.encode('latin1')).hexdigest()  
    #the session key is what we use to authenticate the session, once it's passed the session is auth'd and we no longer need the key
    #and we can just use the sessionID. definitely a possible attack vector here
    return session_key
    #---------------------------------------------------------------------------------------------------------------------------------#

def manageResultAuthentication(loginuser, sessionID):
    #print('managing login for : ' + loginuser)
    #print('sessionID: ' + sessionID)
    #at some point I'm going to make these sessions reusable so this function exists to expand into that capability, there is some way to 
    #do that with the requests library. Maybe make this whole thing a class and have the session be public? !more to do here!
    return(sessionID)

def login_and_get_session_id(loginUser, passwordUser, ip_addr):
    response = requests.get(f'http://{ip_addr}/config/gateway?page=cgi_authentication&login={parse.quote(base64.b64encode(loginUser.encode("ascii")).decode())}')
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
            manageResultAuthentication(loginUser, response_data_formatted['data'][0])
        elif success_resp_formatted['success'] == 'true' and response_data_formatted['data'][3] == 0 and response_data_formatted['data'][5] != 'password' and response_data_formatted['data'][5] != 'challenge' and response_data_formatted['data'][5] != 'radiusChallenge':
            sys.exit(f'{loginUser} does not have access')
        elif success_resp_formatted['success'] == 'true' and response_data_formatted['data'][5] == 'password':
            #responsePassword(loginUser, PasswordUser, result.data[0])
            NotImplemented #no clue when we would end up here but this is present in the JS
        elif success_resp_formatted['success'] == 'true' and response_data_formatted['data'][5] == 'challenge':
            return responseChallenge(loginUser, passwordUser, response_data_formatted['data'][0], response_data_formatted['data'][6], ip_addr)
        elif success_resp_formatted['success'] == 'true' and response_data_formatted['data'][5] == 'radiusChallenge':
            #responseRadiusChallenge(loginUser, passwordUser, result.data[0], result.data[6]) #radius not implimented
            NotImplemented
        else:
            NotImplemented
    else:
        sys.exit(f'http response {response.status_code}')
    
def responseChallenge(loginUser, passwordUser, sessionID, data, ip_addr):
    szUsername = loginUser
    szRealm = data[0]
    szNonce = data[1]
    szCnonce = data[2]
    szUri = data[3]
    szQop = data[4]
    uiNcValue = "00000001"
    sessionKey = generate_session_key(szUsername,szRealm,passwordUser,szNonce,szCnonce)
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
    response = requests.get(f"http://{ip_addr}/config/gateway?page=cgi_authenticationChallenge&sessionId={sessionID}&login={parse.quote(base64.b64encode(loginUser.encode()).decode())}&sessionKey={sessionKey}&szResponse={szResponse}&szResponseValue={szResponseValue}")
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
                    sys.exit(f'HP Error:{resp_json['error']} Same User')
                case 3332:
                    sys.exit(f'HP Error:{resp_json['error']} Session Expired')
                case 3334:
                    sys.exit('HP Error: 3334 too many connections')
                case 3337 | 3338 | 3341 | 3347 | 3348 | 3351 | 3352 | 3407 | 3442 | 3443: 
                    sys.exit(f'HP Error:{resp_json['error']} Permission error')
                case 3353 | 3444:
                    sys.exit(f'HP Error:{resp_json['error']} Authentication configuration error')
                case 3342 | 3354 | 3355 | 3356 | 3372 | 3376 | 3441 | 3447 | 3452:
                    sys.exit(f'HP Error:{resp_json['error']} Server conneciton error')
                case 11:
                    sys.exit(f'HP Error:{resp_json['error']} Session expired')
                case _:
                    sys.exit(f'HP error:{resp_json['error']}')
        if([5] in resp_json['data']):
            if(resp_json['data'][5] == 'challenge'):
                sys.exit('invalid username or password')
                #possible to retry here: responseChallenge(loginUser, passwordUser, resp_json['data'][0], resp_json['data'][6])
        elif(resp_json['success'] and resp_json['data'][3] != 0):
            return manageResultAuthentication(loginUser, sessionID)
        else:
            sys.exit('data mangled')

def switch_pdu(ip_addr, user, password, outlet, state): #outlet is an int between 1 and 24, state is a string, either off or on
    sessionID = login_and_get_session_id(user, password, ip_addr)
    if(outlet < 1 or outlet > 24):
        sys.exit(f'{outlet} is not a valid port id')
    elif(state == 'on'):
        requests.post(f'http://{ip_addr}/config/set_object_mass.xml?sessionId={sessionID}', f"<SET_OBJECT><OBJECT name='PDU.OutletSystem.Outlet[{outlet}].DelayBeforeStartup'>0</OBJECT></SET_OBJECT>")

    elif(state == 'off'):
        requests.post(f'http://{ip_addr}/config/set_object_mass.xml?sessionId={sessionID}', f"<SET_OBJECT><OBJECT name='PDU.OutletSystem.Outlet[{outlet}].DelayBeforeShutdown'>0</OBJECT></SET_OBJECT>")
    else:
        sys.exit('please enter a valid state')
    logout(sessionID, ip_addr)

switch_pdu(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

sys.exit(0)
