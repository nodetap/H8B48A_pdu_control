import requests
import base64
import json
import hashlib
import urllib.parse as parse
import re
import sys

class H8B48A:
    None


pdu = H8B48A()

if __name__ == "__main__":
    match sys.argv[1]:
        case 'set_outlet_state':
            pdu.switch_pdu(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]) #ip address, username, password, outlet number[1-24], state[on,off]
        case 'get_outlet_states':
            pdu.get_outlet_states(sys.argv[2], sys.argv[3], sys.argv[4]) #ip address, username, password
        case 'get_overview':
            pdu.get_overview(sys.argv[2], sys.argv[3], sys.argv[4]) #ip address, username, password

sys.exit(0)