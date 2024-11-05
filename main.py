from H8B48A import H8B48A
import sys

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