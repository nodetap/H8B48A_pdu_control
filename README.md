# H8B48A_pdu_control
This repo provides a basic interface to the H8B48A PDU. It can be accessed from the command line using `main.py {Ip address} {username} {password} {outlet number 1-24} {[on, off]}`

Currently it handles a few different error states within the code and all the same HP defined errors that the JS in the web page handles. The default response is just to fail and pass the error out to the console, leaving the script or user to handle retry.

## Next steps

### Getters for: 
  - voltage
  - current
  - plug state
  - frequency
  - power factor
  - reactive power
  - active power
  - apparent power
  - environmental status?
  - device status

### Setters for:
  - device state
  - branch state

### Session management:
Currently we make and destry a session every time the script is called. 
  - switch to destroy or not destroy session after completion
  - switch to just destroy a particular session
  - switch to use a current sesison
  - distinct error response for session expired


###Radius support
