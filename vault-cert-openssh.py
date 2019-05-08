#!/usr/bin/env python3
#
# OpenSSH certificate sign with Hashicorp Vault
# https://github.com/yverry/vault-cert-openssh
#
# References:
# - https://tools.ietf.org/html/rfc4251.html#section-5
# - http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
# - https://gist.github.com/corny/8264b74a130eb663dbf3d3f0fe0e0ec9
#


import hvac
import time, os
import base64
from struct import unpack

def vaultRenewKey(filename, vault_var):
    sshKey = filename.replace('-cert','')
    public_key = open(sshKey,'r')
    client = hvac.Client(url=vault_var['VAULT_ADDR'], token=vault_var['VAULT_TOKEN'])
    renew = client.write(vault_var['VAULT_SSHSIGNPATH'],public_key=public_key.read())
   
    if len(renew['data']['signed_key']) > 0:
      s = open(filename,'w')
      s.write(renew['data']['signed_key'])
      s.close()

def Decode(base64encoded):
  certType, bin = decodeString(base64.b64decode(base64encoded))

  h = {}
  for typ, key in formats[certType.decode('UTF-8')]:
    val, bin = typ(bin)
    h[key] = val
  return h

def decodeUint32(value):
  return unpack('>I', value[:4])[0], value[4:]

def decodeUint64(value):
  return unpack('>Q', value[:8])[0], value[8:]

def decodeMpint(value):
  size = unpack('>I', value[:4])[0]+4
  return None, value[size:]

def decodeString(value):
  size = unpack('>I', value[:4])[0]+4
  return value[4:size], value[size:]

def decodeList(value):
  joined, remaining = decodeString(value)
  list = []
  while len(joined) > 0:
    elem, joined = decodeString(joined)
    list.append(elem)
  return list, remaining

rsaFormat = [
  (decodeString, "nonce"),
  (decodeMpint,  "e"),
  (decodeMpint,  "n"),
  (decodeUint64, "serial"),
  (decodeUint32, "type"),
  (decodeString, "key id"),
  (decodeString, "valid principals"),
  (decodeUint64, "valid after"),
  (decodeUint64, "valid before"),
  (decodeString, "critical options"),
  (decodeString, "extensions"),
  (decodeString, "reserved"),
  (decodeString, "signature key"),
  (decodeString, "signature"),
]

ecdsaFormat = [
  (decodeString, "nonce"),
  (decodeString, "curve"),
  (decodeString, "public_key"),
  (decodeUint64, "serial"),
  (decodeUint32, "type"),
  (decodeString, "key id"),
  (decodeString, "valid principals"),
  (decodeUint64, "valid after"),
  (decodeUint64, "valid before"),
  (decodeString, "critical options"),
  (decodeString, "extensions"),
  (decodeString, "reserved"),
  (decodeString, "signature key"),
  (decodeString, "signature"),
]

ed25519Format = [
  (decodeString, "nonce"),
  (decodeString, "pk"),
  (decodeUint64, "serial"),
  (decodeUint32, "type"),
  (decodeString, "key id"),
  (decodeList,   "valid principals"),
  (decodeUint64, "valid after"),
  (decodeUint64, "valid before"),
  (decodeString, "critical options"),
  (decodeString, "extensions"),
  (decodeString, "reserved"),
  (decodeString, "signature key"),
  (decodeString, "signature"),
]

formats = {
  "ssh-rsa-cert-v01@openssh.com":        rsaFormat,
  "ecdsa-sha2-nistp256-v01@openssh.com": ecdsaFormat,
  "ecdsa-sha2-nistp384-v01@openssh.com": ecdsaFormat,
  "ecdsa-sha2-nistp521-v01@openssh.com": ecdsaFormat,
  "ssh-ed25519-cert-v01@openssh.com":    ed25519Format,
}


  

if __name__ == "__main__":
  import sys
  vault_var = dict()

  try:
    vault_var['VAULT_SSHSIGNPATH'] = os.environ['VAULT_SSHSIGNPATH']
    vault_var['VAULT_ADDR'] = os.environ['VAULT_ADDR']
  except KeyError as e:
    print('Error ' + str(e) + ' variable is missing')

  try:
    vault_var['VAULT_TOKEN'] = os.environ['VAULT_TOKEN']
  except KeyError:
    from os.path import expanduser
    home = expanduser("~")
    o = open(home + '/.vault-token','r')
    vault_var['VAULT_TOKEN'] = o.read().splitlines()[0]

  if len(sys.argv) > 1:
    try:
      with open(sys.argv[1],'r') as f:
        key = Decode(f.read().split(" ")[1])
        if int(time.time()) > key['valid before']:
            print("Need to renew" + sys.argv[1])
            vaultRenewKey(sys.argv[1],vault_var)
        else:
            print("Nothing to do")
    except FileNotFoundError:
      vaultRenewKey(sys.argv[1],vault_var)
  else:
    print("Usage: %s [path to certificate]" % sys.argv[0])
    exit(1)