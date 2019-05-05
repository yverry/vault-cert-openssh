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
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import hvac
import time, os
import base64
from struct import unpack

def vaultrenewkey(filename, vault_var):
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
  error = 0
  vault_var = dict()

  if os.environ['VAULT_SSHSIGNPATH']:
    vault_var['VAULT_SSHSIGNPATH'] = os.environ['VAULT_SSHSIGNPATH']
    error = error + 1
  if os.environ['VAULT_ADDR']:
    vault_var['VAULT_ADDR'] = os.environ['VAULT_ADDR']
    error = error + 1
  try:
    vault_var['VAULT_TOKEN'] = os.environ['VAULT_TOKEN']
    error = error + 1

  except KeyError:
    from os.path import expanduser
    home = expanduser("~")
    o = open(home + '/.vault-token','r')
    vault_var['VAULT_TOKEN'] = o.read().splitlines()[0]
    error = error + 1


  if error != 3:
    print("Variable missing")
    exit(1)

  if len(sys.argv) > 1:
    with open(sys.argv[1],'r') as f:
      key = Decode(f.read().split(" ")[1])
      if int(time.time()) > key['valid before']:
          print("Need to renew" + sys.argv[1])
          vaultrenewkey(sys.argv[1],vault_var)
      else:
          print("Nothing to do")
  else:
    print("Usage: %s [path to certificate]" % sys.argv[0])
    exit(1)