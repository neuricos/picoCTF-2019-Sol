#!/bin/bash

openssl x509 -text -pubkey -noout -in cert > key.pub
modulus=$(openssl rsa -text -pubin -in key.pub 2>/dev/null | grep Modulus | awk '{ print $2 }')
curl "http://factordb.com/api/index.php?query=${modulus}" --silent | python3 -c 'import sys, json; factors = json.load(sys.stdin)["factors"]; q, p = factors[0][0], factors[1][0]; print("picoCTF{%s,%s}" % (p, q))'
