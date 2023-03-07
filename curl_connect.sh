#!/bin/bash


# openssl s_client -connect localhost:4000 -prexit -debug -msg -tlsextdebug -status
/opt/homebrew/opt/curl/bin/curl --tlsv1.3 -iv  -debug https://localhost:4000
# curl --tlsv1.3 --ciphers TLS_AES_128_GCM_SHA256  https://localhost:4000

