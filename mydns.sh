#!/bin/sh

HOST=www.MyDNS.jp
UNAME=mydns64505
PASS=UQ4ti8p5

ftp -nv $HOST <<EOF
user $UNAME $PASS
quit
EOF
