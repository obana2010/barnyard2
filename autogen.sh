#!/bin/sh
# Run this to generate all the initial makefiles, etc.
autoreconf -fvi -I /usr/local/share/aclocal -I ./m4

./configure --enable-debug
