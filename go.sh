#!/bin/bash

make -j5
sudo make install
echo
echo "cp to /usr/lib64/purple-2/"
echo "....."
sudo cp /usr/local/lib/purple-2/libnull.so /usr/lib64/purple-2/
sudo cp /usr/local/lib/purple-2/libnull.la /usr/lib64/purple-2/
echo "done."
