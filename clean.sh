#!/bin/bash

make clean
sudo make uninstall
echo "rm /usr/lib64/purple-2/libnull.*"
echo "...."
sudo rm /usr/lib64/purple-2/libnull.*
echo "done."
