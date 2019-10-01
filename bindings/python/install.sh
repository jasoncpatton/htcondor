#!/bin/bash
set -ex
env

PYTHON=$1
SETUP_PY=$2
PREFIX=$3
LIB_DIR=$4

if [ ! -z "$DESTDIR" ]; then
    echo "Prepending DESTDIR to install location"
    PREFIX=${DESTDIR}/${PREFIX}
fi

$PYTHON $SETUP_PY install --root=$PREFIX --install-lib=$LIB_DIR
