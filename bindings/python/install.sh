#!/bin/bash
set -ex
env

PYTHON=$1
SETUP_PY=$2
PREFIX=$3
LIB_DIR=$4

if [ ! -z "$DESTDIR" ]; then
    echo "Using DESTDIR instead of CMAKE_INSTALL_PREFIX"
    PREFIX=${DESTDIR}
fi

$PYTHON $SETUP_PY install --root=$PREFIX --install-lib=$LIB_DIR
