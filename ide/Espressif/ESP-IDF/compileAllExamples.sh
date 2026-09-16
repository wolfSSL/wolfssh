#!/usr/bin/env bash

# Build every wolfSSH ESP-IDF example project under ./examples/
#
# The examples carry local wolfssh and wolfssl components that compile the
# library sources in place, so both source trees have to be on disk. Their
# CMakeLists find them through the WOLFSSH_ROOT and WOLFSSL_ROOT environment
# variables, which this script fills in when they are not already set.
#
# Run from an ESP-IDF environment:
#
#   . /opt/esp/idf/export.sh
#   WOLFSSL_ROOT=/path/to/wolfssl ide/Espressif/ESP-IDF/compileAllExamples.sh
#
# WOLFSSH_ROOT defaults to the tree holding this script, WOLFSSL_ROOT to a
# wolfssl checkout beside it. IDF_TARGET selects the chip; default esp32.

if [ -z "${IDF_PATH}" ]; then
    echo "ERROR: IDF_PATH is not set. Source the ESP-IDF export.sh first."
    exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

if [ -z "${WOLFSSH_ROOT}" ]; then
    WOLFSSH_ROOT=$(cd "${SCRIPT_DIR}/../../.." && pwd)
fi

if [ -z "${WOLFSSL_ROOT}" ]; then
    WOLFSSL_ROOT="$(dirname "${WOLFSSH_ROOT}")/wolfssl"
fi

export WOLFSSH_ROOT
export WOLFSSL_ROOT
export IDF_TARGET="${IDF_TARGET:-esp32}"

if [ ! -f "${WOLFSSH_ROOT}/wolfssh/ssh.h" ]; then
    echo "ERROR: no wolfSSH source in WOLFSSH_ROOT=${WOLFSSH_ROOT}"
    exit 1
fi

if [ ! -f "${WOLFSSL_ROOT}/wolfssl/ssl.h" ]; then
    echo "ERROR: no wolfSSL source in WOLFSSL_ROOT=${WOLFSSL_ROOT}"
    echo "Clone wolfssl beside wolfssh or set WOLFSSL_ROOT."
    exit 1
fi

echo "IDF_PATH     = ${IDF_PATH}"
echo "IDF_TARGET   = ${IDF_TARGET}"
echo "WOLFSSH_ROOT = ${WOLFSSH_ROOT}"
echo "WOLFSSL_ROOT = ${WOLFSSL_ROOT}"

BUILT=""
FAILED=""

for PROJECT in "${SCRIPT_DIR}"/examples/*/; do
    # A project directory is one with a top level CMakeLists.txt.
    if [ ! -f "${PROJECT}/CMakeLists.txt" ]; then
        continue
    fi

    NAME=$(basename "${PROJECT}")

    echo
    echo "--------------------------------------------------------------"
    echo "Building ${NAME} for ${IDF_TARGET}"
    echo "--------------------------------------------------------------"

    if (cd "${PROJECT}" && idf.py fullclean && idf.py build); then
        BUILT="${BUILT} ${NAME}"
    else
        FAILED="${FAILED} ${NAME}"
    fi
done

if [ -z "${BUILT}" ] && [ -z "${FAILED}" ]; then
    echo "ERROR: no example projects found in ${SCRIPT_DIR}/examples/"
    exit 1
fi

echo
echo "Built: ${BUILT:- none}"

if [ -n "${FAILED}" ]; then
    echo "Failed:${FAILED}"
    exit 1
fi

echo "All wolfSSH Espressif examples built."
