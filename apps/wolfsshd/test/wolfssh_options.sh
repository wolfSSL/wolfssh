#!/bin/sh

# Build option probe for the wolfSSHd test scripts. Source it before any cd,
# since it resolves the tree from the script's own location:
#
#     . ./wolfssh_options.sh
#     if ! wolfssh_has SFTP; then
#         echo "built without SFTP, skipping"
#         exit 77
#     fi
#
# The tests run from this directory, so the one path to the build tree lives
# here. WOLFSSH_ROOT is absolute, so it survives their cd ../../.. . A probe
# that will not run is a build problem, not an option being off.

WOLFSSH_ROOT=$(cd "$(dirname "$0")/../../.." && pwd) || exit 1
WOLFSSH_OPTIONS=$("$WOLFSSH_ROOT/apps/wolfssh-options") || {
    echo "fail: could not run $WOLFSSH_ROOT/apps/wolfssh-options"
    exit 1
}

# Whole line match, so one option name cannot match another that has it as a
# prefix.
wolfssh_has() {
    echo "$WOLFSSH_OPTIONS" | grep -qx "$1"
}
