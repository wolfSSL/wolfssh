#!/bin/bash

USER=`whoami`

cat ../../../keys/hansel-*.pub > authorized_keys_test
sed -i.bak "s/hansel/$USER/" ./authorized_keys_test

# The redirection above leaves the file at the process umask, which is 0664
# under the 002 default of a distro that puts each user in their own group.
# wolfSSHd's StrictModes check refuses a group or world writable
# authorized_keys file, so every public-key test would fail. 0644 is the mode
# run_all_sshd_tests.sh already sets as the positive control of its StrictModes
# test.
chmod 0644 authorized_keys_test

exit 0
