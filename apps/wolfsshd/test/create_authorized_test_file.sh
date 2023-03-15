#!/bin/bash

USER=`whoami`

cat ../../../keys/hansel-*.pub > authorized_keys_test
sed -i.bak "s/hansel/$USER/" ./authorized_keys_test

exit 0
