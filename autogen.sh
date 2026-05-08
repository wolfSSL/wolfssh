#!/bin/sh
#
# Create configure and makefile stuff...

# If this is a source checkout then call autoreconf with error as well
if [ -e .git ]; then
  WARNINGS="all,error"
else
  WARNINGS="all"
fi
export WARNINGS

autoreconf -ivf
