#!/bin/sh
#
# Create configure and makefile stuff...

# Git hooks should come before autoreconf.
if test -d .git
then
  mkdir -p .git/hooks && ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
fi

# If this is a source checkout then call autoreconf with error as well
if test -e .git
then
  WARNINGS="all,error"
else
  WARNINGS="all"
fi
export WARNINGS

autoreconf -ivf
