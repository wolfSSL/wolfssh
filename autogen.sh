#!/bin/sh
#
# Create configure and makefile stuff...

# Check environment
if [ -n "$WSL_DISTRO_NAME" ]; then
    # we found a non-blank WSL environment distro name
    current_path="$(pwd)"
    pattern="/mnt/?"
    if [ "$(echo "$current_path" | grep -E "^$pattern")" ]; then
        # if we are in WSL and shared Windows file system, 'ln' does not work.
        no_links=true
    else
        no_links=
    fi
fi

# Git hooks should come before autoreconf.
if [ -d .git ]; then
    if [ ! -d .git/hooks ]; then
        mkdir .git/hooks || exit $?
    fi

    if [ -n "$no_links" ]; then
        echo "Linux ln does not work on shared Windows file system in WSL."
        if [ ! -e .git/hooks/pre-commit ]; then
            echo "The pre-commit.sh file will not be copied to .git/hooks/pre-commit"
            # shell scripts do not work on Windows; TODO create equivalent batch file
            # cp ./pre-commit.sh .git/hooks/pre-commit || exit $?
        fi
        # unlike wolfssl, wolfssh is not using pre-push.sh at this time. Enable as needed:
        # if [ ! -e .git/hooks/pre-push ]; then
        #     echo "The pre-push.sh file will not be copied to .git/hooks/pre-commit"
        #     # shell scripts do not work on Windows; TODO create equivalent batch file
        #     # cp ./pre-push.sh .git/hooks/pre-push || exit $?
        # fi
    else
        if [ ! -e .git/hooks/pre-commit ]; then
            ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit || exit $?
        fi
        # unlike wolfssl, wolfssh is not using pre-push.sh at this time  Enable as needed:
        # if [ ! -e .git/hooks/pre-push ]; then
        #     ln -s ../../pre-push.sh .git/hooks/pre-push || exit $?
        # fi
    fi
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
