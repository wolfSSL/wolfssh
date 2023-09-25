WOLFSSH CLIENT
==============

The wolfSSH client will connect to a server and try to open a terminal. It'll
default the username to your current username, and it will try to use your
ecdsa private key to authenticate. The key file path is hard coded to
`$HOME/.ssh/id_ecdsa`. It is currently far enough along I can use it. The
private keys are the ones produced by the OpenSSL command line tool, not the
ssh-keygen tool.

Phase 2 is going to bring reading the config files `/etc/ssh/ssh_config` and
`$HOME/.ssh/config`. It will handle OpenSSH style modern keys. It will also
have support for SSH-AGENT and forwarding.

Command Line Options
--------------------

    -E logfile    : Specify a different log file.
    -G            : Print out the configuration as used.
    -l login_name : Overrides the login name specified in the destination.
    -N            : Do not execute remote command.
    -p port       : Overrides the destination port number.
    -V            : Print out the version.

The destination option is the only required option. It can be in the two
following formats:

    [user@]hostname
    ssh://[user@]hostname[:port]

The default value for _user_ is the current user's login name. The default
value for _port_ is 22.
