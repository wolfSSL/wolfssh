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
