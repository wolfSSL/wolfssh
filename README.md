WOLFSSH
=======

wolfSSL's Embeddable SSH Server
[wolfSSH Manual](https://www.wolfssl.com/docs/wolfssh-manual/)

dependencies
------------

[wolfSSH](https://www.wolfssl.com/wolfssh/) is dependent on
[wolfCrypt](https://www.wolfssl.com/download/), found as a part of
wolfSSL. The following is the simplest configuration of wolfSSL to
enable wolfSSH.

    $ cd wolfssl
    $ ./configure [OPTIONS] --enable-ssh
    $ make check
    $ sudo make install

On some systems the optional ldconfig command is needed after installing.

To use the key generation function in wolfSSH, wolfSSL will need to be
configured with keygen: `--enable-keygen`.

If the bulk of wolfSSL code isn't desired, wolfSSL can be configured with
the crypto only option: `--enable-cryptonly`.

Additional build options for wolfSSL are located in
[chapter two](https://www.wolfssl.com/docs/wolfssl-manual/ch2/).
of the wolfSSH manual.

building
--------

From the wolfSSH source directory run:

    $ ./autogen.sh
    $ ./configure --with-wolfssl=[/usr/local]
    $ make
    $ make check

The `autogen.sh` script only has to be run the first time after cloning
the repository. If you have already run it or are using code from a
source archive, you should skip it.

For building under Windows with Visual Studio, see the file
"ide/winvs/README.md".

NOTE: On resource constrained devices the `DEFAULT_WINDOW_SZ` may need
to be set to a lower size. It can also be increased in desktop use cases
to help with large file transfers. By default channels are set to handle
16,384 bytes of data being sent and received. An example of setting a
window size for new channels would be as follows
`./configure CPPFLAGS=-DDEFAULT_WINDOW_SZ=16384`

examples
--------

The directory `examples` contains an echoserver that any client should
be able to connect to. From the terminal run:

    $ ./examples/echoserver/echoserver -f

The option `-f` enables echo-only mode. From another terminal run:

    $ ssh jill@localhost -p 22222

When prompted for a password, enter "upthehill". The server will send a
canned banner to the client:

    wolfSSH Example Echo Server

Characters typed into the client will be echoed to the screen by the
server. If the characters are echoed twice, the client has local echo
enabled. The echoserver isn't being a proper terminal so the CR/LF
translation will not work as expected.

The following control characters will trigger special actions in the
echoserver:

- CTRL-C: Terminate the connection.
- CTRL-E: Print out some session statistics.
- CTRL-F: Trigger a new key exchange.


testing notes
-------------

After cloning the repository, be sure to make the testing private keys
read-only for the user, otherwise `ssh` will tell you to do it.

    $ chmod 0600 ./keys/gretel-key-rsa.pem ./keys/hansel-key-rsa.pem \
                 ./keys/gretel-key-ecc.pem ./keys/hansel-key-ecc.pem

Authentication against the example echoserver can be done with a
password or public key. To use a password the command line:

    $ ssh -p 22222 USER@localhost

Where the *USER* and password pairs are:

    jill:upthehill
    jack:fetchapail

To use public key authentication use the command line:

    $ ssh -i ./keys/USER-key-TYPE.pem -p 22222 USER@localhost

Where the *USER* can be `gretel` or `hansel`, and *TYPE* is `rsa` or
`ecc`.

Keep in mind, the echoserver has several fake accounts in its
`wsUserAuth()` callback function. (jack, jill, hansel, and gretel) When
the shell support is enabled, those fake accounts will not work. They
don't exist in the system's _passwd_ file. The users will authenticate,
but the server will err out because they don't exist in the system. You
can add your own username to the password or public key list in the
echoserver. That account will be logged into a shell started by the
echoserver with the privileges of the user running echoserver.


EXAMPLE TOOLS
=============

wolfSSH comes packaged with a few example tools for testing purposes
and to demonstrate interoperability with other SSH implementations.


echoserver
----------

The echoserver is the workhorse of wolfSSH. It originally only allowed one
to authenticate one of the canned account and would repeat the characters
typed into it. When enabling [shell support](#shell-support), it can
spawn a user shell. It will need an actual user name on the machine and an
updated user authentication callback function to validate the credentials.
The echoserver can also handle SCP and SFTP connections.

The echoserver tool accepts the following command line options:

    -1             exit after a single (one) connection
    -e             expect ECC public key from client
    -E             use ECC private key
    -f             echo input
    -p <num>       port to accept on, default 22222
    -N             use non-blocking sockets
    -d <string>    set the home directory for SFTP connections
    -j <file>      load in a public key to accept from peer


client
------

The client establishes a connection to an SSH server. In its simplest mode,
it sends the string "Hello, wolfSSH!" to the server, prints the response,
and then exits. With the pseudo terminal option, the client will be a real
client.

The client tool accepts the following command line options:

    -h <host>      host to connect to, default 127.0.0.1
    -p <num>       port to connect on, default 22222
    -u <username>  username to authenticate as (REQUIRED)
    -P <password>  password for username, prompted if omitted
    -e             use sample ecc key for user
    -i <filename>  filename for the user's private key
    -j <filename>  filename for the user's public key
    -x             exit after successful connection without doing
                   read/write
    -N             use non-blocking sockets
    -t             use psuedo terminal
    -c <command>   executes remote command and pipe stdin/stdout
    -a             Attempt to use SSH-AGENT


portfwd
-------

The portfwd tool establishes a connection to an SSH server and sets up a
listener for local port forwarding or requests a listener for remote port
forwarding. After a connection, the tool terminates.

The portfwd tool accepts the following command line options:

    -h <host>      host to connect to, default 127.0.0.1
    -p <num>       port to connect on, default 22222
    -u <username>  username to authenticate as (REQUIRED)
    -P <password>  password for username, prompted if omitted
    -F <host>      host to forward from, default 0.0.0.0
    -f <num>       host port to forward from (REQUIRED)
    -T <host>      host to forward to, default to host
    -t <num>       port to forward to (REQUIRED)


scpclient
---------

The scpclient, wolfscp, establishes a connection to an SSH server and copies
the specified files from or to the local machine.

The scpclient tool accepts the following command line options:

    -H <host>      host to connect to, default 127.0.0.1
    -p <num>       port to connect on, default 22222
    -u <username>  username to authenticate as (REQUIRED)
    -P <password>  password for username, prompted if omitted
    -L <from>:<to> copy from local to server
    -S <from>:<to> copy from server to local


sftpclient
----------

The sftpclient, wolfsftp, establishes a connection to an SSH server and
allows directory navigation, getting and putting files, making and removing
directories, etc.

The sftpclient tool accepts the following command line options:

    -h <host>      host to connect to, default 127.0.0.1
    -p <num>       port to connect on, default 22222
    -u <username>  username to authenticate as (REQUIRED)
    -P <password>  password for username, prompted if omitted
    -d <path>      set the default local path
    -N             use non blocking sockets
    -e             use ECC user authentication
    -l <filename>  local filename
    -r <filename>  remote filename
    -g             put local filename as remote filename
    -G             get remote filename as local filename


server
------

This tool is a place holder.


SCP
===

wolfSSH includes server-side support for scp, which includes support for both
copying files 'to' the server, and copying files 'from' the server. Both
single file and recursive directory copy are supported with the default
send and receive callbacks.

To compile wolfSSH with scp support, use the `--enable-scp` build option
or define `WOLFSSL_SCP`:

    $ ./configure --enable-scp
    $ make

For full API usage and implementation details, please see the wolfSSH User
Manual.

The wolfSSL example server has been set up to accept a single scp request,
and is compiled by default when compiling the wolfSSH library. To start the
example server, run:

    $ ./examples/server/server

Standard scp commands can be used on the client side. The following are a
few examples, where `scp` represents the ssh client you are using.

To copy a single file TO the server, using the default example user "jill":

    $ scp -P 22222 <local_file> jill@127.0.0.1:<remote_path>

To copy the same single file TO the server, but with timestamp and in
verbose mode:

    $ scp -v -p -P 22222 <local_file> jill@127.0.0.1:<remote_path>

To recursively copy a directory TO the server:

    $ scp -P 22222 -r <local_dir> jill@127.0.0.1:<remote_dir>

To copy a single file FROM the server to the local client:

    $ scp -P 22222 jill@127.0.0.1:<remote_file> <local_path>

To recursively copy a directory FROM the server to the local client:

    $ scp -P 22222 -r jill@127.0.0.1:<remote_dir> <local_path>


PORT FORWARDING
===============

wolfSSH provides support for port forwarding. This allows the user
to set up an encrypted tunnel to another server, where the SSH client listens
on a socket and forwards connections on that socket to another socket on
the server.

To compile wolfSSH with port forwarding support, use the `--enable-fwd` build
option or define `WOLFSSH_FWD`:

    $ ./configure --enable-fwd
    $ make

For full API usage and implementation details, please see the wolfSSH User
Manual.

The portfwd example tool will create a "direct-tcpip" style channel. These
directions assume you have OpenSSH's server running in the background with
port forwarding enabled. This example forwards the port for the wolfSSL
client to the server as the application. It assumes that all programs are run
on the same machine in different terminals.

    src/wolfssl$ ./examples/server/server
    src/wolfssh$ ./examples/portfwd/portfwd -p 22 -u <username> \
                 -f 12345 -t 11111
    src/wolfssl$ ./examples/client/client -p 12345

By default, the wolfSSL server listens on port 11111. The client is set to
try to connect to port 12345. The portfwd logs in as user "username", opens
a listener on port 12345 and connects to the server on port 11111. Packets
are routed back and forth between the client and server. "Hello, wolfSSL!"

The source for portfwd provides an example on how to set up and use the
port forwarding support in wolfSSH.

The echoserver will handle local and remote port forwarding. To connect with
the ssh tool, using one of the following command lines. You can run either of
the ssh command lines from anywhere:

    src/wolfssl$ ./examples/server/server
    src/wolfssh$ ./examples/echoserver/echoserver
    anywhere 1$ ssh -p 22222 -L 12345:localhost:11111 jill@localhost
    anywhere 2$ ssh -p 22222 -R 12345:localhost:11111 jill@localhost
    src/wolfssl$ ./examples/client/client -p 12345

This will allow port forwarding between the wolfSSL client and server like in
the previous example.


SFTP
====

wolfSSH provides server and client side support for SFTP version 3. This
allows the user to set up an encrypted connection for managing file systems.

To compile wolfSSH with SFTP support, use the `--enable-sftp` build option or
define `WOLFSSH_SFTP`:

    $ ./configure --enable-sftp
    $ make

For full API usage and implementation details, please see the wolfSSH User
Manual.

The SFTP client created is located in the directory examples/sftpclient/ and the
server is ran using the same echoserver as with wolfSSH.

    src/wolfssh$ ./examples/sftpclient/wolfsftp

A full list of supported commands can be seen with typeing "help" after a
connection.


    wolfSSH sftp> help

    Commands :
        cd  <string>                      change directory
        chmod <mode> <path>               change mode
        get <remote file> <local file>    pulls file(s) from server
        ls                                list current directory
        mkdir <dir name>                  creates new directory on server
        put <local file> <remote file>    push file(s) to server
        pwd                               list current path
        quit                              exit
        rename <old> <new>                renames remote file
        reget <remote file> <local file>  resume pulling file
        reput <remote file> <local file>  resume pushing file
        <crtl + c>                        interrupt get/put cmd

An example of connecting to another system would be

    src/wolfssh$ ./examples/sftpclient/wolfsftp -p 22 -u user -h 192.168.1.111


SHELL SUPPORT
=============

wolfSSH's example echoserver can now fork a shell for the user trying to log
in. This currently has only been tested on Linux and macOS. The file
echoserver.c must be modified to have the user's credentials in the user
authentication callback, or the user authentication callback needs to be
changed to verify the provided password.

To compile wolfSSH with shell support, use the `--enable-shell` build option
or define `WOLFSSH_SHELL`:

    $ ./configure --enable-shell
    $ make

By default, the echoserver will try to start a shell. To use the echo testing
behavior, give the echoserver the command line option `-f`.

    $ ./examples/echoserver/echoserver -f

POST-QUANTUM
============

wolfSSH now supports the post-quantum algorithm Kyber. It uses the NIST
submission's Level 1 parameter set implemented by liboqs via an integration
with wolfSSH. It is hybridized with ECDHE over the P-256 ECC curve.

In order be able to use liboqs, you must have it built and installed on your
system. We support the 0.7.0 release of liboqs. You can download it from the
following link:

    https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.7.0.tar.gz

Once unpacked, this would be sufficient:

    $ cd liboqs-0.7.0
    $ mkdir build
    $ cd build
    $ cmake -DOQS_USE_OPENSSL=0 ..
    $ make all
    $ sudo make install


In order to enable support for Kyber Level1 hybridized with ECDHE over the P-256
ECC curve in wolfSSH, use the `--with-liboqs` build option during configuration:

    $ ./configure --with-liboqs

The wolfSSH client and server will automatically negotiate using Kyber Level1
hybridized with ECDHE over the P-256 ECC curve if this feature is enabled.

    $ ./examples/echoserver/echoserver -f

    $ ./examples/client/client -u jill -P upthehill

On the client side, you will see the following output:

Server said: Hello, wolfSSH!

If you want to see inter-operability with OpenQauntumSafe's fork of OpenSSH, you
can build and execute the fork while the echoserver is running. Download the
release from here:

    https://github.com/open-quantum-safe/openssh/archive/refs/tags/OQS-OpenSSH-snapshot-2021-08.tar.gz

The following is sufficient for build and execution:

    $ tar xmvf openssh-OQS-OpenSSH-snapshot-2021-08.tar.gz
    $ cd openssh-OQS-OpenSSH-snapshot-2021-08/
    $ ./configure --with-liboqs-dir=/usr/local
    $ make all
    $ ./ssh -o"KexAlgorithms +ecdh-sha2-nistp256-kyber-512-sha256" \
      -o"PubkeyAcceptedAlgorithms +ssh-rsa" \
      -o"HostkeyAlgorithms +ssh-rsa" \
      jill@localhost -p 22222

NOTE: when prompted, enter the password which is "upthehill".

You can type a line of text and when you press enter, the line will be echoed
back. Use CTRL-C to terminate the connection.
