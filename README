wolfssh
=======

wolfSSL's Embeddable SSH Server

dependencies
------------

wolfSSH is dependent on wolfCrypt. The simplest configuration of wolfSSL
required for wolfSSH is the default build.

    $ cd wolfssl
    $ ./configure [OPTIONS] --enable-ssh
    $ make check
    $ sudo make install

To use the key generation function in wolfSSH, wolfSSL will need to be
configured with keygen: `--enable-keygen`.

If the bulk of wolfSSL code isn't desired, wolfSSL can be configured with
the crypto only option: `--enable-cryptonly`.


building
--------

From the source directory run:

    $ ./autogen.sh
    $ ./configure
    $ make
    $ make check

The `autogen.sh` script only has to be run the first time after cloning the
repository. If you have already run it or are using code from a source
archive, you should skip it.

For building under Windows with Visual Studio, see the file
"ide/winvs/README.md".

NOTE: On resource constrained devices the DEFAULT_WINDOW_SZ may need to be set
to a lower size. By default channels are set to handle 1 Mb of data being sent
and received. An example of setting a lower window size for new channels would
be as follows "./configure CPPFLAGS=-DDEFAULT_WINDOW_SZ=16384"

examples
--------

The directory `examples` contains an echoserver that any client should be able
to connect to. From the terminal run:

    $ ./examples/echoserver/echoserver

From another terminal run:

    $ ssh_client localhost -p 22222

The server will send a canned banner to the client:

    wolfSSH Example Echo Server

Characters typed into the client will be echoed to the screen by the server.
If the characters are echoed twice, the client has local echo enabled. The
echo server isn't being a proper terminal so the CR/LF translation will not
work as expected.


testing notes
-------------

After cloning the repository, be sure to make the testing private keys read-
only for the user, otherwise ssh_client will tell you to do it.

    $ chmod 0600 ./keys/gretel-key-rsa.pem ./keys/hansel-key-rsa.pem \
                 ./keys/gretel-key-ecc.pem ./keys/hansel-key-ecc.pem

Authentication against the example echoserver can be done with a password or
public key. To use a password the command line:

    $ ssh_client -p 22222 USER@localhost

Where the `USER` and password pairs are:

    jill:upthehill
    jack:fetchapail

To use public key authentication use the command line:

    $ ssh_client -i ./keys/key-USER.pem -p 22222 USER@localhost

Where the user can be `gretel` or `hansel`.


scp support
-----------

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


port forwarding support
-----------------------

wolfSSH provides client side support for port forwarding. This allows the user
to set up an encrypted tunnel to another server, where the SSH client listens
on a socket and forwards connections on that socket to another socket on
the server.

To compile wolfSSH with port forwarding support, use the `--enable-fwd` build
option or define `WOLFSSH_FWD`:

    $ ./configure --enable-fwd
    $ make

For full API usage and implementation details, please see the wolfSSH User
Manual.

The wolffwd example tool will create a "direct-tcpip" style channel. These
directions assume you have OpenSSH's server running in the background with
port forwarding enabled. This example forwards the port for the wolfSSL
client to the server as the application. It assumes that all programs are run
on the same machine in different terminals.

    src/wolfssl$ ./examples/server/server
    src/wolfssh$ ./examples/wolffwd/wolffwd -p 22 -u <username> \
                 -f 12345 -t 11111
    src/wolfssl$ ./examples/client/client -p 12345

By default, the wolfSSL server listens on port 11111. The client is set to
try to connect to port 12345. The wolffwd logs in as user "username", opens
a listener on port 12345 and connects to the server on port 11111. Packets
are routed back and forth between the client and server. "Hello, wolfSSL!"

The source for wolffwd provides an example on how to set up and use the
port forwarding support in wolfSSH.
