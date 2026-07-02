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

When using X.509 certificates for user authentication, wolfSSL must be
built with TLS enabled. wolfSSH uses wolfSSL's certificate manager system
for X.509, including OCSP lookups. To allow OCSP, add `--enable-ocsp` to the
wolfSSL configure.

If the bulk of wolfSSL code isn't desired, wolfSSL can be configured with
the crypto only option: `--enable-cryptonly`.

Additional build options for wolfSSL are located in
[chapter two](https://www.wolfssl.com/docs/wolfssl-manual/ch2/).
of the wolfSSH manual.


building
--------

From the wolfSSH source directory run:

    $ ./autogen.sh (if cloned from GitHub)
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
to help with large file transfers. By default channels are set to receive
up to 128kB of data before sending a channel window adjust message. An
example of setting a window size for new channels would be as follows
`./configure CPPFLAGS="-DDEFAULT_WINDOW_SZ=16384"`

For 32bit Linux platforms you can add support for files > 2GB by compiling
with `CFLAGS=-D_FILE_OFFSET_BITS=64`.

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
    -t             use pseudo terminal
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


SCP
===

wolfSSH includes server-side support for scp, which includes support for both
copying files 'to' the server, and copying files 'from' the server. Both
single file and recursive directory copy are supported with the default
send and receive callbacks.

To compile wolfSSH with scp support, use the `--enable-scp` build option
or define `WOLFSSH_SCP`:

    $ ./configure --enable-scp
    $ make

For full API usage and implementation details, please see the wolfSSH User
Manual.

The wolfSSH example server has been set up to accept a single scp request,
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

The SFTP client created is located in the directory examples/sftpclient/ and
the example echoserver acts as a SFTP server.

    src/wolfssh$ ./examples/sftpclient/wolfsftp

A full list of supported commands can be seen with typing "help" after a
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

To try out this functionality, you can use the example echoserver and client.
In a terminal do the following to launch the server:

    $ ./examples/echoserver/echoserver -P <user>:junk

And in another terminal do the following to launch the example client:

    $ ./examples/client/client -t -u <user> -P junk

Note that `<user>` must be the user name of the current user that is logged in.

By default, the echoserver will try to start a shell. To use the echo testing
behavior, give the echoserver the command line option `-f`.

    $ ./examples/echoserver/echoserver -f

To use the shell feature with wolfsshd add `--enable-sshd` to your configure
command and use the following command:

    $ sudo ./apps/wolfsshd/wolfsshd -D -h keys/gretel-key-ecc.pem -p 11111

If it complains about a bad `sshd_config` file, simply copy it to another file
and remove the offending line that it complains about and use the `-f` command
line parameter to point to the new file.

You can then connect to the `wolfsshd` server with ssh:

    $ ssh <user>@localhost -p 11111

Note that `<user>` must be the user name of the current user that is logged in.

CURVE25519
==========

wolfSSH now supports Curve25519 for key exchange. To enable this support simply
compile wolfSSL with support for wolfssh and Curve25519.

    $ cd wolfssl
    $ ./configure --enable-wolfssh --enable-curve25519

After building and installing wolfSSL, you can simply configure with no options.

    $ cd wolfssh
    $ ./configure

The wolfSSH client and server will automatically negotiate using Curve25519.

    $ ./examples/echoserver/echoserver -f

    $ ./examples/client/client -u jill -P upthehill

POST-QUANTUM
============

wolfSSH supports both post-quantum key exchange via ML-KEM (formerly known as
Kyber) and post-quantum signature verification via ML-DSA (formerly known as
Dilithium).

* **ML-KEM**: Uses the ML-KEM-768 parameter set hybridized with ECDHE over the
  P-256 ECC curve.
* **ML-DSA**: Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets for
  both server host keys and client public key authentication. When built with
  certificate support, ML-DSA X.509 certificates (`x509v3-ssh-mldsa-44`,
  `x509v3-ssh-mldsa-65`, and `x509v3-ssh-mldsa-87`) are also supported.

In order to use these algorithms you must build and install wolfSSL with
support for them. Here is an example of an effective configuration:

    $ ./configure --enable-wolfssh --enable-mlkem --enable-mldsa

After that, configure and build wolfSSH as usual:

    $ ./configure
    $ make all

The wolfSSH client and server will automatically negotiate using ML-KEM-768
hybridized with ECDHE over the P-256 ECC curve and ML-DSA for host keys/client
public key authentication.

    $ ./examples/echoserver/echoserver -f

    $ ./examples/client/client -u jill -P upthehill

On the client side, you will see the following output:

Server said: Hello, wolfSSH!

If you want to see interoperability with OpenQuantumSafe's fork of OpenSSH, you
can build and execute the fork while the echoserver is running. Download the
release from here:

    https://github.com/open-quantum-safe/openssh/archive/refs/tags/OQS-OpenSSH-snapshot-2021-08.tar.gz

The following is sufficient for build and execution:

    $ tar xmvf openssh-OQS-OpenSSH-snapshot-2021-08.tar.gz
    $ cd openssh-OQS-OpenSSH-snapshot-2021-08/
    $ ./configure --with-liboqs-dir=/usr/local
    $ make all
    $ ./ssh -o"KexAlgorithms=mlkem768nistp256-sha256" \
      -o"PubkeyAcceptedAlgorithms +ssh-rsa" \
      -o"HostkeyAlgorithms +ssh-rsa" \
      jill@localhost -p 22222

NOTE: when prompted, enter the password which is "upthehill".

You can type a line of text and when you press enter, the line will be echoed
back. Use CTRL-C to terminate the connection.


CERTIFICATE SUPPORT
===================

wolfSSH can accept X.509 certificates in place of just public keys when
authenticating a user.

To compile wolfSSH with X.509 support, use the `--enable-certs` build option
or define `WOLFSSH_CERTS`:

    $ ./configure --enable-certs CPPFLAGS=-DWOLFSSH_NO_FPKI
    $ make

For this example, we are disabling the FPKI checking as the included
certificate for "fred" does not have the required FPKI extensions. If the
flag WOLFSSH_NO_FPKI is removed, you can see the certificate get rejected.

To provide a CA root certificate to validate a user's certificate, give the
echoserver the command line option `-a`.

    $ ./examples/echoserver/echoserver -a ./keys/ca-cert-ecc.pem

The echoserver and client have a fake user named "fred" whose certificate
will be used for authentication.

An example echoserver / client connection using the example certificate
fred-cert.der would be:

    $ ./examples/echoserver/echoserver -a ./keys/ca-cert-ecc.pem -K fred:./keys/fred-cert.der

    $ ./examples/client/client -u fred -J ./keys/fred-cert.der -i ./keys/fred-key.der

TPM PUBLIC KEY AUTHENTICATION
=============================

When using TPM for client side public key authentication wolfSSH has dependencies
on wolfCrypt and wolfTPM. Youll also need to have a tpm simulator
[wolfTPM](https://www.wolfssl.com/products/wolftpm/)
[wolfSSL](https://www.wolfssl.com/products/wolfssl/)
You'll need to build and configure wolfTPM, wolfSSL, and wolfSSH like so:

    $ cd <wolfSSL, wolfTPM, wolfSSH>
    $ ./autogen.sh (if cloned from GitHub)
    $ <Configuration>
    $ make
    $ make check

    <Configuration>
    wolfSSL
        $ ./configure --enable-wolftpm --enable-wolfssh
    wolfTPM
        $ ./configure --enable-swtpm
    wolfSSH
        $ ./configure --enable-tpm

For testing TPM with private rsa key you'll need to run the server from a TPM
simulator like `ibmswtpm2`. This can be done as followed:

    $ cd src
    $ ./tpm_server

Before starting the echoserver you need to run the keygen for keyblob
using the endorsment key in wolfTPM with the following commands:
Default password to `ThisIsMyKeyAuth`:

    $ ./examples/keygen/keygen keyblob.bin -rsa -t -pem -eh

Custom password:

    $ ./examples/keygen/keygen keyblob.bin -rsa -t -pem -eh -auth=<custompassword>

This will produce a key.pem TPM public key which needs to be converted the to
the ssh-rsa BASE64 username format using this command:

    $ ssh-keygen -f key.pem -i -m PKCS8 > ../wolfssh/key.ssh

The directory `examples` contains an echoserver that any client should
be able to connect to. From wolfSSH open two terminal instances and run the
server with the key.ssh file you created in the previous step:

    $ ./examples/echoserver/echoserver -s key.ssh

From another terminal run the client with the keyblob. Using primary endorsement key
If you used the default password for keygen you must specify the password:

    $ ./examples/client/client -i ../wolfTPM/keyblob.bin -u hansel -K ThisIsMyKeyAuth

If you used a custom password for keygen you must specify the password you used:

    $ ./examples/client/client -i ../wolfTPM/keyblob.bin -u hansel -K <custompassword>

TPM SERVER HOST KEY (ECDSA / RSA)
=================================

The server can also keep its own host key inside the TPM so the host private
key is never present in RAM. Build wolfSSL, wolfTPM, and wolfSSH the same way
as above (`--enable-tpm`). Both ECDSA and RSA host keys are supported.

Generate a host key blob under the endorsement hierarchy (ECC or RSA):

    $ ./examples/keygen/keygen hostkey.bin -ecc -t -eh
    $ ./examples/keygen/keygen hostkey.bin -rsa -t -eh

Start the echoserver with the TPM-resident host key using `-G`:

    $ ./examples/echoserver/echoserver -G ../wolfTPM/hostkey.bin

The server loads the key blob into the TPM, registers it with
`wolfSSH_CTX_UseTpmHostKey()`, and advertises the matching host key algorithm
(`ecdsa-sha2-nistp256` or `rsa-sha2-256`). The exchange hash is signed by the
TPM; the host private key never leaves it. Any client that accepts the host
key can connect:

    $ ssh -o HostKeyAlgorithms=ecdsa-sha2-nistp256 user@host
    $ ssh -o HostKeyAlgorithms=rsa-sha2-256 user@host

To integrate this into your own server, provision the key once into the TPM,
load its handle at boot into a `WOLFTPM2_KEY`, and register it:

    wolfSSH_CTX_UseTpmHostKey(ctx, &tpmDev, &tpmKey);

Note: RSA host keys are signed with `rsa-sha2-256`. The default echoserver key
auth produced by keygen is `ThisIsMyKeyAuth` (override with the `-G` example's
`ECHOSERVER_TPM_KEY_AUTH`).

TPM SERVER HOST KEY WITH X.509 CERTIFICATE (ECDSA / RSA)
=======================================================

The server can present an X.509 certificate as its host key while the matching
private key stays non-exportable inside the TPM. The client verifies the
certificate against a trusted CA, so the server's identity is authenticated and
a man-in-the-middle cannot impersonate it. The exchange hash is signed inside
the TPM; the private key never enters RAM.

This requires wolfSSH built with certificate support in addition to TPM support,
and wolfSSL/wolfTPM built with certificate generation:

    wolfSSL
        $ ./configure --enable-wolfssh --enable-wolftpm --enable-keygen \
              --enable-certgen --enable-certreq --enable-certext \
              --enable-cryptocb \
              CFLAGS="-DWC_RSA_NO_PADDING"
    wolfTPM
        $ ./configure --enable-fwtpm --enable-swtpm
    wolfSSH
        $ ./configure --enable-tpm --enable-certs

The example under `examples/tpmcertserver` creates a signing key inside the TPM,
generates a self-signed X.509 certificate from it with
`wolfTPM2_CSR_Generate_ex()`, then serves with `wolfSSH_CTX_UseTpmHostKey()` and
`wolfSSH_CTX_UseCert_buffer()`. Run a TPM simulator first (`fwtpm_server` or
`ibmswtpm2`), then:

    ECDSA:  $ ./examples/tpmcertserver/tpmcertserver -k ecc
    RSA:    $ ./examples/tpmcertserver/tpmcertserver -k rsa

The server writes its certificate to `tpm-server-cert.der`. The companion
client verifies the server against that certificate used as the trusted root:

    $ ./examples/tpmcertserver/tpmcertclient -A tpm-server-cert.der

To integrate this into your own server, load the certificate and bind the TPM
key. Call `wolfSSH_CTX_UseTpmHostKey()` before `wolfSSH_CTX_UseCert_buffer()` so
the certificate is linked to the TPM key slot:

    wolfSSH_CTX_UseTpmHostKey(ctx, &tpmDev, &tpmKey);
    wolfSSH_CTX_UseCert_buffer(ctx, certDer, certDerSz, WOLFSSH_FORMAT_ASN1);

On the client, restrict the accepted host key algorithms to the certificate
algorithms so the connection cannot silently fall back to a plain host key and
skip certificate (CA) verification:

    wolfSSH_CTX_SetAlgoListKey(ctx,
        "x509v3-ecdsa-sha2-nistp256,x509v3-ssh-rsa");
    wolfSSH_CTX_AddRootCert_buffer(ctx, caDer, caDerSz, WOLFSSH_FORMAT_ASN1);

Notes:

- ECDSA is recommended. It uses SHA-256 and needs no extra build options.
- RSA certificate host keys use the `x509v3-ssh-rsa` algorithm, which is defined
  with SHA-1. Modern wolfSSL rejects SHA-1 RSA signatures by default, so RSA
  additionally requires wolfSSL built with
  `-DWC_SIG_MIN_HASH_TYPE=WC_HASH_TYPE_SHA`. This re-enables a deprecated hash;
  prefer ECDSA unless RSA is mandated.

WOLFSSH APPLICATIONS
====================

wolfSSH comes with a server daemon and a command line shell tool. Check out
the apps directory for more information.
