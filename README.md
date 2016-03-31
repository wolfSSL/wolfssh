wolfssh
=======

wolfSSL's Embeddable SSH Server

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

examples
--------

The directory `examples` contains an echoserver that any client should be able
to connect to. From the terminal run:

    $ ./examples/echoserver/echoserver

From another terminal run:

    $ ssh_client localhost -p 22222

The server will send a canned banner to the client:

    CANNED BANNER
    This server is an example test server. It should have its own banner, but
    it is currently using a canned one in the library. Be happy or not.

Characters typed into the client will be echoed to the screen by the server.
If the characters are echoed twice, the client has local echo enabled.
