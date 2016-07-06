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

testing notes
-------------

Authentication against the example echoserver can be done with a password or
public key. To use a password the command line:

    $ ssh_client -p 22222 USER@localhost

Where the `USER` and password pairs are:

    jill:upthehill
    jack:fetchapail

To use public key authentication use the command line:

    $ ssh_client -l ./certs/key-USER.pem -p 22222 USER@localhost

Where the user can be `gretel` or `hansel`.


coding standard
---------------

1. Exceptions are allowed with good reason.

2. Follow the existing style.

3. Try not to shorthand variables, except for ijk as indicies.

4. Lengths of arrays should have the array name followed by Sz.

5. Single return per function.

6. Check all incoming parameters.

7. No gotos.

8. Check all return codes. It feels a little tedious, but the preferred method
is running checks against success. This way if a function returns an error, the
code will drop to the end.

```
    ret = functionCall(parameter);
    if (ret == SUCCESS)
        ret = secondFunctionCall(otherParameter);
    if (ret == SUCCESS)
        ret = thirdFunctionCall(aParameter, anotherParameter);
    cleanUp();
    return ret;
```


