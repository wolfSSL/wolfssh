VisualStudio solution for wolfSSH
=================================

The solution file, wolfssh.sln, facilitates bulding wolfSSH and its
example and test programs. The solution provides both Debug and Release
builds of Static and Dynamic 32- or 64-bit libraries.
the wolfSSL library with your wolfCrypt configuration. The file
`wolfcrypt/user_settings.h` should be used in the wolfSSL build to
configure it.

The wolfcrypt directory is provided as a convenience for the test and
sample tools to find the wolfSSL library and headers.

The wolfSSL library should just be copied into this directory with the
name `wolfssl.lib`. The headers that come with the library are in the
directory `wolfssl` and `wolfssl\wolfcrypt`. That wolfssl directory
should be copied here. If available, copy the file `wolfssl.pdb` to
`wolfssl.pdb`. It might be called `vs110.pdb`, and may be in the `obj`
directory. If it isn't copied, the wolfSSH build will warn about not
finding it and assume wolfSSL isn't built with debugging information.
It isn't critical.

Depending on the build, you may need to copy over other versions
of the wolfSSL library files. If you make a 64-bit build of wolfSSL,
you can only make a 64-bit build of wolfSSH.

You can build wolfSSL as either a Debug or Release build. It does not
need to match your build on wolfSSH. You cannot use the DLL build of
wolfSSL with these projects. wolfSSL is linked statically to wolfSSH.

The following is a subset of files and the directories they live in,
as an example.

    src\ssh.c
    src\internal.c
    wolfcrypt\readme.txt (this file)
    wolfcrypt\wolfssl.lib
    wolfcrypt\wolfssl.pdb
    wolfcrypt\wolfssl\ssl.h
    wolfcrypt\wolfssl\options.h
    wolfcrypt\wolfssl\wolfcrypt\aes.h
    wolfcrypt\wolfssl\wolfcrypt\user_settings.h
