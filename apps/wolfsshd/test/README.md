# wolfSSHd Tests

These are seprate from the tests in scripts directory because of the need for
'sudo' when starting up an SSHd server to test against.

## Running Tests

To run all tests do:

```
$ cd apps/wolfsshd/test/

$ sudo ./run_all_sshd_tests.sh <user>
Running all wolfSSHd tests
Starting up local wolfSSHd for tests on 127.0.0.1:22222
SSHD running on PID 7979
sshd_exec_test.sh ... PASSED
Shutting down test wolfSSHd
Stopping SSHD, killing pid 7979
All tests ran, 1 passed, 0 skipped

```

To run a specific test do:

startup wolfSSHd
```
$ cd ./apps/wolfsshd

$ sudo ./wolfsshd -D -d -f ./test/sshd_config_test
[PID 8049]: [SSHD] parsing config file ./test/sshd_config_test
[PID 8049]: [SSHD] Setting login grace time to 600
[PID 8049]: [SSHD] Turning off privilege separation!
[PID 8049]: [SSHD] Starting wolfSSH SSHD application
[PID 8049]: Entering wolfSSH_CTX_new()
[PID 8049]: Entering CtxInit()
[PID 8049]: Leaving wolfSSH_CTX_new(), ctx = 0x5574747f3520
[PID 8049]: Entering wolfSSH_CTX_SetBanner()
[PID 8049]:   setting banner to: "wolfSSHD
"
...
...
...
```

point the test to the host/port if needed
```
$ cd ./apps/wolfsshd/test

$ ./sshd_exec_test.sh 127.0.0.1 22222
```

## Adding Tests
New tests should be added to a new .sh file if not related to any of the 
existing tests. The test should then be called from run_all_sshd_tests.sh once
added, for example:

```
run_test "new_test.sh"
```

This would be added before the call to stop the SSHd server `stop_wolfsshd` and
after the test files have been setup:

```
 48 # setup
 49 set -e
 50 ./create_authorized_test_file.sh
 51 ./create_sshd_config.sh
 52 set +e
```

