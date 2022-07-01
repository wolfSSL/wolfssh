# wolfSentry Itegration Example

This is a basic example that uses wolfsentry with SSH server. wolfSentry will filter a ssh client when it types invalid password more than a threshold value.
Once the peer breaks the theshold number, the peer is accommodated into a penalty box with the certain penalty time.

# Prerequisites

This example is designed to be run an environment that has file system because JSON configuration file is expected to be read.

# Build echoserver with wolfsentry

## Build and Install wolfsentry
Build and Install wolfSentry

```
$ cd <wolfsentry root folder>
$ make -j check
$ sudo make install
```
## Build wolfSSH

Build wolfSSH with the following configuration option

```
$ cd <wolfSSH root folder>
$./configure --enable-wolfsentry`
$ make
```

# wolfSentry Configuration

## Filtering IP Address
The example is configured by JSON configuraiotn file to only accept connetions from 127.0.0.1 or 192.168.11.3. Change `192.168.11.3` to your preference IP address first.

```json
    "static-routes-insert" : [
	{
	    "parent-event" : "static-route-parent",
	    "direction-in" : true,
	    "direction-out" : false,
	    "penalty-boxed" : false,
	    "green-listed" : true,
	    "dont-count-hits" : false,
	    "dont-count-current-connections" : false,
	    "family" : 2,
	    "remote" : {
		"address" : "127.0.0.1",
		"prefix-bits" : 8
	    },
	    "local" : {
		"address" : "127.0.0.1",
		"prefix-bits" : 8
	    }
	},
    {
	    "parent-event" : "static-route-parent",
	    "direction-in" : true,
	    "direction-out" : true,
	    "penalty-boxed" : false,
	    "green-listed" : true,
	    "dont-count-hits" : false,
	    "dont-count-current-connections" : false,
	    "family" : 2,
        "protocol" : 6,
	    "remote" : {
	    "address" : "192.168.11.3", <--------  IP Address to change
	    "prefix-bits" : 32,
	    "interface" : 0
	    }
	}
```
## Threshold for invalid password and duration at penaly boxing 

The threshold number is 5 times continuously. The peer is accommodated into the penalty box when it inputs wrong password more than 5 times continuously.

```json
{
    "label" : "static-route-parent",
    "priority" : 1,
    "config" : {
	"max-connection-count" : 10,
	"penalty-box-duration" : "1h",                 <---- Duration at penalty boxing. In this case, the duration is 1 hour.
	"derog-thresh-for-penalty-boxing" : 5,         <---- Theshold for invalid password
	"derog-thresh-ignore-commendable" : true,      <---- Theshold for invalid password
	"commendable-clears-derogatory" : false        <---- dero
    },
    "actions" : [ "handle-connect" ],
    "insert-event" : "event-on-insert",
    "match-event"  : "event-on-match",
    "update-event" : "event-on-update",
    "delete-event" : "event-on-delete",
    "decision-event" : "event-on-decision"
}
```

# Run echo server with wolfsentry filtering

## Launch echo SSH server

Launch `echoserver` as usual. You see additional message lines as follows:

```shell
$ cd <wolfSSH root folder>
$ ./examples/echoserver/echoserver 
action callback: a="handle-insert" parent_event="static-route-parent" trigger="static-route-parent" t=2 r_id=20 caller_arg=(nil)
rule_route render: 
127.0.0.0/8:* -> 127.0.0.0/8:*, ev = "static-route-parent", AF = INET, proto = *
 insert_time 		Fri Sep  2 10:45:25 2022
 last_hit_time 		
 last_penaltybox_time 	
 connection_count 	0
 derogatory_count 	0
 commendable_count 	0

action callback: a="handle-insert" parent_event="static-route-parent" trigger="static-route-parent" t=2 r_id=21 caller_arg=(nil)
rule_route render: 
192.168.11.3/32%0:* <-> *:*, ev = "static-route-parent", AF = INET, proto = tcp
 insert_time 		Fri Sep  2 10:45:25 2022
 last_hit_time 		
 last_penaltybox_time 	
 connection_count 	0
 derogatory_count 	0
 commendable_count

password upthehill
password fetchapail
```

Those messages are displayed by callback function from wolfsentry when `static route rule` is inserted.

## Connect from SSH Client

Open terminal on your PC whose IP address is in JSON Configuration file above. Connect to echo SSH server with 22222 port number. In this document, echo SSH server is running at 192.168.11.35, and SSH client runs on 192.168.11.3.

```shell
$ ssh jill@192.168.11.35 -p 22222
wolfSSH Example Echo Server
jill@192.168.11.35's password:
```

### Types invalud password more than 5 times


```shell
foo@hoge ~
$ ssh jill@192.168.11.35 -p 22222
wolfSSH Example Echo Server
jill@192.168.11.35's password:
Permission denied, please try again.
jill@192.168.11.35's password:
Permission denied, please try again.
jill@192.168.11.35's password:
jill@192.168.11.35: Permission denied (publickey,password).
foo@hoge ~
$ ssh jill@192.168.11.35 -p 22222
wolfSSH Example Echo Server
jill@192.168.11.35's password:
Permission denied, please try again.
jill@192.168.11.35's password:
Permission denied, please try again.
jill@192.168.11.35's password:
Received disconnect from 192.168.11.35 port 22222:14:
Disconnected from 192.168.11.35 port 22222
```

You see the following messages at echo SSH server side

```shell
action callback: a="notify-on-match" parent_event="static-route-parent" trigger="authentication_failed" t=3 r_id=21 caller_arg=0x561e60cd7a60
rule_route render: 
192.168.11.3/32%0:* <-> *:*, ev = "static-route-parent", AF = INET, proto = tcp
 insert_time 		Fri Sep  2 10:45:25 2022
 last_hit_time 		Fri Sep  2 10:57:21 2022
 last_penaltybox_time 	
 connection_count 	0
 derogatory_count 	4                            <--- Peer types invalid password 4 times continuously.
 commendable_count 	0

action callback: a="handle-update" parent_event="static-route-parent" trigger="authentication_failed" t=4 r_id=21 caller_arg=0x561e60cd7a60
rule_route render: 
192.168.11.3/32%0:* <-> *:*, ev = "static-route-parent", AF = INET, proto = tcp
 insert_time 		Fri Sep  2 10:45:25 2022
 last_hit_time 		Fri Sep  2 10:57:21 2022
 last_penaltybox_time 	Fri Sep  2 10:57:21 2022 <--- Peer is accommodated into a penalty box because of exceeding threshold
 connection_count 	0
 derogatory_count 	0
 commendable_count 	0

action callback: a="notify-on-decision" parent_event="static-route-parent" trigger="authentication_failed" t=6 r_id=21 caller_arg=0x561e60cd7a60
rule_route render: 
192.168.11.3/32%0:* <-> *:*, ev = "static-route-parent", AF = INET, proto = tcp
 insert_time 		Fri Sep  2 10:45:25 2022
 last_hit_time 		Fri Sep  2 10:57:21 2022
 last_penaltybox_time 	Fri Sep  2 10:57:21 2022
 connection_count 	0
 derogatory_count 	0
 commendable_count 	0

TCP Sentry action returned code 0 (OK, operation succeeded), src 4 (routes.c), line 1174
wolfsentry rejected                              <--- Peer connection is rejected because of penalty boxing now
User authentication error

```

You will be rejected once you connect to echo SSH server because you are in penalty box.

```shell
$ ssh jill@192.168.11.35 -p 22222
kex_exchange_identification: Connection closed by remote host
Connection closed by 192.168.11.35 port 22222
```

You will be released from a penalty box after finishing your 1 hour term.

`client side prompt`
```shell
$ date
Fri Sep  2 12:05:31 JST 2022
$ ssh jill@192.168.11.35 -p 22222
wolfSSH Example Echo Server
jill@192.168.11.35's password:
```

`server side prompt`
```shell
action callback: a="notify-on-decision" parent_event="static-route-parent" trigger="call-in-from-echo" t=6 r_id=21 caller_arg=(nil)
rule_route render: 
192.168.11.3/32%0:* <-> *:*, ev = "static-route-parent", AF = INET, proto = tcp
 insert_time 		Fri Sep  2 10:45:25 2022
 last_hit_time 		Fri Sep  2 12:05:47 2022
 last_penaltybox_time 	Fri Sep  2 10:57:21 2022
 connection_count 	0
 derogatory_count 	0
 commendable_count 	0

TCP Sentry action returned code 0 (OK, operation succeeded), src 4 (routes.c), line 1178
wolfsentry accepted
```

## derogatory count

derogatory count will be cleared when the peer becomes commendable(valid password input).
The following example messages, Peer continuously typed invalid password 3 times. And then, it becomes commendable. Therefore, wolfsentry clears its derogatory count.

```shell
action callback: a="notify-on-match" parent_event="static-route-parent" trigger="authentication_succeeded" t=3 r_id=21 caller_arg=0x55adeff1be30
rule_route render: 
192.168.11.3/32%0:* <-> *:*, ev = "static-route-parent", AF = INET, proto = tcp
 insert_time 		Fri Sep  2 15:20:23 2022
 last_hit_time 		Fri Sep  2 15:20:41 2022
 last_penaltybox_time 	
 connection_count 	0
 derogatory_count 	3                      <--- Peer continuously typed invalid password 3 times.
 commendable_count 	1

action callback: a="handle-update" parent_event="static-route-parent" trigger="authentication_succeeded" t=4 r_id=21 caller_arg=0x55adeff1be30
clear derogatory count
Route detail: 
192.168.11.3/32%0:* <-> *:*, ev = "static-route-parent", AF = INET, proto = tcp
 insert_time 		Fri Sep  2 15:20:23 2022
 last_hit_time 		Fri Sep  2 15:20:41 2022
 last_penaltybox_time 	
 connection_count 	0
 derogatory_count 	0                       <--- Because Peer has become commendable peer, wolfsentry clears the count.
 commendable_count 	2

action callback: a="notify-on-decision" parent_event="static-route-parent" trigger="authentication_succeeded" t=6 r_id=21 caller_arg=0x55adeff1be30
rule_route render: 
192.168.11.3/32%0:* <-> *:*, ev = "static-route-parent", AF = INET, proto = tcp
 insert_time 		Fri Sep  2 15:20:23 2022
 last_hit_time 		Fri Sep  2 15:20:41 2022
 last_penaltybox_time 	
 connection_count 	0
 derogatory_count 	0
 commendable_count 	2

```
