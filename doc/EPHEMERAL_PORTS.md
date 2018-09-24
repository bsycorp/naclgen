# Ephemeral Port Ranges

## About ephemeral ports

When a network client makes an outbound request, by default the operating 
system will select an *ephemeral port* number to use as the source port of
the connection. These numbers are chosen from an operating system specific 
range.

The ephemeral port range is chosen to fall outside the port range which is 
generally used for listening services on hosts.

## Why ephemeral port ranges matter for NACLs

Inherent in stateless network ACL designs is the assumption that services 
will be presented on a certain set of ports while return traffic will be 
sent back to the client with a destination port in a different range.

If this were not true, then the only network ACL rules which could be written 
would be to allow or block whole subnets and it would not be possible to 
enforce service level access controls.

Consider the following diagram (not to scale):


```
+----+---+                       ->+--------+   PORT 0  
 |    |   |                    -/  |   |    |     
 |    | S |                  -/    | S |    |     
 |    | V |                -/      | V |    |     
 |    | C |              -/        | C |    |     
 |    |   |            -/          |   |    |     
 |    +---+          -/           >|---+    |   PORT 1024  
 |        |        -/            / |        |     
 |        |      -/            -/  |        |     
 |        |    -/             /    |        |     
 |        |  -/              /     |        |     
 |    +---+-/              -/      |---+    |   PORT 32768  
 |    |   |               /        |   |    |     
 |    | E |              /         | E |    |     
 |    | P |             /          | P |    |     
 |    | H |           -/           | H |    |     
 |    | E |          /             | E |    |     
 |    | M |         /              | M |    |     
 |    | E |        /               | E |    |     
 |    | R |      -/                | R |    |     
 |    | A |     /                  | A |    |     
 |    | L |    /                   | L |    |     
 |    |   |  -/                    |   |    |     
 |    |   | /                      |   |    |     
 +----+---+/                       +--------+   PORT 65535  
                                                  
   Host A                            Host B
                                                  
```

In the above diagram, "Host A" is initiating a connection to "Host B".  "A" 
will choose a port from the range (32768 - 65535) and open a connection to B
on port (0 - 1024).

The following rules are required to allow this flow (in the order the rules
would be traversed):

* A EGRESS:  ALLOW TO B ON PORT 0-1024
* B INGRESS: ALLOW FROM A ON PORT 0-1024
* B EGRESS:  ALLOW TO A ON PORT 32768-65535   # RETURN TRAFFIC
* A INGRESS: ALLOW FROM B TO PORT 32768-65535 # RETURN TRAFFIC

The rules `naclgen` creates to permit *return traffic* have to take into 
account the ephemeral port ranges of all possible clients and allow back
traffic to that port range.

Ideally, we would like to use the narrowest feasible ephemeral port range 
so that the widest number of "service ports" can be protected, and to reduce 
the chance that a host service accidentally strays into the ephemeral port 
range.

## Platform ephemeral port ranges

We choose a default ephemeral port range of: 32768-65535. This covers the 
two main ranges selected by modern operating systems:

* Linux: 32768 - 60999 (Default, customisable)
* IANA: 49151 - 65535 (Used by modern Windows, OSX, many others)

There are a few real-world cases where the default may need to be overridden: 

* Egress traffic flows through AWS NAT gateways. These use a wide range of 
  ephemeral ports (1024-65535).
* Accepting traffic from "external" networks where we can not be sure what 
  ephemeral ports that clients might use. An example might be SSH into the 
  management zone, where VPN traffic might be accepted. The ephemeral port
  range will depend on various implementation details of the VPN server in
  use but the most robust thing to do is to allow a wide source port range.

Rules with the +ephemeral_loose tag will generate return rules which use the
widest reasonable ephemeral port range (1024-65535). 

Generally speaking, loose ephemeral port ranges should only be required on
edge networks. 

## Additional information

### AWS

We communicate with many AWS services. Usually these use a "sensible" ephemeral 
port range (32768+), with the exception of NAT gateways. Port exhaustion (as 
described below in "scalability implications") is particularly acute for NAT 
gateways which is why they use such a large ephemeral range.

* https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_ACLs.html#VPC_ACLs_Ephemeral_Ports

AWS's advice is as follows:

```
The client that initiates the request chooses the ephemeral port range. The 
range varies depending on the client's operating system. Many Linux kernels 
(including the Amazon Linux kernel) use ports 32768-61000. Requests originating 
from Elastic Load Balancing use ports 1024-65535. Windows operating systems 
through Windows Server 2003 use ports 1025-5000. Windows Server 2008 and later 
versions use ports 49152-65535. A NAT gateway uses ports 1024-65535. For 
example, if a request comes into a web server in your VPC from a Windows XP 
client on the Internet, your network ACL must have an outbound rule to enable 
traffic destined for ports 1025-5000.
```

### Scalability implications of the ephemeral port range

We also do not want the ephemeral port range to be too small.

Consider a service on a fixed port with a single front-end IP and imagine a 
client making a large number of requests to this service.

Suppose the ephemeral port range for a given client is 5000-6000. Obviously 
there can be no more than 1000 simultaneous connections between the client and 
the service.

Less obviously, the ephemeral port range also affects the maximum connection 
*rate* between the client and the service.

A given (protocol, src ip, src port, dst ip, dst port) tuple may not be re-used 
within a certain window of time dictated by TCP standards. This is so that 
packets from old connections which are delayed or re-ordered by the network are 
not accidentally interpreted as part of a new connection.

The amount of time to wait before the tuple can be re-used is referred to as 
the TIME_WAIT delay. This is operating system dependent, somewhat tunable and 
usually about 60 to 120 seconds. 

In the scenario above, connections between the client and the server above 
could be established at a maximum rate of about 16 per second, calculated by:

`1000 (ports) / 60 (TIME_WAIT seconds) =~ 16.6` 

This is quite low! Even if the server responds instantly, the TCP protocol will
not allow connections to be established any faster. 

* Upper bound: 0 - 65535 => ~1000 connections/sec
* IANA: 49151 - 65535 => ~273 connections/sec
* Linux: 32768 - 60999 => ~470 connections/sec

Compatible TCP stacks can sometimes exceed these limits using TCP modifications
which perform special processing of TCP sequence numbers or timestamps to permit
more aggressive connection re-use.  However, it is generally unwise to rely on 
these in a high level design.

