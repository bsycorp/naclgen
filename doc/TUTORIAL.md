## Policy Tutorial

By convention, policy files have the file extension `.policy` and implementation 
files have the extension `.ng`. 

For anyone with previous firewall configuration experience, the policy and 
implementation files are intended be fairly readable without much introduction.

A short example policy: `sample1.policy`

```
zone dmz internal
zone int internal
zone mgn internal

rule dmz {
  < internet 
  > int
}

rule int {
  # Left blank, does not initiate traffic
}

rule mgn {
  > dmz 
  > int
}
```

The policy begins by defining 3 internal zones (within our VPC). 
There is also an implicit zone called "internet" which will be 
discussed further later.

This policy reads as follows:

* "dmz" (dmz) zone may accept traffic from the "internet" and 
   initiate traffic to the "int" zone
* "int" (internal) zone may not initiate traffic to any other zone
* "mgn" (management) may initiate connections to the "dmz" or "int" 
   zones

The forward arrow `>` indicates that trafic will be initiated towards 
a zone, while the `<` backwards arrow indicates that traffic will be 
accepted from a zone.

In general, flows are written in the forward direction (with `>`), 
except when defining rules which accept traffic from "external" zones 
such as the Internet. 

Here is a corresponding implementation: `sample1.ng`

```
service ssh     22/tcp
service https   443/tcp

zone dmz internal
zone int internal
zone mgn internal
zone internet external 

rule dmz {
  < internet https
  > int https
}

rule mgn {
  > dmz ssh
  > int ssh
}
```

The implementation above is written with the exact same syntax as the 
policy, but is slightly more detailed. In this case, we have added some specific 
services (ssh and https) to our rules.

This implementation can be read as follows:

* "dmz" (dmz) zone accepts https from the "internet" and initiates https 
   to the "int" zone
* "mgn" (management) zone may initiate ssh towards the "dmz" and "int" zones
* Since no rules are defined for the "int" zone, it may not initiate traffic
  towards any other zone.

Note that the implementation must be "more strict" than the overall policy. 
That is, it must permit a *subset* of the traffic that is allowed by policy. 
