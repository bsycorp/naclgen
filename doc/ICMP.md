# ICMP

Currently we don't support ICMP between zones. The main thing we break with this
is path MTU discovery. 

This has not been a problem yet. Presumably because our usable MTUs are the same
everywhere.

Overall the risks of enabling ICMP between internal zones is pretty low.

Ideally, we would want to allow:

* "Good" ICMP
  * type 3 code 4: Fragmentation needed but DF set (allows PMTU-d)
* "Diagnostic" ICMP
  * type 0 code 0: Echo reply
  * type 8 code 0: Echo request
  * type 11 code 0: TTL exceeded in transit (allows traceroute)

While blocking all other ICMP ("Useless" or "Bad"). However depending on how this
is done, it could add a *lot* of extra rules.

## AWS Advice

* https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_NACLs.html

```
If the maximum transmission unit (MTU) between hosts in your subnets is 
different, you must add the following inbound and outbound network ACL rules 
to ensure that Path MTU Discovery can function correctly and prevent packet 
loss: Custom ICMP Rule type and Destination Unreachable: fragmentation required, 
and DF flag set port range (Type 3, Code 4). For more information, see Network 
Maximum Transmission Unit (MTU) for Your EC2 Instance in the Amazon EC2 User 
Guide for Linux Instances.
```
