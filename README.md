
# naclgen - A network ACL generator and validator.

## Purpose

The `naclgen` software provides a simple DSL (domain-specific-language) for 
describing allowed network traffic flows. The DSL is used to generate (terraform) 
network ACLs for each subnet in a network environment.

## Description

Our platform enforces strict network ACLs between all AWS subnets.

Initially, the rules were manually maintained. The main problems with manually 
maintained NACLs were:

1. Verbosity - over 1000 lines need to define the rules for one 
   environment (currently there are 3 envs). This was partly due to the number 
   of zones in play (6) per environment.
1. Repetition - one "flow" (say, allow protocol X between subnets A and B) results
   in 4 rules  (1 ingress and 1 egress rule on both A and B) to be maintained and
   kept consistent over time. 
1. Due to the large number of rules needed, it was difficult to validate that the 
   NACLs actually implemented the original design intent.
1. It was also difficult to validate that the NACLs conformed with network
   governance rules.

All of these factors made NACL changes fairly "risky" and impeded agility. 

To define network ACLs, two types of files must be created:

* "policy files" - Define in broad terms the allowed traffic flows,
  allowing some level of automated governance.
* "implementation files" - Which propose specific traffic flows for a given 
  environment. They will be validated against policy.

## Command-line Usage

Taking a policy and an implementation file, the generation process looks 
like this:

`./naclgen.py my-aws-vpc.ng my-aws-vpc.policy > my-aws-vpc-nacls.tf`

Where:

* `my-aws-vpc.policy` is the network policy definition
* `my-aws-vpc.ng` contains the specific traffic flows requested for use between
  the "my-aws-vpc" subnets
* `my-aws-vpc-nacls.tf` is the generated terraform code to implement the NACLs

If the proposed implementation violates allowed traffic flows defined at the policy
level, then an error will be emitted and no NACLs will be generated.

## References

* [doc/TUTORIAL.md](doc/TUTORIAL.md) - Policy design tutorial
* [doc/REFERENCE.md](doc/REFERENCE.md) - Policy DSL reference
* [doc/INTERNALS.md](doc/INTERNALS.md) - How it works
* Extras:
  * [doc/EPHEMERAL_PORTS.md](doc/EPHEMERAL_PORTS.md) - Detailed discussion of ephemeral port issues
  * [doc/ICMP.md](doc/ICMP.md) - Discussion of ICMP

## Limitations

* Port ranges are not supported. Services must list each port separately. This
  will need to be fixed if we have any services which use large port ranges (say
  >5 ports) or we will probably hit NACL length limits.
* Only TCP and UDP services are supported. Currently, the generated NACLs will
  not permit any ICMP between zones. ICMP rules are not supported.  See 
  [doc/ICMP.md](doc/ICMP.md) for more details. 
* AWS supports up to 20 ingress and 20 egress rules per network ACL. AWS support
  can increase these limits up to 40, but `naclgen` currently does not detect 
  when this is required. 

## Known Bugs / Issues

* The +ephemeral_strict tag does not work when applied to an external zone. This
  configuration will be raised as an error.
* The +ephemeral_strict tag is not taken into account during rule coalescing or
  policy enforcement.
* It is not currently an error if a service port overlaps with the ephemeral port
  range for a flow or zone.

