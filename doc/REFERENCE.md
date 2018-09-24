# Naclgen Reference

* [Network Requirements](#network-requirements)
* [Policy Definitions](#policy-definitions)
 * [Services](#services)
 * [Zones](#zones)
 * [Rules](#rules)
* [Terraform Binding](#terraform-binding)

## Network requirements

For `naclgen` to work well and provide good security, the network 
should meet the following requirements:

General assumptions:

* All zones should have non-overlapping IP address ranges, except 
  for the implicitly defined `internet` zone.
* Service ports in zones with loose ephemeral port ranges (using
  the ephemeral range 1024-65535) should be below 1024.
* Service ports in zones with strict ephemeral port ranges (using
  the ephemeral range 32768-65535) should be below 32768.

Codegen / Terraform assumptions:

* The code generator currently assumes that any subnets defined are
  present in 3 AWS availability zones (a, b, c). This can be overridden
  for a zone with the zone tag `+single_az`.
* Subnets are per-AZ. The codegen assumes that for a given zones, all
  the subnets are sliced out of a single CIDR identifying the zone. So 
  `dmz_a`, `dmz_b` and `dmz_c` must all be subnets of a larger range 
  named `dmz`.

## Policy definitions

There are 3 types of objects in a naclgen policy or implementation file:

* *service* - a friendly name for one or more port and protocol 
  combinations
* *zone* - a network zone, which might be internal (in-vpc) or 
  external (out-of-vpc)
* *rule* - defines which services are permitted between which zones

### Services

A service definition looks like: `service <name> [port/proto...]`, for example:

```
service dns 53/udp 53/tcp
```

Services may appear anywhere in a rules file, although recommended style 
is to include all services together in a block at the top of the file.

There is one "special" (implicitly defined) service "any", which means 
"all protocols, all ports".

There is no support for port ranges at this time (e.g. `2000-2003/tcp`), so 
one needs to write a service definition for a range of ports as:

```
service lunahsm 2000/tcp 2001/tcp 2002/tcp 2003/tcp
```

### Zones

A zone definition looks like: `zone <name> <internal|external> [+tag,...]`, 
for example:

```
zone dmz      internal
zone trusted  internal
zone partner1 external
zone corpnet  external +ephemeral_loose
```

An "internal" zone corresponds to a subnet in our VPC. An "external" zone 
corresponds to one or more network CIDRs that are external to the VPC.

There are two "special" zones with reserved names:

* *all* - represents all *internal* networks
* *internet* - represents `0.0.0.0/0` (i.e, all sources)

The valid values for zone tags are:

* `+ephemeral_loose`: This means that traffic egressing from the given zone
  will use a wide range of ephemeral ports (1024-65535). This will affect the
  generation of return traffic rules. *Note* currently this is only supported 
  on internal zones. For zones that accept external traffic with wide ephemeral 
  port ranges you must use `+ephemeral_loose` as a rule tag.

#### The "all" zone

The "all" zone can only be used in a rule source and is used to define rules 
which will apply to all internal zones. For example:

```
rule all {
   > shared_services dns
}
```

Would allow all zones to initiate dns traffic to the "shared_services" zone.

#### The "internet" zone

The "internet" zone is an implicit zone which represents a CIDR of `0.0.0.0/0`, 
but *excluding* any internal zones. 

This is implemented during concrete rule generation by moving internet rules 
to the bottom of the ruleset, and inserting a "VPC block rule" in front of them.

This prevents 0.0.0.0/0 ranges from implicitly allowing traffic from internal
subnets.

### Rules

Rule syntax is as follows:

```
rule <subject-zone> {
    <direction-indicator> <target-zone> [service(s)...] [+tags]
}
```

* *subject-zone*: Identifies the primary zone that the rule applies to. This 
  must be an *internal* zone.
* *direction-indicator*: Indicates the direction of the traffic flow. Valid
  values are:
  * `>`: indicates that traffic will be initiated from the subject-zone
  * `<`: indicates that traffic will be accepted from the target-zone. Traffic
    may only be accepted in this way from an *external* zone.
* *target-zone*: Identifies the zone to which traffic will be emitted (>) or
  received from (<) depending on the direction indicator.
* *services*: The list of services which will be allowed by the rule. If the
  service list is omitted, *all* services will be allowed (all TCP, UDP and 
  ICMP traffic)
* *tags*: These are "extra attributes" of the flow. Currently the following
  tags are allowed:
  * *+ephemeral_loose*: Indicates that return traffic for the given flow should
    allow ports 1024-65535 instead of the default 32768-65535. This affects the
    generation of rules allowing return traffic.

## Terraform Binding

To use the generated terraform, the host project (aka the platform) must 
provide some local variables, in the following format:

locals {
  naclgen_vpc_id = "vpc-123456",
  naclgen_acl_label = "my.kube.cluster"
  naclgen_subnets = {
    ids = {
      trusted_a = "subnet-12341",
      trusted_b = "subnet-12342",
      trusted_c = "subnet-12343",
      restricted_a = "subnet-12344",
      restricted_b = "subnet-12345",
      restricted_c = "subnet-12346",
      aws_public = "subnet-123457",
    },
    cidrs = {
      vpc = "12.34.56.56/24",
      trusted = "12.34.56.78/24",
      restricted = "12.34.56.89/24",
    },
  }
}

* `naclgen_vpc_id`: the ID of the VPC
* `naclgen_subnets`: contains two maps, one with subnet ids and 
  the other with subnet cidrs.
  * `ids`: Entries should be in the format: `$(ZONE)_$(AZ)`. For each zone, 
  the code will try to look up the ID of the subnet in each applicable AZ to
  apply the nacls. If the zone is single-AZ, don't bother with the suffixes.
  * `cidrs`: Defines network CIDRs for each zone, and each AZ in each
  zone. Certain keys should be present:
    * `vpc` => The CIDR of the whole VPC
    * Then for each zone, (e.g. `dmz`):
      * `dmz` => CIDR covering all subnets in the zone 

For example, considering the following generated terraform code:

```
resource "aws_network_acl" "semitrusted" {
  vpc_id = "${local.naclgen_vpc_id}"

  subnet_ids = [
    "${lookup(local.naclgen_subnets["ids"], "dmz_a")}",
    "${lookup(local.naclgen_subnets["ids"], "dmz_b")}",
    "${lookup(local.naclgen_subnets["ids"], "dmz_c")}",
  ]

  ...

  # Rule(zone='all', direction='>', target_zone='shared_services', service_list=['dns'])
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(var.subnets, "shared_services")}"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "shared_services")}",
    from_port  = 32768
    to_port    = 65535
  }

```

An example compatible subnet map would be:

```
locals {
  naclgen_vpc_id = ...,
  naclgen_acl_label = ...,
  naclgen_subnets = {
    ids = {
       ...,
    },
    cidrs = {
      // Whole VPC CIDR
      vpc = "10.215.96.0/21",
   
      // Each internal zone CIDR
      semitrusted   = "10.215.96.0/25",
      ...

      // Each external zone CIDR
      shared_services    = "10.99.0.0/16",
      ...
    },
  }
}
``` 

