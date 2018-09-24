########
# NACLGEN GENERATED POLICY, DO NOT EDIT
# See: https://github.com/bsycorp/naclgen
# Generated: 2018-09-27T10:46:02.005073
########

resource "aws_network_acl" "a" {
  vpc_id = "${local.naclgen_vpc_id}"

  subnet_ids = [
    "${lookup(local.naclgen_subnets["ids"], "a_a")}",
    "${lookup(local.naclgen_subnets["ids"], "a_b")}",
    "${lookup(local.naclgen_subnets["ids"], "a_c")}",
  ]

  # Rule(zone='a', direction='<>', target_zone='a', service_list=['self_traffic'], tags=[])
  ingress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "a")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='a', direction='>', target_zone='b', service_list=['https'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "b")}"
    from_port  = 1024
    to_port    = 65535
  }

  # Rule(zone='a', direction='<>', target_zone='a', service_list=['self_traffic'], tags=[])
  egress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "a")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='a', direction='>', target_zone='b', service_list=['https'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "b")}"
    from_port  = 443
    to_port    = 443
  }

  tags {
    Name = "a.${local.naclgen_acl_label}"
  }
}

resource "aws_network_acl" "b" {
  vpc_id = "${local.naclgen_vpc_id}"

  subnet_ids = [
    "${lookup(local.naclgen_subnets["ids"], "b_a")}",
    "${lookup(local.naclgen_subnets["ids"], "b_b")}",
    "${lookup(local.naclgen_subnets["ids"], "b_c")}",
  ]

  # Rule(zone='b', direction='<>', target_zone='b', service_list=['self_traffic'], tags=[])
  ingress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "b")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='a', direction='>', target_zone='b', service_list=['https'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "a")}"
    from_port  = 443
    to_port    = 443
  }

  # Rule(zone='b', direction='<>', target_zone='b', service_list=['self_traffic'], tags=[])
  egress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "b")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='a', direction='>', target_zone='b', service_list=['https'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "a")}"
    from_port  = 1024
    to_port    = 65535
  }

  tags {
    Name = "b.${local.naclgen_acl_label}"
  }
}
