########
# NACLGEN GENERATED POLICY, DO NOT EDIT
# See: https://github.com/bsycorp/naclgen
# Generated: 2018-09-27T10:46:02.099140
########

resource "aws_network_acl" "dmz" {
  vpc_id = "${local.naclgen_vpc_id}"

  subnet_ids = [
    "${lookup(local.naclgen_subnets["ids"], "dmz_a")}",
    "${lookup(local.naclgen_subnets["ids"], "dmz_b")}",
    "${lookup(local.naclgen_subnets["ids"], "dmz_c")}",
  ]

  # Rule(zone='dmz', direction='<>', target_zone='dmz', service_list=['self_traffic'], tags=[])
  ingress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "dmz")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='dmz', direction='>', target_zone='int', service_list=['https'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "int")}"
    from_port  = 1024
    to_port    = 65535
  }

  # Rule(zone='mgn', direction='>', target_zone='dmz', service_list=['ssh'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "mgn")}"
    from_port  = 22
    to_port    = 22
  }

  # Rule(zone='dmz', direction='!', target_zone='vpc', service_list=['any'], tags=[])
  ingress {
    protocol   = "all"
    rule_no    = 300
    action     = "deny"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "vpc")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='dmz', direction='<', target_zone='internet', service_list=['https'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 400
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Rule(zone='dmz', direction='<>', target_zone='dmz', service_list=['self_traffic'], tags=[])
  egress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "dmz")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='dmz', direction='>', target_zone='int', service_list=['https'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "int")}"
    from_port  = 443
    to_port    = 443
  }

  # Rule(zone='mgn', direction='>', target_zone='dmz', service_list=['ssh'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "mgn")}"
    from_port  = 1024
    to_port    = 65535
  }

  # Rule(zone='dmz', direction='!', target_zone='vpc', service_list=['any'], tags=[])
  egress {
    protocol   = "all"
    rule_no    = 300
    action     = "deny"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "vpc")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='dmz', direction='<', target_zone='internet', service_list=['https'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 400
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  tags {
    Name = "dmz.${local.naclgen_acl_label}"
  }
}

resource "aws_network_acl" "int" {
  vpc_id = "${local.naclgen_vpc_id}"

  subnet_ids = [
    "${lookup(local.naclgen_subnets["ids"], "int_a")}",
    "${lookup(local.naclgen_subnets["ids"], "int_b")}",
    "${lookup(local.naclgen_subnets["ids"], "int_c")}",
  ]

  # Rule(zone='int', direction='<>', target_zone='int', service_list=['self_traffic'], tags=[])
  ingress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "int")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='dmz', direction='>', target_zone='int', service_list=['https'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "dmz")}"
    from_port  = 443
    to_port    = 443
  }

  # Rule(zone='mgn', direction='>', target_zone='int', service_list=['ssh'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "mgn")}"
    from_port  = 22
    to_port    = 22
  }

  # Rule(zone='int', direction='<>', target_zone='int', service_list=['self_traffic'], tags=[])
  egress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "int")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='dmz', direction='>', target_zone='int', service_list=['https'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "dmz")}"
    from_port  = 1024
    to_port    = 65535
  }

  # Rule(zone='mgn', direction='>', target_zone='int', service_list=['ssh'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "mgn")}"
    from_port  = 1024
    to_port    = 65535
  }

  tags {
    Name = "int.${local.naclgen_acl_label}"
  }
}

resource "aws_network_acl" "mgn" {
  vpc_id = "${local.naclgen_vpc_id}"

  subnet_ids = [
    "${lookup(local.naclgen_subnets["ids"], "mgn_a")}",
    "${lookup(local.naclgen_subnets["ids"], "mgn_b")}",
    "${lookup(local.naclgen_subnets["ids"], "mgn_c")}",
  ]

  # Rule(zone='mgn', direction='<>', target_zone='mgn', service_list=['self_traffic'], tags=[])
  ingress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "mgn")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='mgn', direction='>', target_zone='dmz', service_list=['ssh'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "dmz")}"
    from_port  = 1024
    to_port    = 65535
  }

  # Rule(zone='mgn', direction='>', target_zone='int', service_list=['ssh'], tags=[])
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "int")}"
    from_port  = 1024
    to_port    = 65535
  }

  # Rule(zone='mgn', direction='<>', target_zone='mgn', service_list=['self_traffic'], tags=[])
  egress {
    protocol   = "all"
    rule_no    = 50
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "mgn")}"
    from_port  = 0
    to_port    = 0
  }

  # Rule(zone='mgn', direction='>', target_zone='dmz', service_list=['ssh'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "dmz")}"
    from_port  = 22
    to_port    = 22
  }

  # Rule(zone='mgn', direction='>', target_zone='int', service_list=['ssh'], tags=[])
  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "${lookup(local.naclgen_subnets["cidrs"], "int")}"
    from_port  = 22
    to_port    = 22
  }

  tags {
    Name = "mgn.${local.naclgen_acl_label}"
  }
}
