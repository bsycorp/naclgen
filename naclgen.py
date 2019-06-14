#!/usr/bin/env python3

import re
import os
import sys
import datetime
from collections import namedtuple

# Abstract realm (domain objects related to written rules)
Policy   = namedtuple('Policy', ['name', 'services', 'zones', 'rules'])
Port     = namedtuple('Port', ['port', 'proto'])
Service  = namedtuple('Service', ['name', 'ports'])
Zone     = namedtuple('Zone', ['name', 'int_or_ext', 'tags'])
Rule     = namedtuple('Rule', ['zone', 'direction', 'target_zone', 'service_list', 'tags'])

def strip_comments(s):
    return re.sub("#.*$", "", s)

def validate_name(name):
    if re.match("^[a-zA-Z][a-zA-Z_0-9-]*$", name) is None:
        raise ValueError('invalid name: %s', name)
    return name

def validate_port_number(portstr):
    try:
        portnum = int(portstr)
    except:
        raise ValueError("invalid port number: %s" % portstr)
    if portnum < 1 or portnum > 65535:
        raise ValueError("port number out of range: %s" % portnum)
    return portnum

def validate_zone_tag(tag):
    if tag not in ['+ephemeral_strict', '+single_az']:
        raise ValueError("invalid zone tag: %s" % tag)
    return tag

def validate_rule_tag(tag):
    if tag not in ['+ephemeral_strict', '+ephemeral_loose']:
        raise ValueError('invalid rule tag: %s' % tag)
    return tag

# Put a bunch of validation around domain object creation, this helps us
# keep the parser dumb.

def new_port(s):
    portstr, proto = s.split('/')[0:2]
    if not portstr or not proto:
        raise ValueError("port/proto does not make sense: %s" % s)
    if proto not in ["tcp", 'udp']:
        raise ValueError("unknown protocol: %s" % proto)
    return Port(port=validate_port_number(portstr), proto=proto)

def new_service(name, ports):
    return Service(validate_name(name), [new_port(p) for p in ports])

def new_zone(name, int_or_ext, tags):
    if int_or_ext not in ["internal", "external"]:
        raise ValueError("wanted internal/external tag, got: %s" % int_or_ext)
    if name in ['all', 'internet']:
        raise ValueError("tried to declare reserved zone name: %s", name)
    if int_or_ext == 'external' and '+ephemeral_strict' in tags:
        raise RuntimeError('sorry, +ephemeral_strict on external zones does not work')
    return Zone(validate_name(name), int_or_ext, [validate_zone_tag(x) for x in tags])

def new_rule(zone, direction, target_zone, service_list, tags=None):
    """Create a new rule, validating all arguments"""
    if direction not in ['<', '>']:
        raise ValueError("unexpected rule direction: %s" % direction)
    if target_zone == 'all':
        raise ValueError("cannot use 'all' zone as a rule target")
    if tags is None:
        tags = []
    return Rule(validate_name(zone), direction, validate_name(target_zone), 
                [validate_name(s) for s in service_list], 
                [validate_rule_tag(t) for t in tags])

def synthetic_rule(zone, direction, target_zone, service_list):
    """Like new_rule, but allows arbitrary direction (e.g. <> or !). Only used
    internally for auto-generated rules. Not reachable from normal policy code."""
    return Rule(validate_name(zone), direction, validate_name(target_zone),
                [validate_name(s) for s in service_list], [])

def new_policy(name):
    return Policy(name=name, services={}, zones={}, rules=[])

def parse_policy(name, lines):
    """Take a proto or ng file and parse it into a Policy."""
    policy = new_policy(name)
    state = "body"
    current_rule_target_zone = None
    for i, line in enumerate(lines):
        try:
            line = strip_comments(line).strip()
            if not line:
                continue
            tokens = line.split()
            cmd, args = tokens[0], tokens[1:]
            if state == "body":
                if cmd == "service" and len(args) > 1:
                    s = new_service(name=args[0], ports=args[1:])
                    policy.services[s.name] = s
                elif cmd == "zone" and len(args) >= 2:
                    z = new_zone(name=args[0], int_or_ext=args[1], tags=args[2:])
                    policy.zones[z.name] = z
                elif cmd == "rule" and len(args) == 2 and args[1] == "{":
                    current_rule_target_zone = args[0]
                    state = "ruleblock"                    
                else:
                    raise ValueError("failed to parse: %s" % line)
            elif state == "ruleblock":
                if cmd in ['<', '>'] and len(args) > 0:
                    if len(args) == 1:
                        service_list = ['any']
                        tag_list = []
                    else:
                        service_list = [s for s in args[1:] if not s.startswith('+')]
                        tag_list = [s for s in args[1:] if s.startswith('+')]
                    r = new_rule(zone=current_rule_target_zone, direction=cmd, 
                             target_zone=args[0], service_list=service_list, tags=tag_list)
                    policy.rules.append(r)
                elif cmd == "}":
                    current_rule_target_zone = None
                    state = "body"
                else:
                    raise ValueError("in rule block, failed to parse: %s" % line)
            else:
                # "can't happen"
                raise NotImplementedError
        except Exception as e:
            # Patch the exception with the policy name and line number
            exc_args = list(e.args)
            exc_args[0] = ('error in policy %s at line %d: ' % (name, i)) + exc_args[0]
            e.args = tuple(exc_args)
            
            raise
    # Internet zone is an implicit part of every policy because we handle internet
    # zone rules specially
    policy.zones['internet'] = Zone(name='internet', int_or_ext='external', tags=[])
    return policy

###
# Policy validation
###

def validate_policy(p):
    """Determine whether a given policy is internally consistent."""
    # Mostly, this is about whether the rules all reference things that exist
    for rule in p.rules:
        # Services in rules must exist
        for service_name in rule.service_list:
            if service_name not in p.services and service_name != 'any':
                raise AssertionError('unknown service name: %s' % service_name)
        # Source zones must exist or be 'all'
        if rule.zone not in p.zones and rule.zone != 'all':
            raise AssertionError('unknown zone in source: %s' % rule.zone)
        # Target zones must exist, they cannot be 'all'
        if rule.target_zone not in p.zones:
            raise AssertionError('unknown zone in target: %s' % rule.target_zone)
        # Can't define rules on external zones (we don't control them!)
        if rule.zone != 'all' and p.zones[rule.zone].int_or_ext == 'external':
            raise AssertionError('cannot define rules on external zone: %s', rule.zone)
        # Enforce "positive" traffic flow, that is defining by initiator
        # This means we don't allow e.g. "internal < other_internal stuff more_stuff"
        if rule.direction == '<' and p.zones[rule.target_zone].int_or_ext == 'internal':
            raise AssertionError('cannot receive traffic from internal zone: %s' %
                                 rule.target_zone)
    return p

def rules_are_compatible(policy_rule, impl_rule):
    """Returns true if the given policy *could* permit the given impl rule.
    This means the source, target and direction are the same. This handles 
    everything except the specific services involved."""
    if policy_rule.zone != impl_rule.zone and policy_rule.zone != 'all':
        return False
    if policy_rule.direction != impl_rule.direction:
        return False
    if policy_rule.target_zone != impl_rule.target_zone:
        return False
    return True

def validate_policy_allows_impl_rule(all_policy, impl_rule):
    """Scan the entire set of policy rules, verifying that the impl_rule is 
    permitted by the policy ruleset. We raise if that is not the case."""
    blocked_impl_services = set(impl_rule.service_list)
    for policy_rule in all_policy:
        # Only compare if rules are compatible
        if not rules_are_compatible(policy_rule, impl_rule):
            continue
        # This is the easy case: all traffic was allowed by policy, so any
        # "compatible" impl rule will be fine.
        if 'any' in policy_rule.service_list:
            return 
        # This is the tricky case; perhaps there are two distinct
        # policy rules which, taken together, permit a given impl
        # rule. We start off with all services blocked and unblock
        # them as we match them in policy. If there are no blocked
        # services at the end of this process, success.
        for policy_service in policy_rule.service_list:
            if policy_service in blocked_impl_services:
                blocked_impl_services.remove(policy_service)
                
    if len(blocked_impl_services) > 0:
        err = "impl rule: %s: services blocked by policy: %s" % \
            (impl_rule, blocked_impl_services)
        raise AssertionError(err)

    # Victory
    return    

def validate_policy_vs_impl(policy, impl):
    """Validate that implementation is a subset of policy."""
    
    # Must be no zones in impl that were not defined in policy
    # Zone type (internal vs external) must match
    for impl_zone_name, impl_zone in impl.zones.items():
        if impl_zone_name not in policy.zones:
            raise AssertionError('zone %s not defined in policy' % impl_zone_name)
        if impl_zone.int_or_ext != policy.zones[impl_zone_name].int_or_ext:
            raise AssertionError('zone %s differs between impl and policy' %
                                 impl_zone_name)

    # Any services defined in impl must be defined identically in policy.
    # It is OK if there are some extra services in impl, but they can only 
    # match a corresponding "allow all" in the policy. That gets checked later.
    for impl_svc_name, impl_svc in impl.services.items():
        if impl_svc_name in policy.services:
            if impl_svc != policy.services[impl_svc_name]:
                raise AssertionError('service definition "%s" differs from policy' %
                                     impl_svc_name)

    # Rules in impl must be matched by corresponding rules in policy. We do this by 
    # brute force. For each rule in the impl, we scan all the rules in policy to ensure
    # that all the services listed in the impl are permitted by policy.
    for impl_rule in impl.rules:
        validate_policy_allows_impl_rule(all_policy=policy.rules, impl_rule=impl_rule)

###
# Expansion from abstract to concrete rules
###

# Concrete realm (what gets generated)
ConcretePolicy = namedtuple('ConcretePolicy', ['zones'])
ConcretePort = namedtuple('ConcretePort', ['proto', 'from_port', 'to_port'])
ConcreteRule = namedtuple('ConcreteRule', ['source_rules', 'rule_no', 'target_zone', 
                                           'direction', 'port', 'action'])

class ConcreteZone(object):
    def __init__(self, name, source_zone):
        self.name = name
        self.rules = []
        self.source_zone = source_zone

    @property
    def ingress_rules(self):
        return [r for r in self.rules if r.direction == 'ingress']

    @property
    def egress_rules(self):
        return [r for r in self.rules if r.direction == 'egress']

def rule_affects_zone(zone, rule):
    """Determine whether an abstract rule should trigger concrete rule generation for
    the given zone"""
    return rule.zone == zone.name or rule.target_zone == zone.name or rule.zone == 'all'
    
def split_out_internet_rules(rule_list):
    """Separate rules targeting the Internet versus normal rules"""
    normal_rules = filter(lambda x: x.target_zone != 'internet', rule_list)
    internet_rules = filter(lambda x: x.target_zone == 'internet', rule_list)
    return list(normal_rules), list(internet_rules)
    
def make_concrete_rule(rule_no, zone_map, direction, zone, rule, concrete_port):
    """Take a rule and create a corresponding concrete rule."""

    def make_rule(target_zone, port):
        return ConcreteRule(source_rules=[rule], rule_no=rule_no, target_zone=target_zone,
                            direction=direction, port=port, action="allow")

    target_zone = zone_map[rule.target_zone]

    # Rule level ephemerality overrides zone level
    if '+ephemeral_strict' in rule.tags:
        ephem_start = 32768
    elif '+ephemeral_loose' in rule.tags:
        ephem_start = 1024
    elif rule.direction == '>' and '+ephemeral_strict' in zone.tags and direction == 'ingress':
        # An internal network with systems that use a tight ephemeral port range
        ephem_start = 32768
    else:
        ephem_start = 1024

    if concrete_port.proto == 'all':
        # ISSUE: We should *maybe* prevent rules with the "all" protocol from being
        # concretized. Because of the nature of "all" rules you can't restrict the 
        # return traffic at all. Really, this should be a policy level error?
        return_port = ConcretePort(proto=concrete_port.proto, from_port=0, to_port=0)
    else:
        return_port = ConcretePort(proto=concrete_port.proto, from_port=ephem_start, to_port=65535)

    if direction == 'ingress':
        if rule.direction == '>':
            if rule.zone == zone.name or rule.zone == 'all': # a > b (return traffic)
                return make_rule(target_zone=rule.target_zone, port=return_port)
            elif rule.target_zone == zone.name: # b > a (forward traffic)
                return make_rule(target_zone=rule.zone, port=concrete_port)
        else: # '<'
            if rule.zone == zone.name: # a < b (forward traffic)
                return make_rule(target_zone=rule.target_zone, port=concrete_port)
            elif rule.target_zone == zone.name: # b < a 
                raise NotImplementedError("Receiving traffic from internal zone?")
    else:  # egress
        if rule.direction == '>':
            if rule.zone == zone.name or rule.zone == 'all': # a > b (forward traffic)
                return make_rule(target_zone=rule.target_zone, port=concrete_port)
            elif rule.target_zone == zone.name: # b > a (return traffic)
                return make_rule(target_zone=rule.zone, port=return_port)
        else: # '<'
            if rule.zone == zone.name: # a < b (return traffic)
                return make_rule(target_zone=rule.target_zone, port=return_port)
            elif rule.target_zone == zone.name: # b < a
                raise NotImplementedError("Receiving traffic from internal zone?")

    raise AssertionError("should not reach here")

def generate_concrete_policy(policy_impl):
    """Take a Policy and generate a ConcretePolicy.
    
    This is done by taking each zone in turn, and:

    * Generating "self traffic rules" (allow ingress/egress between subnets in same zone)
    * Filtering the list of abstract rules to find the rules which affect the current zone
    * Iterating over all normal (non-internet) rules and generating concrete rules
    * If there are Internet rules, adding a VPC block rule
    * Iterating over all the Internet rules and generating concrete rules
    """
    cp = ConcretePolicy(zones={})
    for _, zone in policy_impl.zones.items():
        # We only generate rules for "internal" zones, aka, zones we control
        if zone.int_or_ext == 'external':
            continue
        czone = ConcreteZone(name=zone.name, source_zone=zone)
        cp.zones[czone.name] = czone

        # Used for self-rules and 'any' rules
        all_traffic = ConcretePort(proto='all', from_port=0, to_port=0)
    
        # Add implicit self rules (ingress and egress)
        self_rule = synthetic_rule(zone.name, '<>', zone.name, ['self_traffic'])
        for dir_ in ['ingress', 'egress']:
            czone.rules.append(
                ConcreteRule(source_rules=[self_rule], rule_no=50, 
                             target_zone=zone.name, direction=dir_, port=all_traffic, action="allow"))
        
        # Add zone-targeted rules. 
        for ingress_or_egress in ['ingress', 'egress']:
            rule_no = 100
            seen = []

            def concrete_rule_is_equiv(r1, r2):
                """Compare 2 rules, ignoring rule number and source_rules 
                (for dup suppression)"""
                return r1.target_zone == r2.target_zone and \
                       r1.port.proto == r2.port.proto and \
                       r1.port.from_port == r2.port.from_port and \
                       r1.port.to_port == r2.port.to_port and \
                       r1.direction == r2.direction and \
                       r1.action == r2.action
            
            def find_equiv_rule(haystack, needle):
                """Check haystack (a list of rules) for a rule which matches
                the 'needle' (a concrete rule)."""
                for r in haystack:
                    if concrete_rule_is_equiv(r, needle):
                        return r
                return None

            def add_to_zone(concrete_rule):
                nonlocal rule_no
                if concrete_rule is None: # No rule was actually generated
                    return

                # If we *did* get a concrete rule, have we already seen it 
                # for this zone?  This mainly suppresses duplicate return rules
                equiv_rule = find_equiv_rule(czone.rules, concrete_rule)
                if equiv_rule is not None:
                    # The concrete_rule has not been coalesced yet, so must come from 
                    # exactly one source rule. That's why we use source_rules[0] here.
                    if concrete_rule.source_rules[0] not in equiv_rule.source_rules:
                        equiv_rule.source_rules.append(concrete_rule.source_rules[0])
                    return

                # OK, it looks unique, let's add it to the concrete ruleset
                czone.rules.append(concrete_rule)
                rule_no += 100

            def process_rules(rule_list):
                for rule in rule_list:
                    for service_name in rule.service_list:
                        if 'any' in rule.service_list:
                            # 'any' rules allow all traffic
                            cr = make_concrete_rule(rule_no, policy_impl.zones, ingress_or_egress, zone,
                                                    rule, all_traffic)
                            add_to_zone(cr)
                        else:
                            service = policy_impl.services[service_name]
                            for p in service.ports:
                                cport = ConcretePort(proto=p.proto, from_port=p.port,
                                                  to_port=p.port)
                                cr = make_concrete_rule(rule_no, policy_impl.zones, ingress_or_egress,
                                                        zone, rule, cport)
                                add_to_zone(cr)

            # Filter ruleset to find rules affecting this zone, then split
            # into regular and Internet rules
            applicable_rules = list(filter(lambda r: rule_affects_zone(zone, r), policy_impl.rules))
            normal_rules, internet_rules = split_out_internet_rules(applicable_rules)

            # Concretize regular rules
            process_rules(normal_rules)
            if len(internet_rules) > 0:
                # Generate synthetic block rules to prevent unwanted vpc traffic
                # to internet exposed services
                block_vpc_rule = synthetic_rule(zone.name, '!', 'vpc', ['any'])
                cr_block = ConcreteRule(source_rules=[block_vpc_rule], rule_no=rule_no,
                                        target_zone='vpc', direction=ingress_or_egress,
                                        port=all_traffic, action="deny")
                add_to_zone(cr_block)
                # Now concretize the Internet rules
                process_rules(internet_rules)
    return cp

###
# Terraform output
###

def render_tf_file_header():
    hdr = """
    ########
    # NACLGEN GENERATED POLICY, DO NOT EDIT
    # See: https://github.com/bsycorp/naclgen
    # Generated: {}
    ########
    """.format(datetime.datetime.now().isoformat())
    return "\n".join([s.lstrip() for s in hdr.splitlines()])

def render_tf_zone_header(concrete_zone):
    if '+single_az' in concrete_zone.source_zone.tags:
        return render_tf_singlezone_header(concrete_zone.name)
    else:
        return render_tf_multizone_header(concrete_zone.name)

def render_tf_multizone_header(zone_name):
    return """
    resource "aws_network_acl" "{0}" {{
      vpc_id = "${{local.naclgen_vpc_id}}"
      subnet_ids = [
        "${{lookup(local.naclgen_subnets["ids"], "{0}_a")}}",
        "${{lookup(local.naclgen_subnets["ids"], "{0}_b")}}",
        "${{lookup(local.naclgen_subnets["ids"], "{0}_c")}}",
      ]""".format(zone_name)

def render_tf_singlezone_header(zone_name):
    return """
    resource "aws_network_acl" "{0}" {{
      vpc_id = "${{local.naclgen_vpc_id}}"
      subnet_ids = [
        "${{lookup(local.naclgen_subnets["ids"], "{0}")}}",
      ]""".format(zone_name)

def render_tf_zone_footer(concrete_zone):
    return """

      tags = {{
        Name = "{0}.${{local.naclgen_acl_label}}"
      }}
    }}
    """.format(concrete_zone.name)

def render_tf_rule(ingress_or_egress, rule):
    # Format the rule comments (references to abstract rules)
    rule_comment_fmt = "      # {0}"
    rule_comments = [rule_comment_fmt.format(src_rule) for src_rule in rule.source_rules]
    r = "\n\n" + "\n".join(rule_comments)

    # Format the cidr_block lookup
    if rule.target_zone == 'internet':
        cidr_lookup = "0.0.0.0/0"
    else:
        cidr_lookup = '${{lookup(local.naclgen_subnets["cidrs"], "{0}")}}'.format(rule.target_zone)

    return r + """
      {0} {{
        protocol   = "{1.port.proto}"
        rule_no    = {1.rule_no}
        action     = "{1.action}"
        cidr_block = "{2}"
        from_port  = {1.port.from_port}
        to_port    = {1.port.to_port}
      }}""".format(ingress_or_egress, rule, cidr_lookup)

def generate_terraform(concrete_policy):
    s = render_tf_file_header()
    # Sort here to get a stable order, reduces diff churn
    concrete_zones = sorted([x for _, x in concrete_policy.zones.items()], 
                            key=lambda x: x.name)
    for z in concrete_zones:
        s += render_tf_zone_header(z)
        for r in z.ingress_rules:
            s += render_tf_rule('ingress', r)
        for r in z.egress_rules:
            s += render_tf_rule('egress', r)
        s += render_tf_zone_footer(z)
    return s

def load_policy(f):
    lines = open(f).read().splitlines()
    p = validate_policy(parse_policy(f, lines))
    return p

def main(impl_file, policy_file):
    impl = load_policy(impl_file)
    if policy_file is not None:
        policy = load_policy(policy_file)
        validate_policy_vs_impl(policy, impl)
    concrete_policy = generate_concrete_policy(impl)
    print(generate_terraform(concrete_policy))

if __name__ == '__main__':
    if len(sys.argv) == 2:
        main(sys.argv[1], None)
    elif len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    else:
        print("Usage: naclgen.py <impl-file> [policy-file]")
        sys.exit(1)
        
