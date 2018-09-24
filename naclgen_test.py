#!/usr/bin/env python3

import unittest
import pprint
from naclgen import *

class TestHelpers(unittest.TestCase):
    def test_stripping(self):
        """Test stripping of comments"""
        self.assertEqual(strip_comments(""), "")
        self.assertEqual(strip_comments("foo # foo the thing"), "foo ")
        self.assertEqual(strip_comments("bar baz"), "bar baz")

    def test_validate_name(self):
        """Test name validation"""
        with self.assertRaises(ValueError):
            validate_name("1something")
        with self.assertRaises(ValueError):
            validate_name("!")
        self.assertEqual(validate_name("fred"), "fred")
        
    def test_validate_zone_tag(self):
        """Test zone tag validation"""
        with self.assertRaises(ValueError):
            validate_zone_tag('fred')
        with self.assertRaises(ValueError):
            validate_zone_tag('+fred')
        self.assertEqual(validate_zone_tag('+ephemeral_strict'), '+ephemeral_strict')

    def test_validate_rule_tag(self):
        """Test rule tag validation"""
        with self.assertRaises(ValueError):
            validate_zone_tag('fred')
        with self.assertRaises(ValueError):
            validate_zone_tag('+fred')
        self.assertEqual(validate_rule_tag('+ephemeral_strict'), '+ephemeral_strict')
    
    def test_validate_port_number(self):
        """Test port number validation"""
        with self.assertRaises(ValueError):
            validate_port_number("65536")
        with self.assertRaises(ValueError):
            validate_port_number("ice cream")
        with self.assertRaises(ValueError):
            validate_port_number(-1)
        self.assertEqual(validate_port_number("22"), 22)

    def test_new_port(self):
        """Test proto/port validation"""
        self.assertEqual(new_port("22/tcp"), Port(port=22, proto="tcp"))
        self.assertEqual(new_port("53/udp"), Port(port=53, proto="udp"))
        with self.assertRaises(ValueError):
            new_port('')
        with self.assertRaises(ValueError):
            new_port("fuuuuu")
        with self.assertRaises(ValueError):
            new_port("22/whut")
        with self.assertRaises(ValueError):
            new_port("foo/tcp")
        with self.assertRaises(ValueError):
            new_port('22/')
        with self.assertRaises(ValueError):
            new_port('/')

    def test_new_rule_direction(self):
        """Test validation of direction in new rules"""
        with self.assertRaisesRegexp(ValueError, 'unexpected rule direction: foo'):
            r = new_rule('a', 'foo', 'b', ['dns', 'https'])

class TestPolicies(unittest.TestCase):
    def test_service(self):
        """Test service creation in policy definition"""
        case = ['service dns 53/tcp 53/udp']
        p = parse_policy('test', case)
        expected = new_policy('test')
        s = new_service('dns', ["53/tcp", "53/udp"])
        expected.services[s.name] = s
        self.assertEqual(p.services, expected.services)
        
    def test_zone(self):
        """Test zone creation in policy definition"""
        case = ['zone management internal']
        p = parse_policy('test', case)
        expected = new_policy('test')
        s = new_zone('management', 'internal', [])
        expected.zones[s.name] = s
        self.assertEqual(p.zones['management'], expected.zones['management'])
    
    def test_reserved_zone(self):
        """Test that creating a zone with a reserved name is an error"""
        with self.assertRaisesRegex(ValueError, 'tried to declare reserved zone name:'):
            new_zone('internet', 'external', [])
        with self.assertRaisesRegex(ValueError, 'tried to declare reserved zone name:'):
            new_zone('all', 'internal', [])
    
    def test_zone_tags(self):
        """Test zone tags in policy definitions"""
        case = ['zone dmz internal +ephemeral_strict']
        p = parse_policy('test', case)
        expected = new_policy('test')
        s = new_zone('dmz', 'internal', ['+ephemeral_strict'])
        expected.zones[s.name] = s
        self.assertEqual(p.zones['dmz'], expected.zones['dmz'])

    def test_invalid_zone_tags(self):
        """Test that unknown zone tags produce an error"""
        with self.assertRaisesRegexp(ValueError, 'invalid zone tag:'):
            case = ['zone dmz internal +unknown_tag']
            p = parse_policy('test', case)

        
    def test_parse_error_unknown_directive(self):
        """Test that unknown directives are an error in policy definition"""
        case = ['klaatu barada nikto']
        with self.assertRaisesRegex(ValueError, 'failed to parse:'):
            p = parse_policy('test', case)
            
    def test_parse_error_in_rule_block(self):
        """Test that policy errors inside a rule block throw an error"""
        case = '''
        zone a internal
        zone b internal
        rule a {
          ] b   # Direction is wrong
        }
        '''.splitlines()
        with self.assertRaisesRegex(ValueError, "in rule block, failed to parse:"):
            p = parse_policy('test', case)

    def test_a_rule(self):
        """Test rule creation in policy definition"""
        case = """
        rule management {
          < twilight_zone
          > cal_zone dns https
        }
        """.splitlines()
        p = parse_policy("test", case)
        r1 = new_rule('management', '<', 'twilight_zone', ['any'])
        r2 = new_rule('management', '>', 'cal_zone', ['dns', 'https'])
        self.assertEqual(len(p.rules), 2)
        self.assertEqual(p.rules[0], r1)
                
    def test_validate_policy_happy_path(self):
        """Test the happy path for policy validation"""
        case = """
            service dns 53/tcp
            service https 443/tcp
            zone a internal
            zone b internal
            zone c external
            rule all {
              > c dns
            }
            rule a {
              > b https
            }        
        """.splitlines()
        validate_policy(parse_policy("case", case))

    def test_validate_policy_invalid_service(self):
        """Referencing an unknown service in a rule is an error"""
        case = """
            service dns 53/tcp
            service https 443/tcp
            zone a internal
            zone b internal
            zone c external
            rule all {
              > c dns
            }
            rule a {
              > b whut
            }        
        """.splitlines()
        p = parse_policy("case", case)
        with self.assertRaisesRegex(AssertionError, 'unknown service name'):
            validate_policy(p)

    def test_validate_policy_unknown_zone_source(self):
        """Referencing an unknown zone in rule source is an error"""
        case = """
            zone a internal
            zone b internal 
            rule c {
              > a
            }
        """.splitlines()
        p = parse_policy("case", case)
        with self.assertRaisesRegex(AssertionError, 'unknown zone in source'):
            validate_policy(p)

    def test_validate_policy_unknown_zone_target(self):
        """Referencing an unknown zone in a rule target is an error"""
        case = """
            zone a internal
            zone b internal 
            rule a {
              > c
            }            
        """.splitlines()
        p = parse_policy("case", case)
        with self.assertRaisesRegex(AssertionError, 'unknown zone in target'):
            validate_policy(p)
        
    def test_validate_policy_rules_on_external_zone(self):
        """Defining a rule on an external zone is an error"""
        case = """
            zone a internal
            zone b internal
            zone c external
            rule a {
               > c
            }
            rule c {
               > b
            }
        """.splitlines()
        p = parse_policy("case", case)
        with self.assertRaisesRegex(AssertionError, 'cannot define rules on external zone'):
            validate_policy(p)

    def test_validate_policy_traffic_positive(self):
        """Receiving traffic (with <) from an internal zone is an error"""
        case = """
            zone a internal
            zone b internal
            rule a {
               < b
            }
        """.splitlines()
        p = parse_policy("case", case)
        with self.assertRaisesRegex(AssertionError, 'cannot receive traffic from internal zone: b'):
            validate_policy(p)

class TestPolicyVersusImplEnforcement(unittest.TestCase):
    def test_impl_zone_not_in_policy(self):
        """Policy implementation referring to a zone not in the policy is an error"""
        policy = validate_policy(parse_policy('p', []))
        policy_impl = parse_policy('i', ['zone a internal'])
        with self.assertRaisesRegex(AssertionError, 'zone a not defined in policy'):
            validate_policy_vs_impl(policy, policy_impl)
        
    def test_impl_zone_differs_from_policy_zone(self):
        """Policy implementation must define a zone in exactly the same way as policy"""
        policy = validate_policy(parse_policy('p', ['zone a internal']))
        policy_impl = parse_policy('i', ['zone a external'])
        with self.assertRaisesRegex(AssertionError, 'zone a differs between impl and policy'):
            validate_policy_vs_impl(policy, policy_impl)

    def test_impl_service_differs_from_policy(self):
        """Policy implementation must define a service in exactly the same way as policy"""
        policy = validate_policy(parse_policy('p', ['service stuff 53/tcp 22/tcp']))
        policy_impl = parse_policy('i', ['service stuff 53/tcp'])
        with self.assertRaisesRegex(AssertionError, 'service definition "stuff" differs from policy'):
            validate_policy_vs_impl(policy, policy_impl)

    def test_rules_are_compatible(self):
        """Test rule compatibility for policy validation"""
        # Everything the same, yup
        self.assertTrue(rules_are_compatible(
            new_rule('management', '>', 'twilight_zone', ['foo']),
            new_rule('management', '>', 'twilight_zone', ['foo'])
        ))
        # Ensure that we match 'all' rules as compatible too
        self.assertTrue(rules_are_compatible(
            new_rule('all', '>', 'twilight_zone', ['foo']),
            new_rule('management', '>', 'twilight_zone', ['foo'])        
        ))
        # Otherwise, different source zones not compat
        self.assertFalse(rules_are_compatible(
            new_rule('other_zone', '>', 'twilight_zone', ['any']),
            new_rule('management', '>', 'twilight_zone', ['any'])        
        ))
        # Different directions not compat
        self.assertFalse(rules_are_compatible(
            new_rule('management', '>', 'twilight_zone', ['any']),
            new_rule('management', '<', 'twilight_zone', ['any'])
        ))
        # Different directions still not compat
        self.assertFalse(rules_are_compatible(
            new_rule('all', '>', 'twilight_zone', ['any']),
            new_rule('management', '<', 'twilight_zone', ['any'])
        ))
        # Different targets not compat
        self.assertFalse(rules_are_compatible(
            new_rule('management', '>', 'other_zone', ['any']),
            new_rule('management', '>', 'twilight_zone', ['any'])
        ))
        
    def test_validate_policy_allows_impl_rule(self):
        """Test policy enforcement of implementation rules"""
        policy_rules = [
            new_rule('all', '>', 'c', ['any']),
            new_rule('a', '>', 'b', ['dns']),
            new_rule('a', '>', 'b', ['http']),
            new_rule('a', '>', 'x', ['any'])            
        ]
        # Should be allowed, 2 rules in policy, taken together, allow this 1 rule
        impl_rule1 = new_rule('a', '>', 'b', ['dns', 'http'])
        validate_policy_allows_impl_rule(policy_rules, impl_rule1)  # No raise
        # Should raise, no https from a > b
        impl_rule2 = new_rule('a', '>', 'b', ['dns', 'http', 'https'])
        with self.assertRaisesRegex(AssertionError, 'services blocked by policy:'):
            validate_policy_allows_impl_rule(policy_rules, impl_rule2)
        # Should be allowed, any from a > x
        impl_rule3 = new_rule('a', '>', 'x', ['dns', 'https', 'rpc'])
        validate_policy_allows_impl_rule(policy_rules, impl_rule3)
        # Should be allowed, any from all > c
        impl_rule4 = new_rule('a', '>', 'c', ['dns'])
        validate_policy_allows_impl_rule(policy_rules, impl_rule4)            
        
    def test_validate_policy_vs_impl_happy(self):
        """Test the happy path for policy enforcement"""
        policy = validate_policy(parse_policy('p', """
            zone a internal
            zone b internal
            rule a {
              > b
            }
        """.splitlines()))
        
        policy_impl = validate_policy(parse_policy('i', """
            zone a internal
            zone b internal
            service dns 53/udp 53/tcp
            rule a {
              > b dns
            }
        """.splitlines()))
        
        # Totally valid, should not raise
        validate_policy_vs_impl(policy, policy_impl) 
    
    def test_validate_policy_vs_impl_sad(self):
        """Test the sad path for policy enforcement"""
        policy = validate_policy(parse_policy('p', """
            zone a internal
            zone b internal
            service dns 53/udp 53/tcp
            service http 80/tcp
            service https 443/tcp
            rule a {
              > b dns
            }
            rule b {
              > a https
            }
        """.splitlines()))
        policy_impl = validate_policy(parse_policy('i', """
            zone a internal
            zone b internal
            service dns 53/udp 53/tcp
            service http 80/tcp
            service https 443/tcp
            rule a {
              > b dns
            }
            rule b {
              > a http  # will be blocked by policy (http not https)
            }
        """.splitlines()))
        with self.assertRaisesRegex(AssertionError, 'services blocked by policy:'):
            validate_policy_vs_impl(policy, policy_impl) 

class TestConcretization(unittest.TestCase):
    def test_trivial(self):
        """Test implicit rules in a ruleset (aka self-traffic rules)"""
        case = """
            zone a internal
            zone b internal
        """.splitlines()
        policy = validate_policy(parse_policy("case", case))
        self.assertEqual(len(policy.rules), 0)
        concrete_policy = generate_concrete_policy(policy)

        # Even with no rules, we need implicit self-rules between AZs for each zone
        a_z = concrete_policy.zones['a']
        b_z = concrete_policy.zones['b']

        zr = a_z.ingress_rules
        self.assertEqual(len(zr), 1)  # Expect 1 self-rule
        self.assertEqual(zr[0].rule_no, 50)
        self.assertEqual(zr[0].target_zone, "a")
        self.assertEqual(zr[0].port.proto, "all")
        self.assertEqual(zr[0].port.from_port, 0)
        self.assertEqual(zr[0].port.to_port, 0)        

        zr = a_z.egress_rules
        self.assertEqual(len(zr), 1)  # Expect 1 self-rule
        self.assertEqual(zr[0].rule_no, 50)
        self.assertEqual(zr[0].target_zone, "a")
        self.assertEqual(zr[0].port.proto, "all")
        self.assertEqual(zr[0].port.from_port, 0)
        self.assertEqual(zr[0].port.to_port, 0)        

        zr = b_z.ingress_rules
        self.assertEqual(len(zr), 1)  # Expect 1 self-rule
        self.assertEqual(zr[0].rule_no, 50)
        self.assertEqual(zr[0].target_zone, "b")
        self.assertEqual(zr[0].port.proto, "all")
        self.assertEqual(zr[0].port.from_port, 0)
        self.assertEqual(zr[0].port.to_port, 0)        

        zr = b_z.egress_rules
        self.assertEqual(len(zr), 1)  # Expect 1 self-rule
        self.assertEqual(zr[0].rule_no, 50)
        self.assertEqual(zr[0].target_zone, "b")
        self.assertEqual(zr[0].port.proto, "all")
        self.assertEqual(zr[0].port.from_port, 0)
        self.assertEqual(zr[0].port.to_port, 0)        

    def test_a_to_b(self):
        """Test concretization of a trivial policy from a > b"""
        case = """
            zone a internal
            zone b internal
        rule a {
          > b 
        }
        """.splitlines()
        policy = validate_policy(parse_policy("case", case))
        self.assertEqual(len(policy.rules), 1)  
        source_rule = policy.rules[0]
        concrete_policy = generate_concrete_policy(policy)

        # A ingress
        a_ing_rules = concrete_policy.zones['a'].ingress_rules[1:]
        self.assertEqual(len(a_ing_rules), 1)
        expected_a_ing = ConcreteRule(source_rules=[source_rule], rule_no=100, target_zone="b", direction='ingress', 
                                      port=ConcretePort(proto="all", from_port=0, to_port=0), action="allow")
        self.assertEqual(a_ing_rules[0], expected_a_ing)

        # A egress
        a_egr_rules = concrete_policy.zones['a'].egress_rules[1:]
        self.assertEqual(len(a_egr_rules), 1)
        expected_a_egr = ConcreteRule(source_rules=[source_rule], rule_no=100, target_zone="b", direction='egress', 
                                      port=ConcretePort(proto="all", from_port=0, to_port=0), action="allow")
        self.assertEqual(a_egr_rules[0], expected_a_egr)

        # B ingress 
        b_ing_rules = concrete_policy.zones['b'].ingress_rules[1:]
        self.assertEqual(len(b_ing_rules), 1)
        expected_b_ing = ConcreteRule(source_rules=[source_rule], rule_no=100, target_zone="a", direction='ingress', 
                                      port=ConcretePort(proto="all", from_port=0, to_port=0), action="allow")
        self.assertEqual(b_ing_rules[0], expected_b_ing)

        # B egress
        b_egr_rules = concrete_policy.zones['b'].egress_rules[1:]
        self.assertEqual(len(b_egr_rules), 1)
        expected_b_egr = ConcreteRule(source_rules=[source_rule], rule_no=100, target_zone="a", direction='egress', 
                                      port=ConcretePort(proto="all", from_port=0, to_port=0), action="allow")
        self.assertEqual(b_egr_rules[0], expected_b_egr)

    def test_all_rules(self):
        """Test that rules are correctly generated on the 'all' zone"""
        case = """
        service dns 53/tcp 53/udp
        zone a internal
        zone b internal
        zone c external
        rule all {
          > c dns
        }
        """.splitlines()
        policy = validate_policy(parse_policy("case", case))
        self.assertEqual(len(policy.rules), 1)
        concrete_policy = generate_concrete_policy(policy)
        
        # Check the non-self rules. 
        a_ingress = concrete_policy.zones['a'].ingress_rules[1:]
        a_egress  = concrete_policy.zones['a'].egress_rules[1:]
        b_ingress = concrete_policy.zones['b'].ingress_rules[1:]
        b_egress  = concrete_policy.zones['b'].egress_rules[1:]
        
        # Expect 2 rules in each chain to have been added for DNS (1 for tcp, 1 for udp)
        self.assertEqual(len(a_ingress), 2)   # return traffic c -> a
        self.assertEqual(len(a_egress), 2)    # outbound a -> c
        self.assertEqual(len(b_ingress), 2)   # return traffic c -> b
        self.assertEqual(len(b_egress), 2)    # outbound b -> c

    def test_return_traffic_rules(self):
        """Test that multiple (identical) return traffic rules get coalesced"""
        case1 = """
            service http 80/tcp
            service https 443/tcp
            zone a internal
            zone b internal
        rule a {
          > b http
          > b https
        }
        """.splitlines()
        policy1 = validate_policy(parse_policy("case", case1))
        self.assertEqual(len(policy1.rules), 2)
        concrete_policy1 = generate_concrete_policy(policy1)
                
        # Check the non-self rules.
        a_ingress = concrete_policy1.zones['a'].ingress_rules[1:]
        a_egress  = concrete_policy1.zones['a'].egress_rules[1:]
        b_ingress = concrete_policy1.zones['b'].ingress_rules[1:]
        b_egress  = concrete_policy1.zones['b'].egress_rules[1:]
        
        # We expect:
        # 2 rules egressing from a (matching the 2 ports)
        # 2 rules ingressing on b (matching the 2 ports)
        # 1 rule ingressing on a (return traffic for both ports)
        # 1 rule egressing on b (return traffic for both ports)
        # The return traffic rules get coalesced
        self.assertEqual(len(a_ingress), 1)
        self.assertEqual(len(a_egress), 2)
        self.assertEqual(len(b_ingress), 2)
        self.assertEqual(len(b_egress), 1)  

    def test_internet_rules(self):
        """Verify that 'internet' rules get concretized properly"""
        case = """
            service http 80/tcp
            service https 443/tcp
            zone a internal
            rule a {
                < internet http https
            }
        """.splitlines()
        policy = validate_policy(parse_policy("case", case))
        self.assertEqual(len(policy.rules), 1)
        concrete_policy = generate_concrete_policy(policy)

        # Expect in zone a:
        # * 2 self rules (1 egress, 1 ingress)
        # * 2 vpc block rules (1 egress, 1 ingress) due to Internet rules
        # * 3 generated rules (2 ingress, 1 egress for return traffic)
        zone_a = concrete_policy.zones['a']
        self.assertEqual(len(zone_a.rules), 2 + 2 + 3)

        # TODO: check the block rules exactly
        
    def test_ephemeral_loose_internet_rule(self):
        """Test that the +ephemeral_strict rule tag is concretized properly for internet"""
        case = """
            service https 443/tcp
            zone a internal +ephemeral_strict
            rule a {
                > internet https
                < internet https
            }
        """.splitlines()
        policy = validate_policy(parse_policy("case", case))
        self.assertEqual(len(policy.rules), 2)
        concrete_policy = generate_concrete_policy(policy)

        # Expect in zone a:
        # * 2 self rules (1 egress, 1 ingress)
        # * 2 vpc block rules (1 egress, 1 ingress) due to the presence
        #   of Internet rules
        # * 2 internet ingress rules (ephemeral + https)
        # * 2 internet egress rules (ephemeral + https)

        a_ingr = concrete_policy.zones['a'].ingress_rules
        a_egr = concrete_policy.zones['a'].egress_rules
        
        self.assertEqual(len(a_ingr), 4)
        self.assertEqual(len(a_egr), 4)

        # Check for the drop rules
        self.assertEqual(a_ingr[1].target_zone, 'vpc')
        self.assertEqual(a_ingr[1].port.proto, 'all')
        self.assertEqual(a_ingr[1].action, 'deny')
        self.assertEqual(a_egr[1].target_zone, 'vpc')
        self.assertEqual(a_egr[1].port.proto, 'all')
        self.assertEqual(a_egr[1].action, 'deny')
        
        # Check the ingress rules
        # For Zone A, ingress should be strict since zone uses strict ephemeral ports
        self.assertEqual(a_ingr[2].port, ConcretePort(proto='tcp', from_port=32768, to_port=65535))
        self.assertEqual(a_ingr[2].action, 'allow')
    
        self.assertEqual(a_ingr[3].port, ConcretePort(proto='tcp', from_port=443, to_port=443))
        self.assertEqual(a_ingr[3].action, 'allow')
        
        # Check the egress rules
        self.assertEqual(a_egr[2].port, ConcretePort(proto='tcp', from_port=443, to_port=443))
        self.assertEqual(a_egr[2].action, 'allow')
        # For Zone A, egress should be loose since Internet uses loose ephemeral ports.
        self.assertEqual(a_egr[3].port, ConcretePort(proto='tcp', from_port=1024, to_port=65535))
        self.assertEqual(a_egr[3].action, 'allow')

    def test_ephemeral_loose_rule(self):
        """Test that the +ephemeral_strict rule tag is concretized properly for internal"""
        case = """
            service https 443/tcp
            zone a internal
            zone b internal +ephemeral_strict
            rule a {
                > b https
            }
        """.splitlines()
        policy = validate_policy(parse_policy("case", case))
        self.assertEqual(len(policy.rules), 1)
        concrete_policy = generate_concrete_policy(policy)

        # Expect in zone a:
        # * 2 self rules (1 egress, 1 ingress)
        # * 1 loose egress rule

        a_ingr = concrete_policy.zones['a'].ingress_rules
        a_egr = concrete_policy.zones['a'].egress_rules

        self.assertEqual(len(a_ingr), 2)
        self.assertEqual(len(a_egr), 2)

        print(generate_terraform(concrete_policy))

        # A: Check the ingress rules
        self.assertEqual(a_ingr[1].port, ConcretePort(proto='tcp', from_port=1024, to_port=65535))
        self.assertEqual(a_ingr[1].action, 'allow')
        
        # A: Check the egress rules
        self.assertEqual(a_egr[1].port, ConcretePort(proto='tcp', from_port=443, to_port=443))
        self.assertEqual(a_egr[1].action, 'allow')

        b_ingr = concrete_policy.zones['b'].ingress_rules
        b_egr = concrete_policy.zones['b'].egress_rules
        
        self.assertEqual(len(b_ingr), 2)
        self.assertEqual(len(b_egr), 2)        

        # B: Check the ingress rules
        self.assertEqual(b_ingr[1].port, ConcretePort(proto='tcp', from_port=443, to_port=443))
        self.assertEqual(b_ingr[1].action, 'allow')
    
        # B: Check the egress rules
        self.assertEqual(b_egr[1].port, ConcretePort(proto='tcp', from_port=1024, to_port=65535))
        self.assertEqual(b_egr[1].action, 'allow')
