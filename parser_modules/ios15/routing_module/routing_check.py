from parser_modules.ios15.routing_module import routing_parsers


def compliance_check_routing(connection, global_report_output):

    match routing_parsers.compliance_check_dynamic_routing_tester(connection, "show running-config | include router"):

        case {'EIGRP':False, 'OSPF':False, 'RIP':False, 'BGP':False}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_no_rip(global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)
            
        case {'EIGRP':False, 'OSPF':False, 'RIP':False, 'BGP':True}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_no_rip(global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)
            
        case {'EIGRP':False, 'OSPF':False, 'RIP':True, 'BGP':False}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 2, global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)   
            
        case {'EIGRP':False, 'OSPF':False, 'RIP':True, 'BGP':True}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 2, global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)
            
        case {'EIGRP':False, 'OSPF':True, 'RIP':False, 'BGP':False}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_no_rip(global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)

        case {'EIGRP':False, 'OSPF':True, 'RIP':False, 'BGP':True}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_no_rip(global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)
        
        case {'EIGRP':False, 'OSPF':True, 'RIP':True, 'BGP':False}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 2, global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)

        case {'EIGRP':False, 'OSPF':True, 'RIP':True, 'BGP':True}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 2, global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)

        case {'EIGRP':True, 'OSPF':False, 'RIP':False, 'BGP':False}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_no_rip(global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)
        
        case {'EIGRP':True, 'OSPF':False, 'RIP':False, 'BGP':True}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_no_rip(global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)
            
        case {'EIGRP':True, 'OSPF':False, 'RIP':True, 'BGP':False}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 2, global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)

        case {'EIGRP':True, 'OSPF':False, 'RIP':True, 'BGP':True}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 2, global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)
        
        case {'EIGRP':True, 'OSPF':True, 'RIP':False, 'BGP':False}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_no_rip(global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)
        
        case {'EIGRP':True, 'OSPF':True, 'RIP':False, 'BGP':True}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_no_rip(global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)
            
        case {'EIGRP':True, 'OSPF':True, 'RIP':True, 'BGP':False}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 2, global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)

        case {'EIGRP':True, 'OSPF':True, 'RIP':True, 'BGP':True}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 2, global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)