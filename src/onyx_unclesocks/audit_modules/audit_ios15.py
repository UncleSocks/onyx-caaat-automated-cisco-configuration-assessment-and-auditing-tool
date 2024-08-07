import time
from parser_modules.ios15 import aaa_parsers, general_parsers, line_parsers, logging_parsers, \
    ntp_parsers, routing_parsers, services_parsers, snmp_parsers, ssh_parsers, users_parsers, border_parsers


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
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 
                                                 "show running-config | section interface", 2, global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)   
            
        case {'EIGRP':False, 'OSPF':False, 'RIP':True, 'BGP':True}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 
                                                 "show running-config | section interface", 2, global_report_output)
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
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 
                                                 "show running-config | section interface", 2, global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)

        case {'EIGRP':False, 'OSPF':True, 'RIP':True, 'BGP':True}:
            routing_parsers.compliance_check_no_eigrp(global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 
                                                 "show running-config | section interface", 2, global_report_output)
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
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 
                                                 "show running-config | section interface", 2, global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)

        case {'EIGRP':True, 'OSPF':False, 'RIP':True, 'BGP':True}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_no_ospf(global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 
                                                 "show running-config | section interface", 2, global_report_output)
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
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 
                                                 "show running-config | section interface", 2, global_report_output)
            routing_parsers.compliance_check_no_bgp(global_report_output)

        case {'EIGRP':True, 'OSPF':True, 'RIP':True, 'BGP':True}:
            routing_parsers.compliance_check_eigrp(connection, "show running-config | section key chain", 
                                                    "show running-config | section router eigrp", 2, global_report_output)
            routing_parsers.compliance_check_ospf(connection, "show running-config | section router ospf", 
                                                  "show running-config | section interface",2, global_report_output)
            routing_parsers.compliance_check_rip(connection, "show running-config | section key chain", 
                                                 "show running-config | section interface", 2, global_report_output)
            routing_parsers.compliance_check_bgp(connection, "show running-config | section router bgp", 
                                                "3.3.4.1 Set 'neighbor password'", 2, global_report_output)


def run_cis_cisco_ios_15_assessment(connection):

    start_time = time.time()
    global_report_output = []

    #1 Management Plane CIS Compliance Checks
    print("Performing CIS Cisco IOS 15 Management Plane Benchmarks assessment.")

    general_parsers.compliance_check_without_no_prefix(connection, "show running-config | include aaa new-model", "1.1.1 Enable 'aaa new-model'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication login", "1.1.2 Enable 'aaa authentication login'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication enable","1.1.3 Enable 'aaa authentication enable default'", 1, global_report_output)
    aaa_parsers.compliance_check_aaa_auth_line_con(connection, "show running-config | section con | include login authentication", "1.1.4 Set 'login authentication for 'line con 0'", 1, global_report_output)
    aaa_parsers.compliance_check_aaa_auth_line_tty(connection, "show line", "show running-config | section tty | include login authentication", "1.1.5 Set 'login authentication for 'line tty'", 1, global_report_output)
    aaa_parsers.compliance_check_aaa_auth_line_vty(connection, "show running-config | section vty | include login authentication", "1.1.6 Set 'login authentication for 'line vty'", 1, global_report_output)

    aaa_accounting_commands = ["commands 15", "connection", "exec", "network", "system"]
    for index, aaa_accounting_command in enumerate(aaa_accounting_commands, start = 7):
        if aaa_accounting_command == "commands 15":
            general_parsers.compliance_check_with_expected_output(connection, f"show running-config | include aaa accounting {aaa_accounting_command}", 
                                          f"1.1.{index} Set 'aaa accounting' to log all privileged use commands using {aaa_accounting_command}", 
                                          2, global_report_output)
        else:
            general_parsers.compliance_check_with_expected_output(connection, f"show running-config | include aaa accounting {aaa_accounting_command}", 
                                               f"1.1.{index} Set 'aaa accounting {aaa_accounting_command}'", 2, global_report_output)

    users_parsers.compliance_check_acl_privilege(connection, "show running-config | include privilege", "1.2.1 Set 'privilege 1' for local users", 1, global_report_output)        
    line_parsers.compliance_check_transport_input(connection, "show running-config | section vty", "1.2.2 Set 'transport input ssh' for 'line vty' connections", 1, global_report_output)
    line_parsers.compliance_check_vty_acl(connection, "show ip access-list", "show running-config | section vty", "1.2.4 Create 'access-list' for use with 'line vty'", 
                             "1.2.5 Set 'access-class' for 'line vty'", 1, global_report_output)

    banner_commands = ["exec", "login", "motd"]
    for index, banner_command in enumerate(banner_commands, start = 1):
        general_parsers.compliance_check_banner(connection, f"show running-config | begin banner {banner_command}",
                                            f"1.3.{index} Set the 'banner-text' for 'banner {banner_command}'", 1, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include enable secret", "1.4.1 Set 'password' for 'enable secret'", 1, global_report_output)
    general_parsers.compliance_check_without_no_prefix(connection, "show running-config | include service password-encryption", "1.4.2 Enable 'service password-encryption'", 1, global_report_output)
    users_parsers.compliance_check_user_secret(connection, "show running-config | include username", "1.4.3 Set 'username secret' for all local users", 1, global_report_output)

    if snmp_parsers.complaince_check_snmp_enabled(connection, "show snmp community", "1.5.1 Set 'no snmp-server' to disable SNMP when unused", 1, global_report_output) == True:
        snmp_parsers.compliance_check_no_snmp(global_report_output)

    else:
        snmp_community_commands = ["private", "public"]
        for index, snmp_community_command in enumerate(snmp_community_commands, start = 2):
            snmp_parsers.compliance_check_snmp_community(connection, f"show snmp community | include {snmp_community_command}", 
                                            f"1.5.{index} Unset {snmp_community_command} for 'snmp-server community'", 1, global_report_output)
        
        snmp_parsers.compliance_check_snmp_rw(connection, "show running-config | include snmp-server community", "1.5.4 Do not set 'RW' for any 'snmp-server community'", 
                                 "1.5.5 Set the ACL for each 'snmp-server community'", 1, global_report_output)
        
        general_parsers.compliance_check_with_expected_output(connection, "show ip access-list", "1.5.6 Create an 'access-list' for use with SNMP", 1, global_report_output)
        general_parsers.compliance_check_with_expected_output(connection, "show running-config | include snmp-server host", "1.5.7 Set 'snmp-server host' when using SNMP", 1, global_report_output)
        general_parsers.compliance_check_with_expected_output(connection, "show running-config | include snmp-server enable traps snmp", "1.5.8 Set 'snmp-server enable traps snmp'", 1, global_report_output)

        snmp_parsers.compliance_check_snmp_v3(connection, "show snmp group | include groupname", "show snmp user", 
                                              "1.5.9 Set 'priv' for each 'snmp-server group' using SNMPv3", 
                                              "1.5.10 Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3", 
                                              2, global_report_output)
        
    
    #2. Control Plane CIS Compliance Checks
    print("Performing CIS Cisco IOS 15 Control Plane Benchmarks assessment.")

    ssh_parsers.compliance_check_hostname(connection, "show running-config | include hostname", "2.1.1.1.1 Set the 'hostname'", 1, global_report_output)
    ssh_parsers.compliance_check_domain_name(connection, "show running-config | include ip domain", "2.1.1.1.2 Set the 'ip domain-name'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show crypto key mypubkey rsa", "2.1.1.1.3 Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'",
                                       1, global_report_output)
    
    ssh_parsers.compliance_check_ssh(connection, "show ip ssh", "2.1.1.1.4 Set 'seconds' for 'ip ssh timeout'", "2.1.1.1.5 Set maximum value for 'ip ssh authentication-retries'", 
                         "2.1.1.2 Set version 2 for 'ip ssh version'", 1, global_report_output)

    services_parsers.compliance_check_cdp(connection, "show cdp", "2.1.2 Set 'no cdp run'", 1, global_report_output)
    services_parsers.compliance_check_bootp(connection, "show running-config all | include ip bootp", "2.1.3 Set 'no ip bootp server'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_empty_output(connection, "show running-config all | include service dhcp", "2.1.4 Set 'no service dhcp'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_empty_output(connection, "show running-config all | include ip identd", "2.1.5 Set 'no ip identd'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include service tcp-keepalives-in", "2.1.6 Set 'service tcp-keepalives-in'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include service tcp-keepalives-out", "2.1.7 Set 'service tcp-keepalives-out'", 1, global_report_output)
    services_parsers.compliance_check_service_pad(connection, "show running-config all | include service pad$", "2.1.8 Set 'no service pad'", 1, global_report_output)
    
    general_parsers.compliance_check_without_no_prefix(connection, "show running-config | include logging on", "2.2.1 Set 'logging on'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include logging buffered", "2.2.2 Set 'buffer size' for 'logging buffered'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include logging console critical", "2.2.3 Set 'logging console critical'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include logging host", "2.2.4 Set IP address for 'logging host'", 1, global_report_output)
    logging_parsers.compliance_check_logging_trap(connection, "show logging | include Trap logging", "2.2.5 Set 'logging trap informational'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include service timestamps debug datetime", "2.2.6 Set 'service timestamps debug datetime'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include source-interface Loopback", "2.2.7 Set 'logging source interface", 1, global_report_output)
    
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ntp authenticate", "2.3.1.1 Set 'ntp authenticate'", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ntp authentication-key", "2.3.1.2 Set 'ntp authentication-key'", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ntp trusted-key", "2.3.1.3 Set the 'ntp trusted key'", 2, global_report_output)
    ntp_parsers.compliance_check_ntp_server_key(connection, "show running-config | include ntp server", "2.3.1.4 Set 'key' for each 'ntp server'", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show ntp associations", "2.3.2 Set 'ip address' for 'ntp server'", 1, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show ip interface brief | include Loopback", "2.4.1 Create a single 'interface loopback'", 2, global_report_output)
    aaa_parsers.compliance_check_aaa_source_int(connection, "show running-config | include tacacs source-interface Loopback", 
                                                  "show running-config | include radius source-interface Loopback", "2.4.2 Set AAA 'source-interface'", 2, global_report_output)
    
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ntp source Loopback", "2.4.3 Set 'ntp source' to Loopback Interface", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include tftp source-interface Loopback", "2.4.4 Set 'ip tftp source-interface' to the Loopback Interface",
                                                        2, global_report_output)
    
    
    #3 Data Plane CIS Compliance Checks
    print("Performing CIS Cisco IOS 15 Data Plane Benchmarks assessment.")

    routing_parsers.compliance_check_source_route(connection, "show running-config all | include ip source-route", "3.1.1 Set 'no ip source-route'", 1, global_report_output)
    routing_parsers.compliance_check_proxy_arp(connection, "show ip interface", "3.1.2 Set 'no ip proxy-arp'", 2, global_report_output)
    general_parsers.compliance_check_with_expected_empty_output(connection, "show ip interface brief | include Tunnel", "3.1.3 Set 'no interface tunnel;", 2, global_report_output)
    routing_parsers.compliance_check_urpf(connection, "show running-config | section interface", "3.1.4 Set 'ip verify unicast source reachable-via'", 2, global_report_output)

    border_parsers.compliance_check_border_router_filtering(connection, "show ip access-list", "show running-config | section interface", 
                                                            "3.2.1 Set 'ip access-list extended' to Forbid Private Source Addresses frrom External Networks", 
                                                            "3.2.2 Set inbound 'ip access-group' on the External Interface", 2, global_report_output)

    compliance_check_routing(connection, global_report_output)

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Assessment done. Elapsed time: {elapsed_time:.2f} seconds")

    return global_report_output


def parsed_output_ios15(report_output):
    
    parsed_output_dict = {'Management Plane Checks':report_output[0:31], 'Control Plane Checks':report_output[31:60], 'Data Plane Checks':report_output[60:80], 
                          'MP Local AAA Rules':report_output[0:11], 'MP Access Rules':report_output[11:15], 'MP Banner Rules':report_output[15:18], 
                          'MP Password Rules':report_output[18:21], 'MP SNMP Rules':report_output[21:31],
                          'CP Global Services SSH Rules':report_output[31:37], 'CP Global Services Rules':report_output[37:44], 'CP Logging Rules':report_output[44:51],
                          'CP NTP Rules':report_output[51:56], 'CP Loopback Rules':report_output[56:60], 
                          'DP Routing Rules':report_output[60:64], 'DP Border Router Filtering':report_output[64:66],
                          'DP Neighbor Auth EIGRP':report_output[66:75], 'DP Neighbor Auth OSPF':report_output[75:77],
                          'DP Neighbor Auth RIP':report_output[77:82], 'DP Neighbor Auth BGP':report_output[82]}
    
    return parsed_output_dict