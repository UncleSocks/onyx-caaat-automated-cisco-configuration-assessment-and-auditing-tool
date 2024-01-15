import re
from ssh_module import ssh_send
from report import generate_report
from parser_modules.ios15 import general_parsers


def compliance_check_source_route(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    compliant = "no ip source-route" in command_output.lower()
    current_configuration = command_output if command_output else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_proxy_arp(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'^(?P<interface>\S+).*?\n(?: {2}(?!Local).*\n)* {2}Proxy ARP is (?P<proxy_arp>enabled|disabled)\s*$', re.MULTILINE)
    parser = regex_pattern.finditer(command_output)
    non_compliant_interface_counter = 0
    interface_list = []

    for match in parser:
        interface = match.group('interface')
        proxy_arp = match.group('proxy_arp')
        if proxy_arp == "enabled":
            non_compliant_interface_counter += 1
        current_interface_info = {'Interface':interface, 'Proxy ARP':proxy_arp}
        interface_list.append(current_interface_info)
    
    compliant = non_compliant_interface_counter == 0
    current_configuration = interface_list
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
        

def compliance_check_urpf(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'^(?P<interface>\S+).*?IP verify source reachable-via RX', re.MULTILINE | re.DOTALL)
    parser = regex_pattern.finditer(command_output)
    interface_list = []

    if not parser:
        compliant = False
    else:
        for match in parser:
            interface = match.group('interface')
            interface_list.append(interface)
        compliant = True
    
    current_configuration = interface_list if interface_list else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
    

def compliance_check_dynamic_routing_tester(connection, command):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'router (?P<dynamic_route>eigrp|ospf|rip|bgp)', re.MULTILINE)
    parser = regex_pattern.finditer(command_output)
    enabled_dynamic_routing = {'EIGRP':False, 'OSPF':False, 'RIP': False, 'BGP': False}

    if not parser:
        return enabled_dynamic_routing
    else:

        for match in parser:
            dynamic_route = match.group('dynamic_route').lower()
            if dynamic_route == "eigrp":
                enabled_dynamic_routing['EIGRP'] = True
            elif dynamic_route == "ospf":
                enabled_dynamic_routing['OSPF'] = True
            elif dynamic_route == "rip":
                enabled_dynamic_routing['RIP'] = True
            elif dynamic_route == 'bgp':
                enabled_dynamic_routing['BGP'] = True

        return enabled_dynamic_routing


def compliance_check_no_eigrp(global_report_output):
    eigrp_cis_checks = [{'CIS Check':"3.3.1.1 Set 'key chain'", 'Level':2}, {'CIS Check':"3.3.1.2 Set 'key'", 'Level':2}, 
                        {'CIS Check':"3.3.1.3 Set 'key-string'", 'Level':2}, {'CIS Check':"3.3.1.4 Set 'address-family ipv4 autonomous-system'", 'Level':2},
                        {'CIS Check':"3.3.1.5 Set 'af-interface default'", 'Level':2}, {'CIS Check':"3.3.1.6 Set 'authentication key-chain'", 'Level':2},
                        {'CIS Check':"3.3.1.7 Set 'authentication mode md5'", 'Level':2}, {'CIS Check':"3.3.1.8 Set 'ip authentication key-chain eigrp'", 'Level':2},
                        {'CIS Check':"3.3.1.9 Set 'ip authentication mode eigrp'", 'Level':2}]
    
    for eigrp_cis_check in eigrp_cis_checks:
        compliant = "Not Applicable"
        current_configuration = "EIGRP not enabled"
        cis_check = eigrp_cis_check['CIS Check']
        level = eigrp_cis_check['Level']
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_no_ospf(global_report_output):
    ospf_cis_checks = [{'CIS Check':"3.3.2.1 Set 'authentication message-digest' for OSPF area", 'Level':2},
                       {'CIS Check':"3.3.2.2 Set 'ip ospf message-digest-key md5'", 'Level':2}]

    for ospf_cis_check in ospf_cis_checks:
        compliant = "Not Applicable"
        current_configuration = "OSPF not enabled"
        cis_check = ospf_cis_check['CIS Check']
        level = ospf_cis_check['Level']
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_no_rip(global_report_output):
    rip_cis_checks = [{'CIS Check':"3.3.3.1 Set 'key chain'", 'Level':2}, {'CIS Check':"3.3.3.2 Set 'key'", 'Level':2},
                      {'CIS Check':"3.3.3.3 Set 'key-string'", 'Level':2}, {'CIS Check':"3.3.3.4 Set 'ip rip authentication key-chain", 'Level':2},
                      {'CIS Check':"3.3.3.5 Set 'ip rip authentication mode' to 'md5'", 'Level':2}]

    for rip_cis_check in rip_cis_checks:
        compliant = "Not Applicable"
        current_configuration = "RIP not enabled"
        cis_check = rip_cis_check['CIS Check']
        level = rip_cis_check['Level']
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_no_bgp(global_report_output):
    bgp_cis_check = {'CIS Check':"3.3.4.1 Set 'neighbor password'", 'Level':2}
    compliant = "Not Applicable"
    current_configuration = "BGP not enabled"
    cis_check = bgp_cis_check['CIS Check']
    level = bgp_cis_check['Level']
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_eigrp(connection, command_one, command_two, level, global_report_output):

    def complaince_check_eigrp_key(connection, command, level, global_report_output):

        command_output = ssh_send(connection, command)
        eigrp_key_cis_checks = [{'CIS Check':"3.3.1.1 Set 'key chain'", 'Compliant':False}, 
                                {'CIS Check':"3.3.1.2 Set 'key'", 'Compliant': False}, 
                                {'CIS Check':"3.3.1.3 Set 'key-string'", 'Compliant':False}]

        if not command_output:
            current_configuration = None
            for eigrp_cis_check in eigrp_key_cis_checks:
                cis_check = eigrp_cis_check['CIS Check']
                compliant = eigrp_cis_check['Compliant']
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
        
        else:
            regex_pattern = re.compile(r'key chain (?P<chain>\S+)\n(?: key (?P<key>\d+)(?:\n  key-string (?P<key_string>\S+))?)?')
            parser = regex_pattern.finditer(command_output)
            eigrp_key_list = []
            eigrp_without_key_string_counter = 0

            for match in parser:
                key_chain = match.group('chain')
                key = match.group('key')
                key_string = match.group('key_string') or None
                current_eigrp_key_info = {'Key Chain':key_chain, 'Key':key, 'Key String':key_string}
                eigrp_key_list.append(current_eigrp_key_info)

                if key_string == None:
                    eigrp_without_key_string_counter += 1
            
            for eigrp_cis_check in eigrp_key_cis_checks:

                if eigrp_without_key_string_counter == 0:
                    cis_check = eigrp_cis_check['CIS Check']
                    eigrp_cis_check['Compliant'] = True
                    compliant = eigrp_cis_check['Compliant']
                    current_configuration = eigrp_key_list
                    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
                
                else:
                    cis_check = eigrp_cis_check['CIS Check']

                    if eigrp_cis_check['CIS Check'] == "3.3.1.1 Set 'key chain'" or eigrp_cis_check['CIS Check'] == "3.3.1.2 Set 'key'":
                        eigrp_cis_check['Compliant'] = True
                    compliant = eigrp_cis_check['Compliant']
                    
                    current_configuration = eigrp_key_list
                    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))

    complaince_check_eigrp_key(connection, command_one, level, global_report_output)

    def compliance_check_eigrp_auth(non_compliant_as_counter, non_compliant_af_interface_counter, 
                                    non_compliaint_key_chain_counter, non_compliant_auth_mode_counter,
                                    eigrp_as_list, eirgp_af_list, eigrp_key_chain_list, eirgp_auth_mode_list,
                                    level, global_report_output):

        eigrp_cis_checks = [{'CIS Check':"3.3.1.4 Set 'address-family ipv4 autonomous-system", 'Current Configuration':eigrp_as_list},
                            {'CIS Check':"3.3.1.5 Set 'af-interface default'", 'Current Configuration':eirgp_af_list},
                            {'CIS Check':"3.3.1.6 Set 'authentication key-chain", 'Current Configuration':eigrp_key_chain_list},
                            {'CIS Check':"3.3.1.7 Set 'authentication mode md5'", 'Current Configuration':eirgp_auth_mode_list}]
        
        for eigrp_cis_check in eigrp_cis_checks:

            if eigrp_cis_check['CIS Check'] == "3.3.1.4 Set 'address-family ipv4 autonomous-system":
                cis_check = eigrp_cis_check['CIS Check']
                compliant = non_compliant_as_counter == 0
                current_configuration = eigrp_cis_check['Current Configuration']
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            
            elif eigrp_cis_check['CIS Check'] == "3.3.1.5 Set 'af-interface default'":
                cis_check = eigrp_cis_check['CIS Check']
                compliant = non_compliant_af_interface_counter == 0
                current_configuration = eigrp_cis_check['Current Configuration']
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            
            elif eigrp_cis_check['CIS Check'] == "3.3.1.6 Set 'authentication key-chain":
                cis_check = eigrp_cis_check['CIS Check']
                compliant = non_compliaint_key_chain_counter == 0
                current_configuration = eigrp_cis_check['Current Configuration']
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            
            else:
                cis_check = eigrp_cis_check['CIS Check']
                compliant = non_compliant_auth_mode_counter == 0
                current_configuration = eigrp_cis_check['Current Configuration']
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))                

    def compliance_check_eigrp_auth_stager(connection, command, level, global_report_output):
        command_output = ssh_send(connection, command)
        regex_pattern = re.compile(r'router eigrp (?P<vrf>[A-Za-z]+\d*[A-Za-z]*)(?:\n.*?address-family ipv4 unicast autonomous-system (?P<as>\d+)\n(?P<af_config>.*?)(?=exit-address-family|\Z))?', 
                                   re.DOTALL)
        parser = regex_pattern.finditer(command_output)

        eigrp_as_list = []
        eirgp_af_list= []
        eigrp_key_chain_list= []
        eirgp_auth_mode_list = []

        non_compliant_as_counter = 0
        non_compliant_af_interface_counter = 0
        non_compliant_key_chain_counter = 0
        non_compliant_auth_mode_counter = 0

        for match in parser:
            vrf = match.group('vrf')
            autonomous_system = match.group('as') or None
            af_config = match.group('af_config')
            
            if autonomous_system == None:

                eigrp_as_list.append({'VRF':vrf, 'Autonomous System':None})
                eirgp_af_list.append({'VRF': vrf, 'AF Interface':None})
                eigrp_key_chain_list.append({'VRF': vrf, 'Auth Key Chain':None})
                eirgp_auth_mode_list.append({'VRF': vrf, 'Auth Mode':None})

                non_compliant_as_counter += 1
                non_compliant_af_interface_counter += 1
                non_compliant_key_chain_counter += 1
                non_compliant_auth_mode_counter += 1
            
            else:

                eigrp_as_list.append({'VRF':vrf, 'Autonomous System':autonomous_system})
                address_family_regex_pattern = re.compile(r'af-interface (?P<interface>\S+)(?:\s+authentication mode (?P<mode>\S+))?(?:\s+authentication key-chain (?P<chain>\S+))?', 
                                                        re.DOTALL)
                
                af_interface_parser = address_family_regex_pattern.findall(af_config)

                if af_interface_parser:

                    af_interface_list = []
                    auth_key_chain_list = []
                    auth_mode_list = []

                    for af_interface_match in af_interface_parser:

                        af_interface = af_interface_match[0]
                        auth_mode = af_interface_match[1] if af_interface_match[1] else None
                        auth_key_chain = af_interface_match[2] if af_interface_match[2] else None
                        

                        af_interface_list.append(af_interface)
                        auth_key_chain_list.append(auth_key_chain)
                        auth_mode_list.append(auth_mode)

                        if af_interface.lower() != "default":
                            non_compliant_af_interface_counter += 1
                        elif af_interface.lower() == "default" and auth_key_chain == None:
                            non_compliant_key_chain_counter += 1
                        elif af_interface.lower() == "default" and (auth_mode.lower() != "md5" or auth_mode == None):
                            non_compliant_auth_mode_counter += 1
                    
                    eirgp_af_list.append({'VRF': vrf, 'AF Interface': af_interface_list})
                    eigrp_key_chain_list.append({'VRF': vrf, 'Auth Key Chain': auth_key_chain_list})
                    eirgp_auth_mode_list.append({'VRF': vrf, 'Auth Mode': auth_mode_list})
                
                else:
                    eirgp_af_list.append({'VRF': vrf, 'AF Interface': None})
                    eigrp_key_chain_list.append({'VRF': vrf, 'Auth Key Chain':None})
                    eirgp_auth_mode_list.append({'VRF': vrf, 'Auth Mode':None})

                    non_compliant_af_interface_counter += 1
                    non_compliant_key_chain_counter += 1
                    non_compliant_auth_mode_counter += 1

        return compliance_check_eigrp_auth(non_compliant_as_counter, non_compliant_af_interface_counter, 
                                           non_compliant_key_chain_counter, non_compliant_auth_mode_counter,
                                           eigrp_as_list, eirgp_af_list, eigrp_key_chain_list, eirgp_auth_mode_list, 
                                           level, global_report_output)

    compliance_check_eigrp_auth_stager(connection, command_two, level, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include key-chain", "3.3.1.8 Set 'ip authentication key-chain eigrp", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include authentication mode", "3.3.1.9 Set 'ip authentication mode eigrp'", 2, global_report_output)