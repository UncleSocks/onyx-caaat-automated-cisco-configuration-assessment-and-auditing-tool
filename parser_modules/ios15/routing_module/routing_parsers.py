import re
from ssh import ssh_send
from report_modules.main_report import generate_report


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
    regex_pattern = re.compile(r'interface (?P<interface>\S+)(?:(?!interface).)*?ip verify unicast source reachable-via rx\n', re.DOTALL)
    parser = regex_pattern.findall(command_output)
    
    compliant = bool(parser)
    current_configuration = {'Interface':parser if parser else None}
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
                if compliance_check_rip_version_checker(connection, "show running-config | section router rip") == True:
                    enabled_dynamic_routing['RIP'] = True
                else:
                    enabled_dynamic_routing['RIP'] = False

            elif dynamic_route == 'bgp':
                enabled_dynamic_routing['BGP'] = True

        return enabled_dynamic_routing


def compliance_check_rip_version_checker(connection, command):
    command_output = ssh_send(connection, command)
    version_2_search = re.search(r'version\s+2', command_output, re.IGNORECASE)
    return version_2_search is not None


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
        current_configuration = "RIPv2 not enabled"
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
            regex_pattern = re.compile(r'key chain (?P<chain>\S+)\n(?: key (?P<key>\d+)(?:\n  key-string (?P<key_string>(?:\d+\s+\S+)|\S+))?)?')
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


    def compliance_check_eigrp_auth(eigrp_vrf, non_compliant_as_counter, non_compliant_af_interface_counter, 
                                    non_compliant_key_chain_counter, non_compliant_auth_mode_counter,
                                    eigrp_as_list, eirgp_af_list, eigrp_key_chain_list, eirgp_auth_mode_list,
                                    level, global_report_output):

        eigrp_cis_checks = [{'CIS Check':"3.3.1.4 Set 'address-family ipv4 autonomous-system", 'Current Configuration':eigrp_as_list},
                            {'CIS Check':"3.3.1.5 Set 'af-interface default'", 'Current Configuration':eirgp_af_list},
                            {'CIS Check':"3.3.1.6 Set 'authentication key-chain", 'Current Configuration':eigrp_key_chain_list},
                            {'CIS Check':"3.3.1.7 Set 'authentication mode md5'", 'Current Configuration':eirgp_auth_mode_list}]
        
        for eigrp_cis_check in eigrp_cis_checks:

            if eigrp_cis_check['CIS Check'] == "3.3.1.4 Set 'address-family ipv4 autonomous-system":
                cis_check = eigrp_cis_check['CIS Check']
                if eigrp_vrf == True:
                    compliant = non_compliant_as_counter == 0
                    current_configuration = eigrp_cis_check['Current Configuration']
                else:
                    compliant = "Not Applicable"
                    current_configuration = "No Named EIGRP Configured"
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            
            elif eigrp_cis_check['CIS Check'] == "3.3.1.5 Set 'af-interface default'":
                cis_check = eigrp_cis_check['CIS Check']
                if eigrp_vrf == True:
                    compliant = non_compliant_af_interface_counter == 0
                    current_configuration = eigrp_cis_check['Current Configuration']
                else:
                    compliant = "Not Applicable"
                    current_configuration = "No Named EIGRP Configured"
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            
            elif eigrp_cis_check['CIS Check'] == "3.3.1.6 Set 'authentication key-chain":
                cis_check = eigrp_cis_check['CIS Check']
                if eigrp_vrf == True:
                    compliant = non_compliant_key_chain_counter == 0
                    current_configuration = eigrp_cis_check['Current Configuration']
                else:
                    compliant = "Not Applicable"
                    current_configuration = "No Named EIGRP Configured"
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            
            else:
                cis_check = eigrp_cis_check['CIS Check']
                if eigrp_vrf == True: 
                    compliant = non_compliant_auth_mode_counter == 0
                    current_configuration = eigrp_cis_check['Current Configuration']
                else:
                    compliant = "Not Applicable"
                    current_configuration = "No Named EIGRP Configured"
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))                

    def compliance_check_eigrp_auth_stager(connection, command, level, global_report_output):
        command_output = ssh_send(connection, command)
        regex_pattern = re.compile(r'router eigrp (?P<vrf>[A-Za-z]+\d*[A-Za-z]*)(?:\n.*?address-family ipv4 unicast autonomous-system (?P<as>\d+)\n(?P<af_config>.*?)(?=exit-address-family|\Z))?', 
                                   re.DOTALL)
        parser = regex_pattern.finditer(command_output)
        vrf_check = regex_pattern.search(command_output)

        eigrp_as_list = []
        eirgp_af_list= []
        eigrp_key_chain_list= []
        eirgp_auth_mode_list = []

        non_compliant_as_counter = 0
        non_compliant_af_interface_counter = 0
        non_compliant_key_chain_counter = 0
        non_compliant_auth_mode_counter = 0


        if vrf_check:
            eigrp_vrf = True
            for match in parser:

                vrf = match.group('vrf')
                autonomous_system = match.group('as') or None
                af_config = match.group('af_config')
                
                if autonomous_system == None:

                    eigrp_as_list.append({'VRF':vrf, 'Autonomous System':autonomous_system})
                    eirgp_af_list.append({'VRF':vrf, 'AF Interface':None})
                    eigrp_key_chain_list.append({'VRF':vrf, 'Auth Key Chain':None})
                    eirgp_auth_mode_list.append({'VRF':vrf, 'Auth Mode':None})

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

                            if af_interface.lower() == "default":
                                if auth_key_chain == None:
                                    non_compliant_key_chain_counter += 1
                                if auth_mode == None:
                                    non_compliant_auth_mode_counter += 1
                        
                        if "default" not in af_interface_list:
                            non_compliant_af_interface_counter += 1
                        
                        if "default" not in af_interface_list and None in auth_key_chain_list:
                            non_compliant_af_interface_counter += 1
                            non_compliant_key_chain_counter += 1

                        if "default" not in af_interface_list and None in auth_mode_list:
                            non_compliant_af_interface_counter += 1
                            non_compliant_auth_mode_counter += 1
                        
                        eirgp_af_list.append({'VRF':vrf, 'AF Interface': af_interface_list})
                        eigrp_key_chain_list.append({'VRF':vrf, 'Auth Key Chain': auth_key_chain_list})
                        eirgp_auth_mode_list.append({'VRF':vrf, 'Auth Mode': auth_mode_list})
                    
                    else:
                        eirgp_af_list.append({'VRF':vrf, 'AF Interface':None})
                        eigrp_key_chain_list.append({'VRF':vrf, 'Auth Key Chain':None})
                        eirgp_auth_mode_list.append({'VRF':vrf, 'Auth Mode':None})

                        non_compliant_af_interface_counter += 1
                        non_compliant_key_chain_counter += 1
                        non_compliant_auth_mode_counter += 1
        else:
            eigrp_vrf = False

        return compliance_check_eigrp_auth(eigrp_vrf, non_compliant_as_counter, non_compliant_af_interface_counter, 
                                           non_compliant_key_chain_counter, non_compliant_auth_mode_counter,
                                           eigrp_as_list, eirgp_af_list, eigrp_key_chain_list, eirgp_auth_mode_list, 
                                           level, global_report_output)
    

    def compliance_check_auth_global(eigrp_global_as, non_compliant_key_chain_counter, non_compliant_auth_mode_counter, 
                                     eigrp_key_chain_list, eirgp_auth_mode_list, level, global_report_output):
        eigrp_cis_checks = [{'CIS Check':"3.3.1.8 Set 'ip authentication key-chain eigrp'", 'Current Configuration':eigrp_key_chain_list},
                            {'CIS Check':"3.3.1.9 Set 'ip authentication mode eigrp'", 'Current Configuration':eirgp_auth_mode_list}]
        
        for eigrp_cis_check in eigrp_cis_checks:

            if eigrp_cis_check['CIS Check'] == "3.3.1.8 Set 'ip authentication key-chain eigrp'":
                cis_check = eigrp_cis_check['CIS Check']
                if eigrp_global_as == True:
                    compliant = non_compliant_key_chain_counter == 0
                    current_configuration = eigrp_cis_check['Current Configuration']
                else:
                    compliant = "Not Applicable"
                    current_configuration = "No Classic EIGRP Configured"
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            
            else:
                cis_check = eigrp_cis_check['CIS Check']
                if eigrp_global_as == True:
                    compliant = non_compliant_auth_mode_counter == 0
                    current_configuration = eigrp_cis_check['Current Configuration'] 
                else:
                    compliant = "Not Applicable"
                    current_configuration = "No Classic EIGRP Configured"
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
    
    def compliance_check_eigrp_auth_global_stager(connection, command_two, level, global_report_output):
        command_output = ssh_send(connection, command_two)
        regex_pattern = re.compile(r'router eigrp (?P<global_as>\d+)(?:\n.*?(?P<config>.*?)(?=router eigrp|\Z))?', 
                                   re.DOTALL)
        parser = regex_pattern.finditer(command_output)
        global_as_check = regex_pattern.search(command_output)

        eigrp_key_chain_list = []
        eirgp_auth_mode_list = []

        non_compliant_key_chain_counter = 0
        non_compliant_auth_mode_counter = 0

        if global_as_check:
            eigrp_global_as = True

            for match in parser:
                
                global_as_chain_list = []
                global_as_mode_list = []
                
                global_as = match.group('global_as')

                global_as_chain = ssh_send(connection, f"show running-config | include ip authentication key-chain eigrp {global_as}")

                if not global_as_chain:
                    non_compliant_key_chain_counter += 1
                else:
                    global_as_chain_parser = global_as_chain.split("\n")
                    for global_as_chain_parsed in global_as_chain_parser:
                        auth_key_chain_parser = global_as_chain_parsed.split()
                        auth_key_chain_parsed = auth_key_chain_parser[5]
                        global_as_chain_list.append(auth_key_chain_parsed)

                global_as_mode = ssh_send(connection, f"show running-config | include ip authentication mode eigrp {global_as}")

                if not global_as_mode:
                    non_compliant_auth_mode_counter += 1
                else:
                    global_as_mode_parser = global_as_mode.split("\n")
                    for global_as_mode_parsed in global_as_mode_parser:
                        auth_mode_parser = global_as_mode_parsed.split()
                        auth_mode_parsed = auth_mode_parser[5]
                        global_as_mode_list.append(auth_mode_parsed)

                auth_key_chain = global_as_chain_list if global_as_chain_list else None
                auth_mode = global_as_mode_list if global_as_mode_list else None

                eigrp_key_chain_list.append({'Autonomous System':global_as, 'Auth Key Chain':auth_key_chain})
                eirgp_auth_mode_list.append({'Autonomous System':global_as, 'Auth Mode':auth_mode})

        else:
            eigrp_global_as = False

        return compliance_check_auth_global(eigrp_global_as, non_compliant_key_chain_counter, non_compliant_auth_mode_counter, 
                                            eigrp_key_chain_list, eirgp_auth_mode_list, level, global_report_output)


    complaince_check_eigrp_key(connection, command_one, level, global_report_output)
    compliance_check_eigrp_auth_stager(connection, command_two, level, global_report_output)
    compliance_check_eigrp_auth_global_stager(connection, command_two, level, global_report_output)
    

def compliance_check_ospf(connection, command_one, command_two, level, global_report_output):

    def compliance_check_ospf_auth(connection, command, level, global_report_output):
        command_output = ssh_send(connection, command)
        regex_pattern = re.compile(r"router ospf (?P<id>\d+)(?:.*?(?P<config>.*?))(?=\nrouter ospf|$)", re.DOTALL)    
        parser = regex_pattern.finditer(command_output)

        ospf_list = []

        non_compliant_ospf_counter = 0

        for match in parser:
            
            area_list = []
            auth_list = []
            
            ospf_id = match.group('id')
            ospf_config = match.group('config') or None

            if ospf_config is None:
                non_compliant_ospf_counter += 1
                current_ospf_info = {'Process ID':ospf_id, 'Area Number':ospf_config, 'Authentication':ospf_config}
                ospf_list.append(current_ospf_info)
            
            else:
                auth_regex_pattern = re.compile(r'^\s*area (?P<area_number>\S+) authentication(?:\s+(?P<authentication_value>\S+))?$', re.MULTILINE)
                auth_parser = auth_regex_pattern.findall(ospf_config)

                unique_area_with_auth_list = []

                if auth_parser:
                    
                    for match in auth_parser:
                        area_number, authentication_value = match
                        authentication_value = authentication_value if authentication_value else None
                        
                        if authentication_value is None or authentication_value.lower() != "message-digest":
                            non_compliant_ospf_counter += 1
                        
                        area_list.append(area_number)
                        auth_list.append(authentication_value)
                    
                    unique_area_with_auth_list = [area for area in area_list if area not in unique_area_with_auth_list]

                    area_without_auth_list = []

                    area_regex_pattern = re.compile(r'network\s+\S+\s+\S+\s+area\s+(?P<area_number>\S+)', re.MULTILINE)
                    area_parser = area_regex_pattern.findall(ospf_config)
                    for match in area_parser:
                        area_number = match
                        if area_number not in unique_area_with_auth_list:
                            area_without_auth_list.append(area_number)


                    if area_without_auth_list:
                        non_compliant_ospf_counter += 1
                        unique_area_without_list = []
                        [unique_area_without_list.append(area) for area in area_without_auth_list if area not in unique_area_without_list]

                        area_list.append(unique_area_without_list)

                        authentication_value = None
                        auth_list.append(authentication_value)
                    
                        current_ospf_info = {'Process ID':ospf_id, 'Area Number':area_list, 'Authentication':auth_list}
                        ospf_list.append(current_ospf_info)
                    
                    else:
                        current_ospf_info = {'Process ID':ospf_id, 'Area Number':area_list, 'Authentication':auth_list}
                        ospf_list.append(current_ospf_info)

                else:
                    non_compliant_ospf_counter += 1

                    area_regex_pattern = re.compile(r'network\s+\S+\s+\S+\s+area\s+(?P<area_number>\S+)', re.MULTILINE)
                    area_parser = area_regex_pattern.findall(ospf_config)
                    
                    if area_parser:
                        
                        area_without_auth_list = []
                        
                        for match in area_parser:
                            area_number = match
                            if area_number not in unique_area_with_auth_list:
                                non_compliant_ospf_counter += 1
                                area_without_auth_list.append(area_number)
                        
                        unique_area_without_list = []
                        [unique_area_without_list.append(area) for area in area_without_auth_list if area not in unique_area_without_list]
                        area_list.append(unique_area_without_list)

                        authentication_value = None
                        auth_list.append(authentication_value)

                        current_ospf_info = {'Process ID':ospf_id, 'Area Number':area_list, 'Authentication':auth_list}
                        ospf_list.append(current_ospf_info)

                    else:
                        area = None
                        area_list.append(area)

                        authentication_value = None
                        auth_list.append(authentication_value)

                        current_ospf_info = {'Process ID':ospf_id, 'Area Number':area_list, 'Authentication':auth_list}
                        ospf_list.append(current_ospf_info)
                    
        
        compliant = non_compliant_ospf_counter == 0
        cis_check = "3.3.2.1 Set 'authentication message-digest' for OSPF area"
        current_configuration = ospf_list
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


    def compliance_check_ospf_int(connection, command, level, global_report_output):
        command_output = ssh_send(connection, command)
        regex_pattern = re.compile(r'interface (?P<interface>\S+)(?:(?!interface).)*?ip ospf message-digest-key (?P<key>\d+) md5 (?P<md5_key>(?:\d+\s+\S+)|\S+)\n(?:.*?(?=(?:interface|$)))', re.DOTALL)
        parser = regex_pattern.findall(command_output)

        ospf_int_list = []
        non_compliant_ospf_int_counter = 0

        if not parser:
            non_compliant_ospf_int_counter += 1

        else:
            for match in parser:
                interface, key, md5_key = match
                current_ospf_int_info = {'Interface':interface, 'Key':key, 'MD5 Key':md5_key}
                
                ospf_int_list.append(current_ospf_int_info)

        compliant = non_compliant_ospf_int_counter == 0
        cis_check = "3.3.2.2 Set 'ip ospf message-digest-key md5'"
        current_configuration = ospf_int_list if ospf_int_list else None
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


    compliance_check_ospf_auth(connection, command_one, level, global_report_output)
    compliance_check_ospf_int(connection, command_two, level, global_report_output)



def compliance_check_rip(connection, command_one, command_two, level, global_report_output):

    def compliance_check_rip_key(connection, command, level, global_report_output):
        command_output = ssh_send(connection, command)

        rip_key_cis_checks = [{'CIS Check':"3.3.3.1 Set 'key chain'", 'Compliant':False},
                              {'CIS Check':"3.3.3.2 Set 'key'", 'Compliant':False},
                              {'CIS Check':"3.3.3.3 Set 'key-string", 'Compliant':False}]
        
        if not command_output:
            current_configuration = None
            for rip_key_cis_check in rip_key_cis_checks:
                cis_check = rip_key_cis_check['CIS Check']
                compliant = rip_key_cis_check['Compliant']
                global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
        
        else:
            regex_pattern = re.compile(r'key chain (?P<chain>\S+)\n(?: key (?P<key>\d+)(?:\n  key-string (?P<key_string>(?:\d+\s+\S+)|\S+))?)?')
            parser = regex_pattern.finditer(command_output)
            rip_key_list = []
            rip_without_key_string_counter = 0

            for match in parser:
                key_chain = match.group('chain')
                key = match.group('key')
                key_string = match.group('key_string') or None
                current_rip_key_info = {'Key Chain':key_chain, 'Key':key, 'Key String':key_string}
                rip_key_list.append(current_rip_key_info)

                if key_string == None:
                    rip_without_key_string_counter += 1

            for rip_key_cis_check in rip_key_cis_checks:

                if rip_without_key_string_counter == 0:
                    cis_check = rip_key_cis_check['CIS Check']
                    rip_key_cis_check['Compliant'] = True
                    compliant = rip_key_cis_check['Compliant']
                    current_configuration = rip_key_list
                    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
                
                else:
                    cis_check = rip_key_cis_check['CIS Check']

                    if rip_key_cis_check['CIS Check'] == "3.3.3.1 Set 'key chain'" or rip_key_cis_check['CIS Check'] == "3.3.3.2 Set 'key'":
                        rip_key_cis_check['Compliant'] = True
                    compliant = rip_key_cis_check['Compliant']
                    
                    current_configuration = rip_key_list
                    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
    
    
    def compliance_check_rip_key_chain(connection, command, level, global_report_output):
        command_output = ssh_send(connection, command)
        regex_pattern = re.compile(r'interface (?P<interface>\S+)(?:(?!interface).)*?ip rip authentication key-chain (?P<key_chain>\S+)\n(?:.*?(?=(?:interface|$)))', re.DOTALL)
        parser = regex_pattern.findall(command_output)

        rip_int_list = []
        non_compliant_rip_int_counter = 0

        if not parser:
            non_compliant_rip_int_counter += 1
        
        else:
            for match in parser:
                interface, key_chain = match
                current_rip_int_info = {'Interface':interface, 'Key Chain':key_chain}

                rip_int_list.append(current_rip_int_info)
        
        compliant = non_compliant_rip_int_counter == 0
        cis_check = "3.3.3.4 Set 'ip rip authentication key-chain'"
        current_configuration = rip_int_list if rip_int_list else None
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


    def compliance_check_rip_mode(connection, command, level, global_report_output):
        command_output = ssh_send(connection, command)
        regex_pattern = re.compile(r'interface (?P<interface>\S+)(?:(?!interface).)*?ip rip authentication mode (?P<mode>\S+)\n(?:.*?(?=(?:interface|$)))', re.DOTALL)
        parser = regex_pattern.findall(command_output)

        rip_int_list = []
        non_compliant_rip_int_counter = 0

        if not parser:
            non_compliant_rip_int_counter += 1
        
        else:
            for match in parser:
                interface, mode = match
                current_rip_int_info = {'Interface':interface, 'Mode':mode}

                rip_int_list.append(current_rip_int_info)
        
        compliant = non_compliant_rip_int_counter == 0
        cis_check = "3.3.3.5 Set 'ip rip authentication mode'"
        current_configuration = rip_int_list if rip_int_list else None
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


    compliance_check_rip_key(connection, command_one, level, global_report_output)
    compliance_check_rip_key_chain(connection, command_two, level, global_report_output)
    compliance_check_rip_mode(connection, command_two, level, global_report_output)


def compliance_check_bgp(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'router bgp (?P<as>\d+)\n(?P<config>.*?)(?=\nrouter|\Z)', re.DOTALL)
    parser = regex_pattern.finditer(command_output)
    
    bgp_list = []

    for match in parser:
        bgp_autonomous_system = match.group('as')
        bgp_config = match.group('config')

        bgp_neighbor_list = []
        bgp_peer_list = []
        non_compliant_neighbor_counter = 0
        non_compliant_peer_counter = 0

        regex_pattern_bgp_neighbor = re.compile(r'neighbor\s+(?P<neighbor>[\w\.]+)\s+(?P<neighbor_config>.*?)(?=\n|\Z)', re.DOTALL)
        bgp_neighbor_parser = regex_pattern_bgp_neighbor.finditer(bgp_config)

        for neighbor_match in bgp_neighbor_parser:
            bgp_neighbor = neighbor_match.group('neighbor')
            bgp_neighbor_config = neighbor_match.group('neighbor_config')

            if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", bgp_neighbor):
                existing_neighbor = next((neighbor for neighbor in bgp_neighbor_list if neighbor['Neighbor'] == bgp_neighbor), None)

                if existing_neighbor is None:
                    current_neighbor_info = {'Neighbor':bgp_neighbor, 'Peer-Group':None, 'Password':None}
                    
                    regex_pattern_bgp_peer_match = re.match(r'peer-group (?P<peer>\w+)', bgp_neighbor_config)
                    if regex_pattern_bgp_peer_match:
                        bgp_peer_group = regex_pattern_bgp_peer_match.group('peer')
                        current_neighbor_info['Peer-Group'] = bgp_peer_group

                    regex_pattern_bgp_password_match = re.match(r'password (?P<password>\S+)', bgp_neighbor_config)
                    if regex_pattern_bgp_password_match:
                        bgp_password = regex_pattern_bgp_password_match.group('password')
                        current_neighbor_info['Password'] = bgp_password
                
                    bgp_neighbor_list.append(current_neighbor_info)

                else:
                    regex_pattern_bgp_peer_match = re.match(r'peer-group (?P<peer>\w+)', bgp_neighbor_config)
                    if regex_pattern_bgp_peer_match:
                        bgp_peer_group = regex_pattern_bgp_peer_match.group('peer')
                        current_neighbor_info['Peer-Group'] = bgp_peer_group

                    regex_pattern_bgp_password_match = re.match(r'password (?P<password>\S+)',bgp_neighbor_config)
                    if regex_pattern_bgp_password_match:
                        bgp_password = regex_pattern_bgp_password_match.group('password')
                        current_neighbor_info['Password'] = bgp_password

            else:
                existing_peer = next((peer for peer in bgp_peer_list if peer['Peer'] == bgp_neighbor), None)

                if existing_peer is None:
                    current_peer_info = {'Peer':bgp_neighbor, 'Password':None}
                    regex_pattern_bgp_password_match = re.match(r'password (?P<password>\S+)', bgp_neighbor_config)

                    if regex_pattern_bgp_password_match:
                        bgp_password = regex_pattern_bgp_password_match.group('password')
                        current_peer_info['Password'] = bgp_password
                    
                    bgp_peer_list.append(current_peer_info)
                
                else:
                    regex_pattern_bgp_password_match = re.match(r'password (?P<password>\S+)', bgp_neighbor_config)
                    if regex_pattern_bgp_password_match:
                        bgp_password = regex_pattern_bgp_password_match.group('password')
                        current_peer_info['Password'] = bgp_password
        
        current_bgp_info = {'Autonomous System':bgp_autonomous_system, 'Neighbor':bgp_neighbor_list if bgp_neighbor_list else None, 
                            'Peer-Group':bgp_peer_list if bgp_peer_list else None}
        bgp_list.append(current_bgp_info)

        for neighbor in bgp_neighbor_list:
            
            if neighbor['Peer-Group'] == None and neighbor['Password'] == None:
                non_compliant_neighbor_counter += 1
        
        non_compliant_peer_check = any('Password' in peer and not peer['Password'] for peer in bgp_peer_list)
        if non_compliant_peer_check:
            non_compliant_peer_counter += 1
    
    

    compliant = non_compliant_neighbor_counter == 0 and non_compliant_peer_counter == 0
    current_configuration = bgp_list
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))