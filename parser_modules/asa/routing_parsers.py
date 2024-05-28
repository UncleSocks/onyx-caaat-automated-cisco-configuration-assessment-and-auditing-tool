import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_enabled_routing_protocols(connection, routing_protocol):
    command = f"show running-config router | include {routing_protocol}"
    command_output = ssh_send(connection, command)

    if command_output:
        return True
    else:
        return False


def compliance_check_ospf(connection, command_one, command_two, cis_check, level, global_report_output):
    
    def compliance_check_enabled_ospf(connection):
    
        routing_protocol = "ospf"

        if compliance_check_enabled_routing_protocols(connection, routing_protocol) == False:
            compliant = "Not Applicable"
            current_configuration = "OSPF not enabled"
            global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            return False
        
        else:
            return True
        
    
    def compliance_check_ospf_int(connection, command):
        command_output = ssh_send(connection, command)
        
        ospf_int_list = []

        regex_pattern = re.compile(r'interface\s+(?P<interface>\S+)(?:(?!interface)).*?ospf\s+message-digest-key\s+(?P<key>\d+)\s+md5\s+(?P<md5_key>(?:\d+\s+\S+)|\S+)\n(?:.*(?=(?:interface|$)))', re.DOTALL)
        ospf_int_match = regex_pattern.findall(command_output)

        if ospf_int_match:
            for ospf_int in ospf_int_match:
                interface = ospf_int[0]
                key_id = ospf_int[1]
                md5_key = ospf_int[2]

                current_ospf_int_info = {'Interface':interface, 'Key ID':key_id, 'MD5 Key':md5_key}
                ospf_int_list.append(current_ospf_int_info)

        return ospf_int_list if ospf_int_list else None
    

    def compliance_check_ospf_auth(connection, command_one, command_two, cis_check, level, global_report_output):
        command_output = ssh_send(connection, command_one)
        regex_pattern = re.compile(r'router ospf (?P<id>\d+)(?:.*?(?P<config>.*?))(?=\nrouter ospf|$)', re.DOTALL)    
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
                    
                    [unique_area_with_auth_list.append(area) for area in area_list if area not in unique_area_with_auth_list]

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

            ospf_int_list = compliance_check_ospf_int(connection, command_two)
            ospf_list.append(ospf_int_list)
                    
        compliant = non_compliant_ospf_counter == 0
        current_configuration = ospf_list
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))

    if compliance_check_enabled_ospf(connection) == True:
        compliance_check_ospf_auth(connection, command_one, command_two, cis_check, level, global_report_output)


def compliance_check_eigrp(connection, command_one, command_two, cis_check, level, global_report_output):

    def compliance_check_enabled_eigrp(connection):
        
        routing_protocol = "eigrp"

        if compliance_check_enabled_routing_protocols(connection, routing_protocol) == False:
            compliant = "Not Applicable"
            current_configuration = "EIGRP not enabled"
            global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
            return False
        
        else:
            return True
        
    
    def compliance_check_eigrp_auth(connection, command, cis_check, level, global_report_output):
        print("EIGRP is enabled")

    if compliance_check_enabled_eigrp(connection) == True:
        compliance_check_eigrp_auth(connection, command_one, cis_check, level, global_report_output)