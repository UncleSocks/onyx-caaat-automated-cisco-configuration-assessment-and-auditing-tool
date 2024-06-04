import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_dns_services(connection, command, cis_check, level, global_report_output, dns_server_list):
    command_output = ssh_send(connection, command)

    domain_lookup_nameif_list = []

    regex_pattern = re.compile(r'dns\s+domain-lookup\s+(?P<interface>\S+)', re.MULTILINE)
    domain_lookup_match = regex_pattern.findall(command_output)

    if domain_lookup_match:
    
        domain_lookup_nameif_list = domain_lookup_match

        if dns_server_list:

            unconfigured_dns_server_list = dns_server_list.copy()
            configured_dns_server_list = []

            for dns_server in dns_server_list:
                dns_server_command = f"show running-config all | include name-server_{dns_server}"
                command_output = ssh_send(connection, dns_server_command)
                
                if command_output:
                    unconfigured_dns_server_list.remove(dns_server)
                    configured_dns_server_list.append(dns_server)

            compliant = not bool(unconfigured_dns_server_list)
            current_configuration = {'Domain-Lookup Interfaces':domain_lookup_nameif_list, 
                                     'Configured DNS Servers':configured_dns_server_list if configured_dns_server_list else None, 
                                     'Unconfigured DNS Servers':unconfigured_dns_server_list if unconfigured_dns_server_list else None}

        else:
            compliant = "Not Applicable"
            current_configuration = {'Domain-Lookup Interfaces':domain_lookup_nameif_list, 
                                     'Configured DNS Servers':"Authorized DNS server list is not defined.", 
                                     'Unconfigured DNS Servers':"Authorized DNS server list is not defined."}

    else:
        compliant = False
        current_configuration = "DNS domain-lookup not enabled."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_ips(connection, command, cis_check, level, global_report_output, untrusted_nameifs_list):
    command_output = ssh_send(connection, command)

    non_compliant_ips_audit_counter = 0
    ips_audit_list = []
    ips_audit_name_list = []

    regex_pattern = re.compile(r'ip\s+audit\s+name\s+(?P<audit_name>\S+)\s+attack\s+action(?:\s+(?P<action>(?:alarm|drop|reset)(?:\s+(?:alarm|drop|reset))*))?', re.MULTILINE)
    ips_audit_match = regex_pattern.findall(command_output)

    if ips_audit_match:
        for ips_audit in ips_audit_match:
            ips_audit_name = ips_audit[0]
            ips_audit_action = ips_audit[1] if ips_audit[1] else "default"

            if ips_audit_action == "default" or ips_audit_action == "alarm":
                non_compliant_ips_audit_counter += 1
            
            ips_audit_name_list.append(ips_audit_name)

            current_ips_audit_info = {'IPS Audit Name':ips_audit_name, 'IPS Audit Action':ips_audit_action}
            ips_audit_list.append(current_ips_audit_info)
            

        if untrusted_nameifs_list:
            non_compliant_untrusted_nameifs_list = untrusted_nameifs_list.copy()
            compliant_untrusted_nameifs_list = []
            non_existent_untrusted_nameifs_list = []

            for untrusted_nameif in untrusted_nameifs_list:
                for ips_audit_name in ips_audit_name_list:
                    ips_audit_untrusted_nameif_command = f"show running-config ip audit interface {untrusted_nameif} | include {ips_audit_name}" 
                    command_output = ssh_send(connection, ips_audit_untrusted_nameif_command)

                    non_existent_interface_search = re.search(r'ERROR:(?:\s*.*?)', command_output)

                    if command_output and not non_existent_interface_search:
                        non_compliant_untrusted_nameifs_list.remove(untrusted_nameif)
                        compliant_untrusted_nameifs_list.append(untrusted_nameif)
                        break

                    elif command_output and non_existent_interface_search:
                        non_compliant_untrusted_nameifs_list.remove(untrusted_nameif)
                        non_existent_untrusted_nameifs_list.append(untrusted_nameif)
                        break

            compliant = not bool(non_compliant_untrusted_nameifs_list) and non_compliant_ips_audit_counter == 0
            current_configuration = {'IPS Audit List':ips_audit_list, 
                                     'Intrusion Prevention Enabled Untrusted Interfaces':compliant_untrusted_nameifs_list if compliant_untrusted_nameifs_list else None,
                                     'No Intrusion Prevention Unstrusted Interfcaes':non_compliant_untrusted_nameifs_list if non_compliant_untrusted_nameifs_list else None,
                                     'Non-existent Untrusted Interfaces':non_existent_untrusted_nameifs_list if non_existent_untrusted_nameifs_list else None}
            
        else:
            compliant = "Not Applicable"
            current_configuration = {'IPS Audit List':ips_audit_list, 
                                     'Intrusion Prevention Enabled Untrusted Interfaces':"Untrusted interfaces list is not defined.",
                                     'No Intrusion Prevention Unstrusted Interfcaes':"Untrusted interfaces list is not defined."}

    else:
        compliant = False
        current_configuration = "No Intrusion Prevention configured."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_fragments(connection, cis_check, level, global_report_output, untrusted_nameifs_list):

    if untrusted_nameifs_list:

        non_compliant_untrusted_nameifs_list = untrusted_nameifs_list.copy()
        compliant_untrusted_nameifs_list = []
        non_existent_untrusted_nameifs_list = []

        for untrusted_name_if in untrusted_nameifs_list:
            packet_fragment_untrusted_nameif_command = f"show running-config fragment {untrusted_name_if} | include chain_1_"
            command_output = ssh_send(connection, packet_fragment_untrusted_nameif_command)

            non_existent_interface_search = re.search(r'ERROR:(?:\s*.*?)', command_output)

            if command_output and not non_existent_interface_search:
                non_compliant_untrusted_nameifs_list.remove(untrusted_name_if)
                compliant_untrusted_nameifs_list.append(untrusted_name_if)

            elif command_output and non_existent_interface_search:
                non_compliant_untrusted_nameifs_list.remove(untrusted_name_if)
                non_existent_untrusted_nameifs_list.append(untrusted_name_if)

        compliant = not bool(non_compliant_untrusted_nameifs_list)
        current_configuration = {'Restricted Packet Fragments Untrusted Interfaces':compliant_untrusted_nameifs_list if compliant_untrusted_nameifs_list else None,
                                 'Untrestricted Packet Fragments Untrusted Interfaces':non_compliant_untrusted_nameifs_list if non_compliant_untrusted_nameifs_list else None,
                                 'Non-existent Untrusted Interfaces':non_existent_untrusted_nameifs_list if non_existent_untrusted_nameifs_list else None}
        
    else:
        compliant = "Not Applicable"
        current_configuration = "Untrusted interface list empty."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_application_inspection(connection, command, cis_check, level, global_report_output, non_default_protocol_list):
    command_output = ssh_send(connection, command)

    inspection_default_config_search = re.search(r'\s*class\s+inspection_default\s*\n(?:(?P<protocol_list>(?:\s*inspect\s+\S+.*\n)*))', command_output)
    regex_protocol_list = inspection_default_config_search.group('protocol_list')

    regex_pattern = re.compile(r'^\s*inspect\s+(?P<protocol>\S+)', re.MULTILINE)
    default_protocol_list = regex_pattern.findall(regex_protocol_list)

    supported_protocol_list = ["ctiqbe", "dcerpc", "diameter", "dns", "esmtp", "ftp", "gtp", "h323", "http", "icmp", 
                               "ils", "im", "ip-options", "ipsec-pass-thru", "ipv6", "lisp", "m3ua", "mgcp", "mmp",
                               "netbios", "pptp", "rsh", "rtsp", "scansafe", "sctp", "sip", "skinny", "snmp", "sqlnet",
                               "stun", "sunrpc", "tftp", "vxlan", "waas", "xdmcp"]
    
    non_existent_protocol_list = []

    inspected_non_default_protocol_list = []
    uninspected_non_default_protocol_list = []

    if non_default_protocol_list:
    
        for non_default_protocol in non_default_protocol_list:
            
            if non_default_protocol.lower() not in supported_protocol_list:
                non_existent_protocol_list.append(non_default_protocol.lower())

            elif non_default_protocol.lower() in supported_protocol_list and non_default_protocol.lower() in default_protocol_list:
                inspected_non_default_protocol_list.append(non_default_protocol.lower())

            elif non_default_protocol.lower() in supported_protocol_list and non_default_protocol.lower() not in default_protocol_list:
                non_default_protocol_command = f"show running-config policy-map | include __inspect.{non_default_protocol.lower()}"
                non_default_protocol_command_output = ssh_send(connection, non_default_protocol_command)

                if non_default_protocol_command_output:
                    inspected_non_default_protocol_list.append(non_default_protocol.lower())

                else:
                    uninspected_non_default_protocol_list.append(non_default_protocol.lower())

            compliant = not bool(uninspected_non_default_protocol_list)
            current_configuration = {'Inspected Applications':inspected_non_default_protocol_list if inspected_non_default_protocol_list else None,
                                    'Uninspected Applications':uninspected_non_default_protocol_list if uninspected_non_default_protocol_list else None,
                                    'Unsupported Applications':non_existent_protocol_list if non_existent_protocol_list else None,
                                    'Default Policy Inspected Applications':default_protocol_list if default_protocol_list else None}
            
    else:

        compliant = "Not Applicable"
        current_configuration = {'Inspected Applications':"Non-standard application list is not defined.",
                        'Uninspected Applications':"Non-standard application list is not defined.",
                        'Unsupported Applications':"Non-standard application list is not defined.",
                        'Default Policy Inspected Applications':default_protocol_list if default_protocol_list else None}
        
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_reverse_path(connection, cis_check, level, global_report_output, untrusted_nameifs_list):

    if untrusted_nameifs_list:

        non_compliant_untrusted_nameifs_list = untrusted_nameifs_list.copy()
        compliant_untrusted_nameifs_list = []
        non_existent_untrusted_nameifs_list = []

        for untrusted_nameif in untrusted_nameifs_list:
            reverse_path_untrusted_nameif_command = f"show running-config ip verify reverse-path interface {untrusted_nameif}"
            command_output = ssh_send(connection, reverse_path_untrusted_nameif_command)
            
            non_existent_interface_search = re.search(r'ERROR:(?:\s*.*?)', command_output)

            if command_output and not non_existent_interface_search:
                non_compliant_untrusted_nameifs_list.remove(untrusted_nameif)
                compliant_untrusted_nameifs_list.append(untrusted_nameif)

            elif command_output and non_existent_interface_search:
                non_compliant_untrusted_nameifs_list.remove(untrusted_nameif)
                non_existent_untrusted_nameifs_list.append(untrusted_nameif)

        compliant = not bool(non_compliant_untrusted_nameifs_list)
        current_configuration = {'Reverse Path Untrusted Interfaces':compliant_untrusted_nameifs_list if compliant_untrusted_nameifs_list else None,
                                 'Unconfigured Reverse Path Untrusted Interfaces':non_compliant_untrusted_nameifs_list if non_compliant_untrusted_nameifs_list else None,
                                 'Non-existent Reverse Path Untrusted Interfaces':non_existent_untrusted_nameifs_list if non_existent_untrusted_nameifs_list else None}
        
    else:
        compliant = "Not Applicable"
        current_configuration = "Untrusted interface list empty."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_security_level(connection, cis_check, level, global_report_output, internet_facing_int_list):

    if internet_facing_int_list:

        non_compliant_internet_facing_int_counter = 0
        processed_internet_facing_int_list = []
        non_existent_internet_facing_int_list = []

        for internet_facing_int in internet_facing_int_list:
 
            internet_facing_int_command = f"show running-config interface {internet_facing_int}"
            command_output = ssh_send(connection, internet_facing_int_command)
            print(command_output)

            security_level_search = re.search(r'security-level\s+(?P<level>\d+)', command_output)
            non_existent_interface_search = re.search(r'ERROR:(?:\s*.*?)', command_output)

            if security_level_search and not non_existent_interface_search:
                security_level = int(security_level_search.group('level'))
                if security_level != 0:
                    non_compliant_internet_facing_int_counter += 1

                current_internetfacing_int_info = {'Internet Facing Interface':internet_facing_int, 'Security Level':security_level}
                processed_internet_facing_int_list.append(current_internetfacing_int_info)

            elif security_level_search and non_existent_interface_search:
                non_existent_internet_facing_int_list.append(internet_facing_int)

        compliant = non_compliant_internet_facing_int_counter == 0
        current_configuration = {'Internet Facing Interfaces':processed_internet_facing_int_list if processed_internet_facing_int_list else None, 
                                 'Non-existent Internet Facing Interfaces':non_existent_internet_facing_int_list if non_existent_internet_facing_int_list else None}
        
    else:
        compliant = "Not Applicable"
        current_configuration = "Internet-facing list is not defined."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))