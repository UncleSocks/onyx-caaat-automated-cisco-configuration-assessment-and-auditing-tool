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

            for untrusted_nameif in untrusted_nameifs_list:
                for ips_audit_name in ips_audit_name_list:
                    ips_audit_untrusted_nameif_command = f"show running-config ip audit interface {untrusted_nameif} | include {ips_audit_name}" 
                    command_output = ssh_send(connection, ips_audit_untrusted_nameif_command)

                    non_existent_interface_search = re.search(r'ERROR:(?:\s*.*?)', command_output)

                    if command_output and not non_existent_interface_search:
                        non_compliant_untrusted_nameifs_list.remove(untrusted_nameif)
                        compliant_untrusted_nameifs_list.append(untrusted_nameif)
                        break

            compliant = not bool(non_compliant_untrusted_nameifs_list) and non_compliant_ips_audit_counter == 0
            current_configuration = {'IPS Audit List':ips_audit_list, 
                                     'Intrusion Prevention Enabled Untrusted Interfaces':compliant_untrusted_nameifs_list if compliant_untrusted_nameifs_list else None,
                                     'No Intrusion Prevention Unstrusted Interfcaes':non_compliant_untrusted_nameifs_list if non_compliant_untrusted_nameifs_list else None}
            
        else:
            compliant = "Not Applicable"
            current_configuration = {'IPS Audit List':ips_audit_list, 
                                     'Intrusion Prevention Enabled Untrusted Interfaces':"Untrusted interfaces list is not defined.",
                            'No Intrusion Prevention Unstrusted Interfcaes':"Untrusted interfaces list is not defined."}

    else:
        compliant = False
        current_configuration = "No Intrusion Prevention configured."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
