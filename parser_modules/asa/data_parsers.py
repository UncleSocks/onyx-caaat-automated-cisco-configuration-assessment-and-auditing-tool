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