import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_noproxyarp(connection, cis_check, level, global_report_output, untrusted_nameifs_list):

    if untrusted_nameifs_list:
        
        non_compliant_untrusted_nameifs_list = untrusted_nameifs_list.copy()
        compliant_untrusted_nameifs_list = []
        non_existent_untrusted_nameifs_list = []

        for untrusted_nameif in untrusted_nameifs_list:
            noproxy_untrusted_nameif_command = f"show running-config systopt | grep proxyarp.{untrusted_nameif}"
            command_output = ssh_send(connection, noproxy_untrusted_nameif_command)

            non_existent_interface_search = re.search(r'ERROR:(?:\s*.*?)', command_output)

            if command_output and not non_existent_interface_search:
                non_compliant_untrusted_nameifs_list.remove(untrusted_nameif)
                compliant_untrusted_nameifs_list.append(untrusted_nameif)

            elif command_output and non_existent_interface_search:
                non_compliant_untrusted_nameifs_list.remove(untrusted_nameif)
                non_existent_untrusted_nameifs_list.append(untrusted_nameif)

        compliant = not bool(non_compliant_untrusted_nameifs_list)
        current_configuration = {'ARP Proxy Disabled Untrusted Interfaces':compliant_untrusted_nameifs_list if compliant_untrusted_nameifs_list else None,
                                'ARP Proxy Enabled Untrusted Interfaces':non_compliant_untrusted_nameifs_list if non_compliant_untrusted_nameifs_list else None,
                                'Non-existend Untrusted Interfaces':non_existent_untrusted_nameifs_list if non_existent_untrusted_nameifs_list else None}

    else:
        compliant = "Not Applicable"
        current_configuration = "Untrusted interface list empty."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_dhcp_services(connection, cis_check, level, global_report_output, untrusted_nameifs_list):

    if untrusted_nameifs_list:

        untrusted_nameifs_dhcp_server_list = []
        untrusted_nameifs_dhcp_relay_list = []

        dhcp_server_check_command = "show running-config | include dhcpd.enable"
        dhcp_server_check = ssh_send(connection, dhcp_server_check_command)

        dhcp_relay_check_command = "show running-config | include dhcprelay.enable"
        dhcp_relay_check = ssh_send(connection, dhcp_relay_check_command)

        if dhcp_server_check:
            for untrusted_nameif in untrusted_nameifs_list:
                dhcp_server_untrusted_nameif_command = f"show running-config | include dhcpd.enable.{untrusted_nameif}"
                command_output = ssh_send(connection, dhcp_server_untrusted_nameif_command)

                non_existent_interface_search = re.search(r'ERROR:(?:\s*.*?)', command_output)

                if command_output and not non_existent_interface_search:
                    untrusted_nameifs_dhcp_server_list.append(untrusted_nameif)

            current_configuration = {'DHCP Server Untrusted Interfaces':untrusted_nameifs_dhcp_server_list, 'DHCP Relay Untrusted Interfaces':"Firewall is configured as a DHCP server."}

        elif dhcp_relay_check:
            for untrusted_nameif in untrusted_nameifs_list:
                dhcp_relay_untrusted_nameif_command = f"show running-config | include dhcprelay.enable.{untrusted_nameif}"
                command_output = ssh_send(connection, dhcp_relay_untrusted_nameif_command)

                if command_output:
                    untrusted_nameifs_dhcp_relay_list.append(untrusted_nameif)

            current_configuration = {'DHCP Server Untrusted Interfaces':"Firewall is configured as a DHCP relay.", 'DHCP Relay Untrusted Interfaces':untrusted_nameifs_dhcp_relay_list}

        else:
            current_configuration = {'DHCP Server Untrusted Interfaces':None, 'DHCP Relay Untrusted Interfaces':None}

        compliant = not bool(untrusted_nameifs_dhcp_server_list) and not bool(untrusted_nameifs_dhcp_relay_list)

    else:
        compliant = "Not Applicable"
        current_configuration = "Untrusted interface list empty."
    
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_icmp_deny(connection, cis_check, level, global_report_output, untrusted_nameifs_list):

    if untrusted_nameifs_list:
        
        non_compliant_untrusted_nameifs_list = untrusted_nameifs_list.copy()
        compliant_untrusted_nameifs_list = []
        non_existent_untrusted_nameifs_list = []

        for untrusted_name_if in untrusted_nameifs_list:
            icmp_deny_untrusted_nameif_command = f"show running-config icmp | include deny.any.{untrusted_name_if}"
            command_output = ssh_send(connection, icmp_deny_untrusted_nameif_command)

            non_existent_interface_search = re.search(r'ERROR:(?:\s*.*?)', command_output)

            if command_output and not non_existent_interface_search:
                non_compliant_untrusted_nameifs_list.remove(untrusted_name_if)
                compliant_untrusted_nameifs_list.append(untrusted_name_if)

            elif command_output and non_existent_interface_search:
                non_compliant_untrusted_nameifs_list.remove(untrusted_name_if)
                non_existent_untrusted_nameifs_list.append(untrusted_name_if)

        compliant = not bool(non_compliant_untrusted_nameifs_list)
        current_configuration = {'ICMP Deny Any Untrusted Interfaces':compliant_untrusted_nameifs_list if compliant_untrusted_nameifs_list else None, 
                                 'No ICMP Deny Any Untrusted Interfaces':non_compliant_untrusted_nameifs_list if non_compliant_untrusted_nameifs_list else None,
                                 'Non-existent Untrusted Interfaces':non_existent_untrusted_nameifs_list if non_existent_untrusted_nameifs_list else None}

    else:
        compliant = "Not Applicable"
        current_configuration = "Untrusted interface list empty."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))