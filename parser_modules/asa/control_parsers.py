import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_noproxyarp(connection, cis_check, level, global_report_output, untrusted_nameifs_list):

    if untrusted_nameifs_list:
        
        non_compliant_untrusted_nameifs_list = untrusted_nameifs_list
        compliant_untrusted_nameifs_list = []

        for untrusted_nameif in untrusted_nameifs_list:
            noproxy_untrusted_nameif_command = f"show running-config systopt | grep proxyarp.{untrusted_nameif}"
            command_output = ssh_send(connection, noproxy_untrusted_nameif_command)

            if command_output:
                non_compliant_untrusted_nameifs_list.remove(untrusted_nameif)
                compliant_untrusted_nameifs_list.append(untrusted_nameif)

        compliant = not bool(non_compliant_untrusted_nameifs_list)
        current_configuration = {'ARP Proxy Disabled Untrusted Interfaces':compliant_untrusted_nameifs_list if compliant_untrusted_nameifs_list else None,
                                'ARP Proxy Enabled Untrusted Interfaces':non_compliant_untrusted_nameifs_list if non_compliant_untrusted_nameifs_list else None}

    else:
        compliant = "Not Applicable"
        current_configuration = "Untrusted interface list (nameif.txt) is not defined."

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
