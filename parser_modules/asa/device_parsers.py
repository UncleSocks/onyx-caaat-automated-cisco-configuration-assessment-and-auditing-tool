import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_unused_interface(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    unused_initerface_list = []
    current_configuration = {'Unused Interfaces':None}

    regex_pattern = re.compile(r'(?P<interface>\S+)\s+.*?(?=\n|$)')
    unused_interface_match = regex_pattern.findall(command_output)

    if unused_interface_match:
        for unused_interface in unused_interface_match:
            unused_initerface_list.append(unused_interface)
        current_configuration['Unused Interfaces'] = unused_initerface_list

    compliant = not unused_interface_match
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))




