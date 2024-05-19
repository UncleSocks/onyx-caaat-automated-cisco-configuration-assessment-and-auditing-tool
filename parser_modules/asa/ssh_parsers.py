import re
from ssh import ssh_send
from report_modules.main_report import generate_report

def compliance_check_ssh_source_restriction(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    ssh_source_restriction_list = []

    regex_pattern = re.compile(r"^ssh\s+(?P<address>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})\s+(?P<subnet>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})\s+(?P<interface>\S+)(?:\n|$)", re.MULTILINE)
    #regex_pattern currently only supports IPv4 addresses.
    ssh_source_restriction_match = regex_pattern.findall(command_output)
    
    if ssh_source_restriction_match:

        for ssh_source_restriction in ssh_source_restriction_match:
            address = ssh_source_restriction[0]
            subnet = ssh_source_restriction[1]
            interface = ssh_source_restriction[2]

            current_ssh_source_restriction_info = {'Address':address, 'Subnet':subnet, 'Interface':interface}
            ssh_source_restriction_list.append(current_ssh_source_restriction_info)
            
    current_configuration = ssh_source_restriction_list if ssh_source_restriction_list else None
    compliant = ssh_source_restriction_list is not None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_ssh_version(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    ssh_version_match = re.match(r'ssh\s+version\s+(?P<version>\d+)', command_output)

    current_configuration = {'SSH Version':None}
    compliant = False
    
    if ssh_version_match:
        ssh_version = int(ssh_version_match.group('version'))

        if ssh_version == 2:
            compliant = True

        current_configuration['SSH Version'] = ssh_version

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_rsa_modulus_size(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    current_configuration = {'Modulus Size':"No key exists."}
    compliant = False

    modulus_size_search = re.search(r'(?:Key|Modulus)\s+Size\s+\(bits\)\:\s+(?P<size>\d+)', command_output, re.IGNORECASE)

    if modulus_size_search:
        modulus_size = int(modulus_size_search.group('size'))

        if modulus_size >= 2048:
            compliant = True

        current_configuration['Modulus Size'] = modulus_size

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_telnet(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    telnet_list = []

    regex_pattern = re.compile(r"^telnet\s+(?P<address>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})\s+(?P<subnet>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})\s+(?P<interface>\S+)(?:\n|$)", re.MULTILINE)
    telnet_match = regex_pattern.findall(command_output)

    if telnet_match:
        
        telnet_status = "Enabled"
        
        for telnet in telnet_match:
    
            address = telnet[0]
            subnet = telnet[1]
            interface = telnet[2]

            current_telnet_info = {'Address':address, 'Subnet':subnet, 'Interface':interface}
            telnet_list.append(current_telnet_info)

    else:
        telnet_status = "Disabled"

    current_configuration = {'Status':telnet_status, 'Telnet Information':telnet_list if telnet_list else None}
    compliant = telnet_status == "Disabled"
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))