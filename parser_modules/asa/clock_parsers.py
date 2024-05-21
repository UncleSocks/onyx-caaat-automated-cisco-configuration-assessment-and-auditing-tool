import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_ntp_authentication_key(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    ntp_authentication_key_list = []

    regex_pattern = re.compile(r'^ntp\s+authentication-key\s+(?P<key>\d+)\s+(?P<key_mode>\S+)\s+(?P<key_string>(?:\d+\s+\S+)|\S+)(?=\n|$)', re.MULTILINE)
    ntp_authentication_key_match = regex_pattern.findall(command_output)

    if ntp_authentication_key_match:
        for ntp_authentication_key in ntp_authentication_key_match:
            key = ntp_authentication_key[0]
            key_mode = ntp_authentication_key[1]
            key_string = ntp_authentication_key[2]

            current_ntp_authentication_key_info = {'Key':key, 'Key Mode':key_mode, 'Key String':key_string}
            ntp_authentication_key_list.append(current_ntp_authentication_key_info)

    current_configuration = ntp_authentication_key_list if ntp_authentication_key_list else None
    compliant = bool(ntp_authentication_key_match)
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_ntp_server(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    ntp_server_list = []

    regex_pattern = re.compile(r'^ntp\s+server\s+(?P<address>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})\s+key\s+(?P<key>\d+)\s+source\s+(?P<interface>\S+)(?=\n|$)', re.MULTILINE)
    ntp_server_match = regex_pattern.findall(command_output)

    if ntp_server_match:
        for ntp_server in ntp_server_match:
            address = ntp_server[0]
            key = ntp_server[1]
            interface = ntp_server[2]

            current_ntp_server_info = {'Address':address, 'Key':key, 'Interface':interface}
            ntp_server_list.append(current_ntp_server_info)

    current_configuration = ntp_server_list if ntp_server_list else None
    compliant = bool(ntp_server_match)
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_local_timezone(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    current_configuration = None
    local_timezone_match = re.match(r'clock\s+timezone\s+(?P<zone_name>\w+)\s+(?P<offset>(?:-)\d+)', command_output)

    if local_timezone_match:
        zone_name = local_timezone_match.group('zone_name')
        offset_value = local_timezone_match.group('offset')

        current_configuration = {'Zone':zone_name, 'Offset':offset_value}

    compliant = local_timezone_match is not None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))