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
            key_mode = ntp_authentication_key_match[1]
            key_string = ntp_authentication_key_match[2]

            current_ntp_authentication_key_info = {'Key':key, 'Key Mode':key_mode, 'Key String':key_string}
            ntp_authentication_key_list.append(current_ntp_authentication_key_info)

    current_configuration = ntp_authentication_key_list if ntp_authentication_key_list else None
    compliant = ntp_authentication_key_match is not None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))