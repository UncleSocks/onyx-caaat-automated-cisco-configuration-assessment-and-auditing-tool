import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_aaa_auth_line_vty(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'line vty (?P<channel>\d+(?: \d)?)?(\n(?P<config>.*?))?(\nline vty|$)', re.DOTALL | re.MULTILINE)
    parser = regex_pattern.finditer(command_output)

    line_vty_list = []
    non_compliant_vty_counter = 0

    for match in parser:
        line_channel = match.group('channel')
        line_config = match.group('config') if match.group('config') else None
        current_line_vty_info = {'Channel':line_channel, 'Config':line_config}
        line_vty_list.append(current_line_vty_info)

        if current_line_vty_info['Config'] == None:
            non_compliant_vty_counter += 1
    
    compliant = bool(line_vty_list) and non_compliant_vty_counter == 0
    current_configuration = line_vty_list if line_vty_list else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))