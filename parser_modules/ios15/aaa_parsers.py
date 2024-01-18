import re
from ssh_module import ssh_send
from report_modules.main_report import generate_report


def compliance_check_aaa_auth_line(connection, command, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'line (?P<line_type>con|vty|tty) (?P<channel>\d+(?: \d)?)\n(?P<config>.*?)(?=\nline|\Z)', re.DOTALL)
    parser = regex_pattern.finditer(command_output)
    expected_lines = [{'line':'con', 'index':4, 'config':None}, {'line':'tty', 'index':5, 'config':None}, {'line':'vty', 'index':6, 'config':None}]
    existing_lines = []

    for match in parser:
        line_type = match.group('line_type')
        config = match.group('config')
        existing_lines.append(line_type)
        for line in expected_lines:
            if line['line'] == line_type:
                line['config'] = config
                break

    unique_existing_lines = set(existing_lines)

    for line_info in expected_lines:
        compliant = line_info['line'] in unique_existing_lines
        cis_check = f"1.1.{line_info['index']} Set 'authentication login' for 'line {line_info['line']}'"
        current_configuration = line_info['config']
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_aaa_source_int(connection, command_one, command_two, cis_check, level, global_report_output):
    command_output_one = ssh_send(connection, command_one)
    command_output_two = ssh_send(connection, command_two)
    if not command_output_one and not command_output_two:
        compliant = False
        current_configuration = None
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
    else:
        compliant = True
        current_configuration = f"TACACS+:{command_output_one if command_output_one else None}, RADIUS:{command_output_two if command_output_two else None}"
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))