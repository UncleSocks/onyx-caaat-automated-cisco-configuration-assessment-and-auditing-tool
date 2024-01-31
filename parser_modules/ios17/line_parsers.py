import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_transport_input(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'line vty (?P<start>\d+)(?: (?P<end>\d+))?(\n(?P<config>.*?)(?=\nline vty|\Z))', re.MULTILINE | re.DOTALL)
    parser = regex_pattern.finditer(command_output)
    transport_inputs = []
    non_compliant_transport_input_counter = 0

    for match in parser:
        line_start = match.group('start')
        line_end = match.group('end') if match.group('end') else None 
        config = match.group('config')
        config_regex_pattern_search = re.search(r'transport input (?P<input>ssh|telnet|all|none|telnet ssh)(?=\n|\Z)', config)

        if config_regex_pattern_search:
            transport_input = config_regex_pattern_search.group('input')
            if transport_input == "ssh":
                compliant_transport_input_info = {'Start':line_start, 'End':line_end, 'Transport Input':transport_input}
                transport_inputs.append(compliant_transport_input_info)
            else:
                non_compliant_transport_input_info = {'Start':line_start, 'End':line_end, 'Transport Input':transport_input}
                transport_inputs.append(non_compliant_transport_input_info)
                non_compliant_transport_input_counter += 1

    compliant = non_compliant_transport_input_counter == 0
    current_configuration = transport_inputs
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_aux_exec(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    exec_search = re.search(r'no exec', command_output)

    compliant = bool(exec_search)
    current_configuration = exec_search.group() if exec_search else None

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_vty_acl(connection, command_one, command_two, cis_check_one, cis_check_two, level, global_report_output):
    command_output = ssh_send(connection, command_one)

    if not command_output:
        compliant = False
        current_configuration = None
        global_report_output.append(generate_report(cis_check_one, level, compliant, current_configuration))
        global_report_output.append(generate_report(cis_check_two, level, compliant, current_configuration))

    else:
        compliant = True
        current_configuration = command_output
        global_report_output.append(generate_report(cis_check_one, level, compliant, current_configuration))
        return compliance_check_vty_ac(connection, command_two, cis_check_two, level, global_report_output)
    

def compliance_check_vty_ac(connection, command, cis_check, level, global_report_output):
        command_output = ssh_send(connection, command)
        regex_pattern = re.compile(r'line vty (?P<start>\d+)(?: (?P<end>\d+))?(\n(?P<config>.*?)(?=\nline vty|\Z))', re.MULTILINE | re.DOTALL)
        parser = regex_pattern.finditer(command_output)
        vty_access_classes = []
        no_access_class_counter = 0

        for match in parser:
            line_start = match.group('start')
            line_end = match.group('end') if match.group('end') else None
            config = match.group('config')
            config_regex_pattern_search = re.search(r'access-class (?P<ac>\d+)\s+(?P<dir>\S+)(?=\n|\Z)', config)

            if config_regex_pattern_search:
                access_class = config_regex_pattern_search.group['ac']
                direction = config_regex_pattern_search.group['dir']
                vty_access_class_info = {'Start':line_start, 'End':line_end, 'Access-Class':access_class, 'Direction':direction}
                vty_access_classes.append(vty_access_class_info)

            else:
                no_access_class_counter += 1
                vty_access_class_info = {'Start':line_start, 'End':line_end, 'Access-Class':None}
                vty_access_classes.append(vty_access_class_info)

        compliant = no_access_class_counter == 0
        current_configuration = vty_access_classes
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_exec_timeout(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    exec_timeout_search = re.search(r'exec-timeout (?P<min>\d+)\s+(?P<sec>\d+)', command_output)

    if exec_timeout_search:
        exec_timeout_min = int(exec_timeout_search.group('min'))
        exec_timeout_sec = int(exec_timeout_search.group('sec'))

        compliant = exec_timeout_min <= 9
        current_configuration = {'Exec-Timeout Minute':exec_timeout_min, 'Exec-Timeout Second':exec_timeout_sec}
    
    else:
        compliant = True
        current_configuration = {'Exec-Timeout Minute':10, 'Exec-Timeout Second':0}

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
