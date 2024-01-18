import re
from ssh_module import ssh_send
from report_modules.main_report import generate_report


def compliance_check_acl_privilege(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'username (?P<user>\S+) privilege (?P<level>\d+)', re.MULTILINE)
    parser = regex_pattern.finditer(command_output)
    local_users = []

    for match in parser:
        current_user = match.group('user')
        current_level = match.group('level')
        current_user_info = {'user':current_user, 'level':current_level}
        local_users.append(current_user_info)

    compliant = not local_users
    current_configuration = local_users if local_users else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_user_secret(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    regex_pattern = re.compile(r'username (?P<user>\S+) (?P<config>.*?)(?=\nusername|\Z)', re.DOTALL)
    parser = regex_pattern.finditer(command_output)
    non_compliant_user_counter = 0
    user_list = []

    for match in parser:
        current_user = match.group('user')
        config = match.group('config')
        config_regex_pattern_search = re.search(r'secret', config)

        if not config_regex_pattern_search:
            non_compliant_user_counter += 1
            current_user_info = {'Username':current_user, 'Secret':False, 'Config':config}
            user_list.append(current_user_info)

        else:
            current_user_info = {'Username':current_user, 'Secret':True, 'Config':config}
            user_list.append(current_user_info)
            
    compliant = non_compliant_user_counter == 0
    current_configuration = user_list if user_list else None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))