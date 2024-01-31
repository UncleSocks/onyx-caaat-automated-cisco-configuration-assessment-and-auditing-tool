import re
from ssh import ssh_send
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