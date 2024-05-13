import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_auth_max_failed(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    auth_max_failed_match = re.match(r'aaa\s+local\s+authentication\s+attempts\s+max-fail\s+(?P<failed_attempts>\d+)',command_output)
    
    current_configuration = {'AAA Local Authentication Max Failed Attempts':None}
    compliant = False

    if auth_max_failed_match:
        auth_max_failed_attempts = int(auth_max_failed_match.group('failed_attempts'))
        if auth_max_failed_attempts <= 3:
            compliant = True
        
        current_configuration['AAA Local Authentication Max Failed Attempts'] = auth_max_failed_attempts

    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_default_accounts(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    default_accounts_list = []
    current_configuration = {'Default Accounts':None}

    regex_pattern = re.compile(r'username\s+(?P<username>\S+)\s+.*?(?=\n|$)')
    default_accounts_match = regex_pattern.findall(command_output)

    if default_accounts_match:
        for default_account in default_accounts_match:
            default_accounts_list.append(default_account)

        current_configuration['Default Accounts'] = default_accounts_list

    compliant = not default_accounts_match
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))