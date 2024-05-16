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


def compliance_check_remote_aaa_servers(connection, command_one, command_two, cis_check, level, global_report_output):
    command_output_tacacs = ssh_send(connection, command_one)
    command_output_radius = ssh_send(connection, command_two)

    current_configuration = {'TACACS+ Server Groups':None, 'RADIUS Server Group':None}    
    tacacs_aaa_server_group_list = []
    radius_aaa_server_group_list = []

    tacacs_server_group_compliance = False
    radius_server_group_compliance = False

    regex_pattern_tacacs = re.compile(r'aaa-server\s+(?P<tacacs_server_group>\S+)\s+.*?(?=\n|$)')
    tacacs_server_group_match = regex_pattern_tacacs.findall(command_output_tacacs)
    
    if tacacs_server_group_match:

        for tacacs_sevrer_group in tacacs_server_group_match:

            tacacs_server_group_host_command = f"show running-config aaa-server {tacacs_sevrer_group} | include host"
            command_output = ssh_send(connection, tacacs_server_group_host_command)

            if not command_output:
                current_tacacs_server_group_info = {'Server Group':tacacs_sevrer_group, 'Host Address':None}
                tacacs_aaa_server_group_list.append(current_tacacs_server_group_info)
            
            else:
                tacacs_host_address = command_output.split()[4]
                current_tacacs_server_group_info = {'Server Group':tacacs_sevrer_group, 'Host Address':tacacs_host_address}
                tacacs_aaa_server_group_list.append(current_tacacs_server_group_info)

        no_host_for_all_tacacs = all(host.get('Host Address') is None for host in tacacs_aaa_server_group_list)
        if not no_host_for_all_tacacs:
            tacacs_server_group_compliance = True

        current_configuration['TACACS+ Server Groups'] = tacacs_aaa_server_group_list

    regex_pattern_radius = re.compile(r'aaa-server\s+(?P<radius_server_group>\S+)\s+.*?(?=\n|$)')
    radius_server_group_match = regex_pattern_radius.findall(command_output_radius)

    if radius_server_group_match:

        for radius_server_group in radius_server_group_match:

            radius_server_group_host_command = f"show running-config aaa-server {radius_server_group} | include host"
            command_output = ssh_send(connection, radius_server_group_host_command)

            if not command_output:
                current_radius_server_group_info = {'Server Group':radius_server_group, 'Host Address':None}
                radius_aaa_server_group_list.append(current_radius_server_group_info)
            
            else:
                radius_host_address = command_output.split()[4]
                current_radius_server_group_info = {'Server Group':radius_server_group, 'Host Address':radius_host_address}
                radius_aaa_server_group_list.append(current_radius_server_group_info)

        no_host_for_all_redius = all(host.get('Host Address') is None for host in radius_aaa_server_group_list)
        if not no_host_for_all_redius:
            radius_server_group_compliance = True

        current_configuration['RADIUS Server Group'] = radius_aaa_server_group_list

    compliant = tacacs_server_group_compliance == True or radius_server_group_compliance == True
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
