import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def compliance_check_login_block(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    if not command_output:
        compliant = False
        current_configuration = None
    else:
        compliant = True
        
        login_block_match = re.match(r'login\s+block-for\s+(?P<block>\d+)\s+attempts\s+(?P<attempts>\d+)\s+within\s+(?P<interval>\d+)', command_output)

        login_block = login_block_match.group('block')
        login_attempts = login_block_match.group('attempts')
        login_interval = login_block_match.group('interval')

        login_quiet_mode_command_output = ssh_send(connection, "show running-config | include quiet-mode access-class")
        login_quiet_mode_match = re.match(r'login\s+quiet-mode\s+access-class\s+(?P<ac>\S+)', login_quiet_mode_command_output)

        login_delay_command_output = ssh_send(connection, "show running-config | include login delay")
        login_delay_match = re.match(r'login\s+delay\s+(?P<delay>\d+)', login_delay_command_output)

        current_configuration = {'Login Block':f"{login_block} secs", 'Login Attempts':f"{login_attempts} attempts", 'Login Interval':f"{login_interval}", 
                                 'Login Quiet-Mode ACL':login_quiet_mode_match.group('ac') if login_quiet_mode_match else None,
                                 'Login Delay':f"{login_delay_match.group('delay')} secs" if login_delay_match else None}
        
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_auto_secure(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    
    compliant = command_output.lower() != "autosecure is not configured"
    current_configuration = "AutoSecure Configured" if compliant else command_output
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_kerberos(connection, command_one, command_two, cis_check, level, global_report_output):
    kerberos_creds_command_output = ssh_send(connection, command_one)
    kerberos_info_command_output = ssh_send(connection, command_two)
        
    kerberos_server_list = []

    kerberos_local_realm_search = re.search(r'kerberos\s+local-realm\s+(?P<realm>\S+)(?=\n|$)', kerberos_info_command_output, re.MULTILINE)

    regex_patter_kerberos_servers = re.compile(r'kerberos\s+server\s+\S+\s+(?P<server>\S+)(?=\n|$)', re.DOTALL | re.MULTILINE)
    kerberos_server_parser = regex_patter_kerberos_servers.findall(kerberos_info_command_output)
    if kerberos_server_parser:
        for kerberos_server in kerberos_server_parser:
            kerberos_server_list.append(kerberos_server)

    
    compliant = kerberos_creds_command_output.strip().lower() != "no kerberos credentials."
    current_configuration = {'Kerberos Credential':"Kerberos credentials present." if compliant else kerberos_creds_command_output.strip(), 
                             'Local Realm':kerberos_local_realm_search.group('realm') if kerberos_local_realm_search else None, 
                             'Kerberos Servers':kerberos_server_list if kerberos_server_list else None}
    
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))

