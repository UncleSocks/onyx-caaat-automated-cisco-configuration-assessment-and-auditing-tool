import re
from ssh import ssh_send
from report_modules.main_report import generate_report
from parser_modules.asa.http_parsers import http_enable_check


def compliance_check_console_timeout(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    console_timeout_search = re.search(r'^console\s+timeout\s+(?P<timeout>\d+)', command_output)

    if console_timeout_search:
        console_timeout_value = int(console_timeout_search.group('timeout'))

        if console_timeout_value <= 5 and console_timeout_value != 0:
            compliant = True
        else: 
            compliant = False

    else:
        console_timeout_value = None
        compliant = False

    current_configuration = {'Console Timeout (minutes)':console_timeout_value}
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_ssh_timeout(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    ssh_timeout_search = re.search(r'^ssh\s+timeout\s+(?P<timeout>\d+)', command_output)

    if ssh_timeout_search:
        ssh_timeout_value = int(ssh_timeout_search.group('timeout'))

        if ssh_timeout_value <= 5 and ssh_timeout_value != 0:
            compliant = True
        else:
            compliant = False
    
    else:
        ssh_timeout_value = None
        compliant = False
    
    current_configuration = {'SSH Timeout (minutes)':ssh_timeout_value}
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_http_idle_timeout(connection, command, cis_check, level, global_report_output):

    if http_enable_check(connection, "show running-config | include http server enable") == False:
        compliant = "Not Applicable"
        current_configuration = "HTTP server not enabled."
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))
        return
    
    command_output = ssh_send(connection, command)

    http_idle_timeout_search = re.search(r'^http\s+server\s+idle-timeout\s+(?P<timeout>\d+)', command_output)

    if http_idle_timeout_search:
        http_idle_timeout_value = int(http_idle_timeout_search.group('timeout'))

        if http_idle_timeout_value <= 5 and http_idle_timeout_value != 0:
            compliant = True
        else:
            compliant = False
    
    else:
        http_idle_timeout_value = 20
        compliant = False
    
    current_configuration = {'HTTP Idle Timeout (minutes)':http_idle_timeout_value}
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))