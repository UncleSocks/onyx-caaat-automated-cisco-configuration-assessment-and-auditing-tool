import re
from ssh import ssh_send
from report_modules.main_report import generate_report


def http_enable_check(connection, command):
    command_output = ssh_send(connection, command)

    http_enabled = re.search(r'http\s+server\s+enable(?=\n|$)', command_output)

    if http_enabled:
        return True
    else:
        return False
    

def complaince_check_no_http_enabled(global_report_output):
    http_cis_checks = [{'CIS Check':"1.7.1 Ensure 'HTTP source restriction' is set to an authorized IP address", 'Level':2},
                      {'CIS Check':"1.7.2 Ensure 'TLS 1.2' or greater is set for HTTPS access", 'Level':1},
                      {'CIS Check':"1.7.3 Ensure 'SSL AES 256 encryption' is set for HTTPS success", 'Level':1}]
    
    for http_cis_check in http_cis_checks:
        cis_check = http_cis_check['CIS Check']
        level = http_cis_check['Level']
        compliant = "Not Applicable"
        current_configuration = "HTTP server not enabled."
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_http_source_restriction(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)

    http_source_restriction_list = []

    regex_pattern = re.compile(r"^http\s+(?P<address>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})\s+(?P<subnet>(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})\s+(?P<interface>\S+)(?:\n|$)", re.MULTILINE)
    http_source_restriction_match = regex_pattern.findall(command_output)

    if http_source_restriction_match:
        for http_source_restriction in http_source_restriction_match:
            address = http_source_restriction[0]
            subnet = http_source_restriction[1]
            interface = http_source_restriction[2]

            current_http_source_restriction_info = {'Address':address, 'Subnet':subnet, 'Interface':interface}
            http_source_restriction_list.append(current_http_source_restriction_info)

    current_configuration = http_source_restriction_list if http_source_restriction_list else None
    compliant = http_source_restriction_match is not None
    global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))


def compliance_check_https_tls(connection, command, cis_check_one, cis_check_two, level, global_report_output):
    command_output = ssh_send(connection, command)

    https_tls_list = []
    https_tls_version_list = []
    non_compliant_ssl_version_counter = 0
    non_compliant_ssl_encryption_counter = 0

    regex_pattern = re.compile(r'^ssl\s+cipher\s+(?P<version>\S+)\s+custom\s+\"(?P<encryption>\S+)\"(?=\n|$)', re.MULTILINE | re.DOTALL)
    https_tls_match = regex_pattern.findall(command_output)

    if https_tls_match:
        for https_tls in https_tls_match:
            ssl_version = https_tls[0]
            ssl_encryption = https_tls[1]

            if ssl_version != "tlsv1.2":
                non_compliant_ssl_version_counter += 1
            if ssl_encryption != "AES256-SHA":
                non_compliant_ssl_encryption_counter += 1

            current_https_tls_info = {'Version':ssl_version, 'Encryption Algorithm':ssl_encryption}
            https_tls_version_list.append(ssl_version)
            https_tls_list.append(current_https_tls_info)

    current_configuration = {'SSL Versions':https_tls_version_list} if https_tls_version_list else None
    compliant = https_tls_match is not None and non_compliant_ssl_version_counter == 0
    global_report_output.append(generate_report(cis_check_one, level, compliant, current_configuration))

    current_configuration = https_tls_list if https_tls_list else None
    compliant = https_tls_match is not None and non_compliant_ssl_version_counter == 0 and non_compliant_ssl_encryption_counter == 0
    global_report_output.append(generate_report(cis_check_two, level, compliant, current_configuration))


