from ssh_module import ssh_send
from report import generate_report


def compliance_check_ntp_server_key(connection, command, cis_check, level, global_report_output):
    command_output = ssh_send(connection, command)
    non_compliant_ntp_server_counter = 0
    ntp_server_list = []

    if not command_output:
        compliant = False
        current_configuration = None
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))

    else:
        for ntp_server in command_output.split("\n"):
            ntp_server_key_parser = ntp_server.split()
            if len(ntp_server_key_parser) > 3 and ntp_server_key_parser[3].lower() == "key":
                ntp_server_list.append(ntp_server)
            else:
                non_compliant_ntp_server_counter += 1
                ntp_server_list.append(ntp_server)
        compliant = non_compliant_ntp_server_counter == 0
        current_configuration = ntp_server_list
        global_report_output.append(generate_report(cis_check, level, compliant, current_configuration))