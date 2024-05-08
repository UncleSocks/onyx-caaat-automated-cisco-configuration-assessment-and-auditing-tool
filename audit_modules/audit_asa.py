from parser_modules.asa import general_parsers


def run_cis_cisco_asa_assessment(connection):

    global_report_output = []

    general_parsers.compliance_check_with_expected_output(connection, "show running-config passwd", "1.1.1 Ensure 'Logon Password' is set", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include enable password", "1.1.2 Ensure 'Enable Password' is set", 1, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include no.service.password-recovery", "1.1.4 Ensure 'Password Recovery' is disabled", 1, global_report_output)

    return global_report_output