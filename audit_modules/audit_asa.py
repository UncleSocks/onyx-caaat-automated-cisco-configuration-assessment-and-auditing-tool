from parser_modules.asa import general_parsers, password_parsers


def run_cis_cisco_asa_assessment(connection):

    global_report_output = []

    general_parsers.compliance_check_with_expected_output(connection, "show running-config passwd", "1.1.1 Ensure 'Logon Password' is set", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include enable password", "1.1.2 Ensure 'Enable Password' is set", 1, global_report_output)
    #1.1.3 Ensure 'Master Key Passphrase' is Set
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include no.service.password-recovery", "1.1.4 Ensure 'Password Recovery' is disabled", 1, global_report_output)
    password_parsers.compliance_check_password_policy(connection, "show running-config password-policy", "1.1.5 Ensure 'Password Policy' is enabled", 1, global_report_output)
    return global_report_output