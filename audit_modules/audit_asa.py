from parser_modules.asa import general_parsers, password_parsers, device_parsers, aaa_parsers


def run_cis_cisco_asa_assessment(connection):

    global_report_output = []

    general_parsers.compliance_check_with_expected_output(connection, "show running-config passwd", "1.1.1 Ensure 'Logon Password' is set", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include enable password", "1.1.2 Ensure 'Enable Password' is set", 1, global_report_output)
    #1.1.3 Ensure 'Master Key Passphrase' is Set
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include no.service.password-recovery", "1.1.4 Ensure 'Password Recovery' is disabled", 1, global_report_output)
    password_parsers.compliance_check_password_policy(connection, "show running-config password-policy", "1.1.5 Ensure 'Password Policy' is enabled", 1, global_report_output)
    
    general_parsers.compliance_check_with_expected_output(connection, "show running-config domain-name", "1.2.1 Ensure 'Domain Name' is set", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config hostname", "1.2.2 Ensure 'Host Name' is set", 1, global_report_output)
    #1.2.3 Ensure 'Failover' is enabled
    device_parsers.compliance_check_unused_interface(connection, "show interface ip brief | include __down", "1.2.4 Ensure 'Unused Interfaces' is disabled", 1, global_report_output)
    #1.3.1 Ensure'Image Integrity' is correct (manual)
    general_parsers.compliance_check_with_expected_output(connection, "show software authenticity running | in CiscoSystems$", "1.3.2 Ensure 'Image Authenticity' is correct", 1, global_report_output)
    
    aaa_parsers.compliance_check_auth_max_failed(connection, "show running-config aaa | include max-fail", "1.4.1.1 Ensure 'aaa local authentication max failed attempts' is set to less than or equal to '3'", 1, global_report_output)
    aaa_parsers.compliance_check_default_accounts(connection, "show running-config username | include _admin_|_asa_|_cisco_|_pix_|_root_", "1.4.1.3 Ensure known default accounts do not exists", 1, global_report_output)
    return global_report_output