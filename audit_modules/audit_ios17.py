from parser_modules.ios17 import general_parsers, aaa_parsers, users_parsers, line_parsers


def run_cis_cisco_ios_17_assessment(connection):

    global_report_output = []

    #1 Management Plane CIS Compliance Checks
    print("Performing CIS Cisco IOS 15 Management Plane Benchmarks assessment...")

    general_parsers.compliance_check_without_no_prefix(connection, "show running-config | include aaa new-model", "1.1.1 Enable 'aaa new-model'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication login", "1.1.2 Enable 'aaa authentication login'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication enable","1.1.3 Enable 'aaa authentication enable default'", 1, global_report_output)
    aaa_parsers.compliance_check_aaa_auth_line_vty(connection, "show running-config | section vty | include login authentication", "1.1.4 Set 'login authentication for 'line vty'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ip http authentication","1.1.5 Set 'login authentication for 'ip http'", 1, global_report_output)

    aaa_accounting_commands = ["commands 15", "connection", "exec", "network", "system"]
    for index, aaa_accounting_command in enumerate(aaa_accounting_commands, start = 6):
        if aaa_accounting_command == "commands 15":
            general_parsers.compliance_check_with_expected_output(connection, f"show running-config | include aaa accounting {aaa_accounting_command}", 
                                          f"1.1.{index} Set 'aaa accounting' to log all privileged use commands using {aaa_accounting_command}", 
                                          2, global_report_output)
        else:
            general_parsers.compliance_check_with_expected_output(connection, f"show running-config | include aaa accounting {aaa_accounting_command}", 
                                               f"1.1.{index} Set 'aaa accounting {aaa_accounting_command}'", 2, global_report_output)
    
    users_parsers.compliance_check_acl_privilege(connection, "show running-config | include privilege", "1.2.1 Set 'privilege 1' for local users", 1, global_report_output)
    line_parsers.compliance_check_transport_input(connection, "show running-config | section vty", "1.2.2 Set 'transport input ssh' for 'line vty' connections", 1, global_report_output)
    line_parsers.compliance_check_aux_exec(connection, "show running-config | section line aux 0", "1.2.3 Set 'no exec' for 'line aux 0'", 1, global_report_output)
    line_parsers.compliance_check_vty_acl(connection, "show ip access-list", "show running-config | section vty", "1.2.4 Create 'access-list' for use with 'line vty'", 
                             "1.2.5 Set 'access-class' for 'line vty'", 1, global_report_output)

    exec_timeout_line_commands = ["line aux 0", "line con 0"]
    for index, exec_timeout_line_command in enumerate(exec_timeout_line_commands, start = 6):
        line_parsers.compliance_check_exec_timeout(connection, f"show running-config | section {exec_timeout_line_command}", 
                                                   f"1.2.{index} Set 'exec-timeout' to less than or equal to 10 minutes for '{exec_timeout_line_command}'", 
                                                   1, global_report_output)
    
    return global_report_output