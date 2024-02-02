from parser_modules.ios17 import general_parsers, aaa_parsers, users_parsers, line_parsers, snmp_parsers, login_parsers


def run_cis_cisco_ios_17_assessment(connection):

    global_report_output = []

    #1 Management Plane CIS Compliance Checks
    print("Performing CIS Cisco IOS 17 Management Plane Benchmarks assessment.")

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
    
    line_parsers.compliance_check_exec_timeout_vty(connection, "show running-config | section vty", "1.2.8 Set 'exec-timeout' to less than or equal to 10 minutes 'line vty'", 
                                                   1, global_report_output)
    
    line_parsers.compliance_check_aux_transport(connection, "show line aux 0 | include input transports", "1.2.9 Set 'transport input none' for 'line aux 0'", 1, global_report_output)
    line_parsers.compliance_check_http(connection, "show running-config | section ip http", "1.2.10 Set 'http Secure-Server' limit", 
                                       "1.2.11 Set 'exec-timeout' to less than or equal to 10 min on 'ip http'", 1, global_report_output)
    
    banner_commands = ["banner exec", "banner login", "banner motd", "auth-proxy-banner http"]
    for index, banner_command in enumerate(banner_commands, start = 1):
        if banner_command == "auth-proxy-banner http":
            general_parsers.compliance_check_banner(connection, f"show running-config | begin {banner_command}", 
                                                    f"1.3.{index} Set the 'banner-text' for 'webauth banner'", 1, global_report_output)
        else:
            general_parsers.compliance_check_banner(connection, f"show running-config | begin {banner_command}",
                                                f"1.3.{index} Set the 'banner-text' for '{banner_command}'", 1, global_report_output)
    
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include enable secret", "1.4.1 Set 'password' for 'enable secret'", 1, global_report_output)
    general_parsers.compliance_check_without_no_prefix(connection, "show running-config | include service password-encryption", "1.4.2 Enable 'service password-encryption'", 1, global_report_output)
    users_parsers.compliance_check_user_secret(connection, "show running-config | include username", "1.4.3 Set 'username secret' for all local users", 1, global_report_output)

    if snmp_parsers.complaince_check_snmp_enabled(connection, "show snmp community", "1.5.1 Set 'no snmp-server' to disable SNMP when unused", 1, global_report_output) == True:
        snmp_parsers.compliance_check_no_snmp(global_report_output)

    else:
        snmp_community_commands = ["private", "public"]
        for index, snmp_community_command in enumerate(snmp_community_commands, start = 2):
            snmp_parsers.compliance_check_snmp_community(connection, f"show snmp community | include {snmp_community_command}", 
                                            f"1.5.{index} Unset {snmp_community_command} for 'snmp-server community'", 1, global_report_output)
        
        snmp_parsers.compliance_check_snmp_rw(connection, "show running-config | include snmp-server community", "1.5.4 Do not set 'RW' for any 'snmp-server community'", 
                                 "1.5.5 Set the ACL for each 'snmp-server community'", 1, global_report_output)
        
        general_parsers.compliance_check_with_expected_output(connection, "show ip access-list", "1.5.6 Create an 'access-list' for use with SNMP", 1, global_report_output)
        general_parsers.compliance_check_with_expected_output(connection, "show running-config | include snmp-server host", "1.5.7 Set 'snmp-server host' when using SNMP", 1, global_report_output)
        general_parsers.compliance_check_with_expected_output(connection, "show running-config | include snmp-server enable traps snmp", "1.5.8 Set 'snmp-server enable traps snmp'", 1, global_report_output)

        snmp_parsers.compliance_check_snmp_v3(connection, "show snmp group | include groupname", "show snmp user", 
                                              "1.5.9 Set 'priv' for each 'snmp-server group' using SNMPv3", 
                                              "1.5.10 Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3", 
                                              2, global_report_output)

    login_parsers.compliance_check_login_block(connection, "show running-config | include login block", "1.6.1 Configure Login Block", 2, global_report_output)
    login_parsers.compliance_check_auto_secure(connection, "show auto secure config", "1.6.2 AutoSecure", 2, global_report_output)
    login_parsers.compliance_check_kerberos(connection, "show kerberos creds", "show running-config | include kerberos", "1.6.3 Configuring Kerberos", 2, global_report_output)
    login_parsers.compliance_check_web_interface(connection, "show running-config | include ip admission", "show running-config | section interface", 
                                                 "1.6.4 Configure Web Interface", 2, global_report_output)

    return global_report_output