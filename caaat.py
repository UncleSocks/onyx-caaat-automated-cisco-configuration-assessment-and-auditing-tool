from maskpass import askpass
from ssh_module import ssh_login
from parser_modules.ios15 import aaa_parsers, general_parsers, line_parsers, logging_parsers, ntp_parsers, services_parsers, snmp_parsers, ssh_parsers, users_parsers


if __name__ == "__main__":

    global_report_output = []

    ip_address = input("Target: ")
    username = input("Username: ")
    password = askpass("Password: ")
    enable_password = askpass("Enable: ")

    try:
        connection = ssh_login(ip_address, username, password, enable_password)
    except:
        print("Error 0001 - Unable to login to the target router, check IP address and login credentials.")
        print("Exiting the Onyx: CAAAT...")
        exit()


    general_parsers.compliance_check_without_no_prefix(connection, "show running-config | include aaa new-model", "1.1.1 Enable 'aaa new-model'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication login", "1.1.2 Enable 'aaa authentication login'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication enable","1.1.3 Enable 'aaa authentication enable default'", 1, global_report_output)
    aaa_parsers.compliance_check_aaa_auth_line(connection, "show running-config | section line | include login authentication", 1, global_report_output)

    aaa_accounting_commands = ["commands 15", "connection", "exec", "network", "system"]
    for index, aaa_accounting_command in enumerate(aaa_accounting_commands, start = 7):
        if aaa_accounting_command == "commands 15":
            general_parsers.compliance_check_with_expected_output(connection, f"show running-config | include aaa accounting {aaa_accounting_command}", 
                                          f"1.1.{index} Set 'aaa accounting' to log all privileged use commands using {aaa_accounting_command}", 
                                          2, global_report_output)
        else:
            general_parsers.compliance_check_with_expected_output(connection, f"show running-config | include aaa accounting {aaa_accounting_command}", 
                                               f"1.1.{index} Set '{aaa_accounting_command}'", 2, global_report_output)

    users_parsers.compliance_check_acl_privilege(connection, "show running-config | include privilege", "1.2.1 Set 'privilege 1' for local users", 1, global_report_output)        
    line_parsers.compliance_check_transport_input(connection, "show running-config | section vty", "1.2.2 Set 'transport input ssh' for 'line vty' connections", 1, global_report_output)
    line_parsers.compliance_check_vty_acl(connection, "show ip access-list", "show running-config | section vty", "1.2.4 Create 'access-list' for use with 'line vty'", 
                             "1.2.5 Set 'access-class' for 'line vty'", 1, global_report_output)

    banner_commands = ["exec", "login", "motd"]
    for index, banner_command in enumerate(banner_commands, start = 1):
        general_parsers.compliance_check_with_expected_output(connection, f"show running-config | begin banner {banner_command}",
                                            f"1.3.{index} Set the 'banner-text' for 'banner {banner_command}'", 1, global_report_output)

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

        snmp_parsers.compliance_check_snmp_group(connection, "show snmp group | include groupname", "1.5.9 Set 'priv' for each 'snmp-server group' using SNMPv3", 2, global_report_output)
        snmp_parsers.compliance_check_snmp_user(connection, "show snmp user", "1.5.10 Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3", 2, global_report_output)
    

    ssh_parsers.compliance_check_hostname(connection, "show running-config | include hostname", "2.1.1.1.1 Set the 'hostname'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show crypto key mypubkey rsa", "2.1.1.1.3 Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'",
                                       1, global_report_output)

    ssh_parsers.compliance_check_ssh(connection, "show ip ssh", "2.1.1.1.4 Set 'seconds' for 'ip ssh timeout'", "2.1.1.1.5 Set maximum value for 'ip ssh authentication-retries'", 
                         "2.1.1.2 Set version 2 for 'ip ssh version'", 1, global_report_output)

    services_parsers.compliance_check_cdp(connection, "show cdp", "2.1.2 Set 'no cdp run'", 1, global_report_output)
    services_parsers.compliance_check_bootp(connection, "show running-config | include bootp", "2.1.3 Set 'no ip bootp server'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_empty_output(connection, "show running-config | include dhcp", "2.1.4 Set 'no service dhcp'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_empty_output(connection, "show running-config | include identd", "2.1.5 Set 'no ip identd'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include service tcp-keepalives-out", "2.1.7 Set 'service tcp-keepalives-out'", 1, global_report_output)
    services_parsers.compliance_check_service_pad(connection, "show running-config | include service pad", "2.1.8 Set 'no service pad'", 1, global_report_output)
    
    general_parsers.compliance_check_without_no_prefix(connection, "show running-config | include logging on", "2.2.1 Set 'logging on'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include logging buffered", "2.2.2 Set 'buffer size' for 'logging buffered'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include logging console critical", "2.2.3 Set 'logging console critical'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include logging host", "2.2.4 Set IP address for 'logging host'", 1, global_report_output)
    logging_parsers.compliance_check_logging_trap(connection, "show logging | include Trap logging", "2.2.5 Set 'logging trap informational'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include service timestamps debug datetime", 
                                          "2.2.6 Set 'service timestamps debug datetime'", 1, global_report_output)
    
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include source-interface Loopback",
                                          "2.2.7 Set 'logging source interface", 1, global_report_output)
    
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ntp authenticate", "2.3.1.1 Set 'ntp authenticate'", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ntp authentication-key", "2.3.1.2 Set 'ntp authentication-key'", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ntp trusted-key", "2.3.1.3 Set the 'ntp trusted key'", 2, global_report_output)
    ntp_parsers.compliance_check_ntp_server_key(connection, "show running-config | include ntp server", "2.3.1.4 Set 'key' for each 'ntp server'", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show ntp associations", "2.3.2 Set 'ip address' for 'ntp server'", 1, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show ip interface brief | include Loopback", "2.4.1 Create a single 'interface loopback'", 2, global_report_output)
    aaa_parsers.compliance_check_aaa_source_int(connection, "show running-config | include tacacs source-interface Loopback", 
                                                  "show running-config | include radius source-interface Loopback", "2.4.2 Set AAA 'source-interface'", 2, global_report_output)
    
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include ntp source Loopback", "2.4.3 Set 'ntp source' to Loopback Interface", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include tftp source-interface Loopback", "2.4.4 Set 'ip tftp source-interface' to the Loopback Interface",
                                                        2, global_report_output)
    


    for report in global_report_output:
        print(report)
    print("Closing connection")
    ssh_login(ip_address, username, password, enable_password).disconnect
