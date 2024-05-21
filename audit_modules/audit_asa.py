from parser_modules.asa import general_parsers, password_parsers, device_parsers, aaa_parsers, ssh_parsers, http_parsers, \
    timout_parsers


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
    aaa_parsers.compliance_check_remote_aaa_servers(connection, "show running-config aaa-server | include protocol.tacacs+", "show running-config aaa-server | include protocol.radius",
                                                    "1.4.2.1 Ensure 'TACACS+/RADIUS' is configured correctly", 2, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication enable console", "1.4.3.1 Enable 'aaa authentication enable console' is configured correctly", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication http console", "1.4.3.2 Enable 'aaa authentication http console' is configured correctly", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication secure-http-client", "1.4.3.3 Enable 'aaa authentication secure-http-client' is configured correctly", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authentication ssh console", "1.4.3.4 Enable 'aaa authentication ssh console' is configured correctly", 1, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authorization command", "1.4.4.1 Ensure 'aaa command authorization' is configured correctly", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa authorization exec", "1.4.4.2 Ensure 'aaa authorization exec' is configured correctly", 1, global_report_output)
    
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa accounting command", "1.4.5.1 Ensure 'aaa accounting command' is configured correctly", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa accounting ssh console", "1.4.5.2 Ensure 'aaa accounting for SSH' is configured correctly", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include aaa accounting enable console", "1.4.5.3 Ensure 'aaa accounting for EXEC mode' is configured correctly", 1, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include banner.asdm", "1.5.1 Ensure 'ASDM banner' is set", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include banner.exec", "1.5.2 Ensure 'EXEC banner' is set", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include banner.login", "1.5.3 Ensure 'LOGIN banner' is set", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config | include banner.motd", "1.5.4 Ensure 'MOTD banner' is set", 1, global_report_output)

    ssh_parsers.compliance_check_ssh_source_restriction(connection, "show running-config ssh | include ssh", "1.6.1 Ensure 'SSH source restriction' is set to an authorized IP address", 1, global_report_output)
    ssh_parsers.compliance_check_ssh_version(connection, "show running-config ssh | include version", "1.6.2 Ensure 'SSH veresion 2' is enabled", 1, global_report_output)
    ssh_parsers.compliance_check_rsa_modulus_size(connection, "show crypto key mypubkey rsa | include Key_Size|_Modulus", "1.6.3 Ensure 'RSA key pair' is greater than or equal to 2048 bits", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config ssh | grep scopy", "1.6.4 Ensure 'SCP protocol' is set to Enable for file transfers", 2, global_report_output)
    ssh_parsers.compliance_check_telnet(connection, "show running-config telnet", "1.6.5 Ensure 'Telnet' is disabled", 1, global_report_output)

    if http_parsers.http_enable_check(connection, "show running-config | include http server enable") == False:
        http_parsers.complaince_check_no_http_enabled(global_report_output)
    else:
        http_parsers.compliance_check_http_source_restriction(connection, "show running-config http | include http", "1.7.1 Ensure 'HTTP source restriction' is set to an authorized IP address", 2, global_report_output)
        http_parsers.compliance_check_https_tls(connection, "show running-config ssl | include ssl cipher", "1.7.2 Ensure 'TLS 1.2' or greater is set for HTTPS access", 
                                                "1.7.3 Ensure 'SSL AES 256 encryption' is set for HTTPS access", 1, global_report_output)
        
    timout_parsers.compliance_check_console_timeout(connection, "show running console | include timeout", "1.8.1 Ensure 'console session timeout' is less than or equal to '5' minutes", 1, global_report_output)
    timout_parsers.compliance_check_ssh_timeout(connection, "show running-config ssh | include timeout", "1.8.2 Ensure 'SSH session timeout' is less than or equal to '5' minutes", 1, global_report_output)
    timout_parsers.compliance_check_http_idle_timeout(connection, "show running-config http | include idle-timeout", "1.8.3 Ensure 'HTTP idle timeout' is less than or equal to '5' minutes", 1, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show running-config ntp | include authenticate", "1.9.1.1 Ensure 'NTP authentication' is enabled", 1, global_report_output)
    
    return global_report_output