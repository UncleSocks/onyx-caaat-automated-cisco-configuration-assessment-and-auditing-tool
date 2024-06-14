import json
from parser_modules.asa import general_parsers, password_parsers, device_parsers, aaa_parsers, ssh_parsers, http_parsers, \
    timout_parsers, clock_parsers, logging_parsers, snmp_parsers, routing_parsers, control_parsers, data_parsers


def unpack_cisco_asa_config():
    
    untrusted_nameifs_list = []

    try:
        
        with open('cisco_config.json') as cisco_config_file:
            asa_config = json.load(cisco_config_file)
            untrusted_nameifs_list = asa_config['asa']['interfaces']['untrusted'] if asa_config['asa']['interfaces']['untrusted'] else None
            internetfacing_nameifs_list = asa_config['asa']['interfaces']['internet-facing'] if asa_config['asa']['interfaces']['internet-facing'] else None

            dns_server_list = asa_config['asa']['dns_servers'] if asa_config['asa']['dns_servers'] else None
            non_default_application_list = asa_config['asa']['inspect_protocol'] if asa_config['asa']['inspect_protocol'] else None
    
    except:
        untrusted_nameifs_list = None
        internetfacing_nameifs_list = None
        dns_server_list = None
        non_default_application_list = None

    return untrusted_nameifs_list, internetfacing_nameifs_list, dns_server_list, non_default_application_list


def run_cis_cisco_asa_assessment(connection):

    global_report_output = []

    untrusted_nameifs_list, internetfacing_nameifs_list, dns_server_list, non_default_application_list = unpack_cisco_asa_config() 

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
    clock_parsers.compliance_check_ntp_authentication_key(connection, "show running-config ntp | include authentication-key", "1.9.1.2 Ensure 'NTP authentication key' is configured correctly", 1, global_report_output)
    clock_parsers.compliance_check_ntp_server(connection, "show running-config ntp | include server", "1.9.1.3 Ensure 'trusted NTP server' exists", 1, global_report_output)
    clock_parsers.compliance_check_local_timezone(connection, "show running-config clock | include timezone", "1.9.2 Ensure 'local timezone' is properly configured", 1, global_report_output)

    general_parsers.compliance_check_with_expected_output(connection, "show running-config logging | include enable", "1.10.1 Ensure 'logging' is enabled", 1, global_report_output)
    logging_parsers.compliance_check_logging_monitor(connection, "show running-config logging | grep monitor", "1.10.2 Ensure 'logging to monitor' is disabled", 1, global_report_output)
    logging_parsers.compliance_check_syslog_hosts(connection, "show running-config logging | include host", "1.10.3 Ensure 'syslog hosts' is configured correctly", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config logging | include device-id", "1.10.4 Ensure 'logging with the device ID' is configured correctly", 1, global_report_output)
    logging_parsers.compliance_check_logging_history(connection, "show running-config logging | include history", "1.10.5 Ensure 'logging history severity level' is set greater than or equal to '5'", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config logging | include timestamp", "1.10.6 Ensure 'logging with timestamps' is enabled", 1, global_report_output)
    logging_parsers.compliance_check_logging_buffer_size(connection, "show running-config logging | include buffer-size", "1.10.7 Ensure 'logging buffer size' is greater '524288' bytes", 1, global_report_output)
    logging_parsers.compliance_check_logging_buffered(connection, "show running-config logging | include buffered", "1.10.8 Ensure 'logging buffered severity level' is greather than or equal to '3'", 1, global_report_output)
    logging_parsers.compliance_check_logging_trap(connection, "show running-config logging | include trap", "1.10.9 Ensure 'logging trap severity level' is greater than or equal to '5'", 1, global_report_output)
    logging_parsers.compliance_check_logging_mail(connection, "show running-config logging | include mail", "1.10.10 Ensure mail logging is configured for critical to emergencies", 1, global_report_output)

    if snmp_parsers.compliance_check_snmp_enabled(connection, "show snmp-server group | include groupname") == False:
        snmp_parsers.compliance_check_disabled_snmp(global_report_output)
    else:
        snmp_parsers.compliance_check_snmp_server_group(connection, "show running-config snmp-server group", "1.11.1 Ensure 'snmp-server group' is set to 'v3 priv'", 1, global_report_output)
        snmp_parsers.compliance_check_snmp_server_user(connection, "show running-config snmp-server user", "1.11.2 Ensure 'snmp-server user' is set to 'v3 auth SHA'", 1, global_report_output)
        snmp_parsers.compliance_check_snmp_server_host(connection, "show running-config snmp-server host", "1.11.3 Ensure 'snmp-server host' is set to 'version 3'", 1, global_report_output)
        snmp_parsers.compliance_check_snmp_traps(connection, "show running-config all | include snmp-server enable traps snmp", "1.11.4 Ensure 'SNMP traps' is enabled", 1, global_report_output)
        snmp_parsers.compliance_check_snmp_community_string(connection, "show snmp-server group | include v1|v2c", "1.11.5 Ensure 'SNMP community string' is not the default string", 1, global_report_output)

    routing_parsers.compliance_check_ospf(connection, "show running-config router ospf", "show running-config interface", "2.1.1 Ensure 'OSPF authentication' is enabled", 2, global_report_output)
    routing_parsers.compliance_check_eigrp(connection, "show running-config router eigrp", "show running-config interface", "2.1.2 Ensure 'EIGRP authentication' is enabled", 2, global_report_output)
    #2.1.3 Ensure 'BGP authentication' is enabled

    control_parsers.compliance_check_noproxyarp(connection, "2.2 Ensure 'noproxyarp' is enabled for untrusted interfaces", 2, global_report_output, untrusted_nameifs_list)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config dns-guard", "2.3 Ensure 'DNS Guard' is enabled", 2, global_report_output)
    control_parsers.compliance_check_dhcp_services(connection, "2.4 Ensure DHCP services are disabled for untrusted interfaces", 1, global_report_output, untrusted_nameifs_list)
    control_parsers.compliance_check_icmp_deny(connection, "2.5 Ensure ICMP is restricted for untrusted interfaces", 1, global_report_output, untrusted_nameifs_list)
    
    data_parsers.compliance_check_dns_services(connection, "show running-config all | include domain-lookup", "3.1 Ensure DNS services are configured correctly", 1, global_report_output, dns_server_list)
    data_parsers.compliance_check_ips(connection, "show running-config ip audit name | include _attack_", "3.2 Ensure intrusion prevention is enabled for untrusted interfaces", 1, global_report_output, untrusted_nameifs_list)
    data_parsers.compliance_check_fragments(connection, "3.3 Ensure packet fragments are restricted for untrusted interfaces", 1, global_report_output, untrusted_nameifs_list)
    data_parsers.compliance_check_application_inspection(connection, "show running-config policy-map global_policy", "3.4 Ensure non-default application inspection is configured", 1, global_report_output, non_default_application_list)
    data_parsers.compliance_check_dos_protection(connection, "show running-config policy-map | include set.connection", "3.5 Ensure DOS protection is enabled for untrusted interfaces", 1, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config threat-detection statistics | include tcp-intercept", "3.6 Ensure 'threat-detection statistics' is set to 'tcp-intercept'", 1, global_report_output)
    data_parsers.compliance_check_reverse_path(connection, "3.7 Ensure 'ip verify' is set to 'reverse-path' for untrusted interfaces", 1, global_report_output, untrusted_nameifs_list)
    data_parsers.compliance_check_security_level(connection, "3.8 Ensure 'security-level' is set to '0' for Internet-facing interface", 1, global_report_output, internetfacing_nameifs_list)
    data_parsers.complaince_check_botnet_protection(connection, "3.9 Ensure Botnet protection is enabled for untrusted interfaces", 2, global_report_output, untrusted_nameifs_list)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config filter | include activex", "3.10 Ensure ActiveX filtering is enabled", 2, global_report_output)
    general_parsers.compliance_check_with_expected_output(connection, "show running-config filter | include java", "3.11 Ensure Java applet filtering is enabled", 2, global_report_output)
    data_parsers.compliance_check_acl_deny(connection, "show running-config access-group", "show running-config access-list | include deny.ip.any.any", "3.12 Ensure explicit deny in access lists is configured correctly", 1, global_report_output)

    return global_report_output