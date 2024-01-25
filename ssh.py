from netmiko import ConnectHandler


def ssh_login(ip_address, username, password, enable_password):
    connection = ConnectHandler(host = ip_address, 
                                username = username, 
                                password = password, 
                                secret = enable_password, 
                                device_type = 'cisco_ios')
    return connection


def ssh_send(connection, command):
    connection.enable()
    send = connection.send_command(command)
    return send

    
