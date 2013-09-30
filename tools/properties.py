# Component properties
#########################################
########################################
single_automation = {
    'host': 'localhost',
}

##########################################
# COMPONENT VALUES
#########################################
os = {
    'hostname': 'automation'
}

mysql = {
    'root_pass': 'stackops',
    'keystone_user': 'keystone',
    'keystone_password': 'stackops',
    'nova_user': 'nova',
    'nova_password': 'stackops',
    'glance_user': 'glance',
    'glance_password': 'stackops',
    'cinder_user': 'cinder',
    'cinder_password': 'stackops',
    'quantum_user': 'quantum',
    'quantum_password': 'stackops',
    'portal_user': 'portal',
    'portal_password': 'stackops',
    'accounting_user': 'activity',
    'accounting_password': 'stackops',
    'automation_user': 'automation',
    'automation_password': 'stackops'
}

keystone = {
    'admin_token': 'stackops_admin',
    'admin_pass': mysql['root_pass'],
    'mysql_username': mysql['keystone_user'],
    'mysql_password': mysql['keystone_password'],
    'mysql_schema': 'keystone',
    'protocol': 'http',
    'auth_port': '35357',
    'host': single_automation['host'],
    'tenant_name': 'service',
    'region': 'RegionOne',
    'endpoint': 'http://' + single_automation['host'] + ':35357/v2.0',
    'ks_public_url': 'https://' + single_automation['host'] + '/keystone/v2.0',
    'ks_admin_url': 'http://' + single_automation['host'] + ':35357/v2.0',
    'ks_internal_url': 'http://' + single_automation['host'] + ':5000/v2.0',
    'ks_user': 'keystone',
    'ks_password': 'stackops',
    'nova_public_url': 'https://' + single_automation['host'] +
                       '/compute/v1.1/$(tenant_id)s',
    'nova_admin_url': 'http://' + single_automation['host']
                      + ':8774/v1.1/$(tenant_id)s',
    'nova_internal_config': 'http://' + single_automation['host'] + ':8774/v1.1',
    'nova_internal_url': 'http://' + single_automation['host']
                         + ':8774/v1.1/$(tenant_id)s',
    'nova_user': 'nova',
    'nova_password': 'stackops',
    'ec2_public_url': 'https://' + single_automation['host'] + '/services/Cloud',
    'ec2_admin_url': 'http://' + single_automation['host'] + '/services/Admin',
    'ec2_internal_url': 'http://' + single_automation['host'] + '/services/Cloud',
    'glance_port': '9292',
    'glance_public_url': 'https://' + single_automation['host'] + '/glance/v1',
    'glance_admin_url': 'http://' + single_automation['host'] + ':9292/v1',
    'glance_internal_url': 'http://' + single_automation['host'] + ':9292/v1',
    'glance_user': 'glance',
    'glance_password': 'stackops',
    'quantum_public_url': 'https://' + single_automation['host'] + '/network',
    'quantum_admin_url': 'http://' + single_automation['host'] + ':9696',
    'quantum_internal_url': 'http://' + single_automation['host'] + ':9696',
    'quantum_user': 'quantum',
    'quantum_password': 'stackops',
    'cinder_public_url': 'https://' + single_automation['host'] +
                         '/volume/v1/$(tenant_id)s',
    'cinder_admin_url': 'http://' + single_automation['host'] +
                        ':8776/v1/$(tenant_id)s',
    'cinder_internal_config': 'http://' + single_automation['host'] + ':8776/v1',
    'cinder_internal_url': 'http://' + single_automation['host'] +
                           ':8776/v1/$(tenant_id)s',
    'cinder_user': 'cinder',
    'cinder_password': 'stackops',
    'portal_public_url': 'https://' + single_automation['host'] + '/portal',
    'portal_admin_url': 'http://' + single_automation['host'] + ':8080/portal',
    'portal_internal_url': 'http://' + single_automation['host'] + ':8080/portal',
    'portal_user': 'portal',
    'portal_password': 'stackops',
    'accounting_public_url': 'https://' + single_automation['host'] + '/activity',
    'accounting_admin_url': 'http://' + single_automation['host']
                            + ':8080/activity',
    'accounting_internal_url': 'http://' + single_automation['host']
                               + ':8080/activity',
    'accounting_user': 'activity',
    'accounting_password': 'stackops',
    'chargeback_public_url': 'https://' + single_automation['host'] + '/chargeback',
    'chargeback_admin_url': 'http://' + single_automation['host']
                            + ':8080/chargeback',
    'chargeback_internal_url': 'http://' + single_automation['host']
                               + ':8080/chargeback',
    'chargeback_user': 'chargeback',
    'chargeback_password': 'stackops',
    'automation_public_url': 'https://' + single_automation['host'] + '/automation',
    'automation_admin_url': 'http://' + single_automation['host']
                            + ':8089/v1.1',
    'automation_internal_url': 'http://' + single_automation['host']
                               + ':8089/v1.1',
    'automation_user': 'automation',
    'automation_password': 'stackops'
}

portal = {
    'admin_token': keystone['admin_token'],
    'mysql_admin_password': mysql['root_pass'],
    'keystone_url': keystone['ks_internal_url'],
    'keystone_admin_url': keystone['ks_admin_url'],
    'mysql_username': mysql['portal_user'],
    'mysql_password': mysql['portal_password']
}

apache = {
    'keystone_host': single_automation['host'],
    'ec2_internal_url': keystone['ec2_internal_url'],
    'compute_internal_url': keystone['nova_internal_config'],
    'keystone_internal_url': keystone['ks_internal_url'],
    'glance_internal_url': keystone['glance_internal_url'],
    'cinder_internal_url': keystone['cinder_internal_config'],
    'quantum_internal_url': keystone['quantum_internal_url'],
    'portal_internal_url': keystone['portal_internal_url'],
    'activity_internal_url': keystone['accounting_internal_url'],
    'chargeback_internal_url': keystone['chargeback_internal_url'],
    'automation_internal_url': keystone['automation_internal_url']
}

automation = {
    'dhcp_start': '192.168.2.100',
    'dhcp_end': '192.168.2.200',
    'dhcp_listen_interface': 'eth0',
    'gateway': '192.168.2.1',
    'netmask': '255.255.255.0',
    'domain': 'stackops.org',
    'dns': '8.8.8.8',
    'license_manager_url': keystone['portal_admin_url'],
    'license_token': 'vs0QiaN9TA6lIIe3uPSfiG3fs',
    'endpoint': keystone['endpoint'],
    'mysql_username': mysql['automation_user'],
    'mysql_password': mysql['automation_password'],
    'automation_user': keystone['automation_user'],
    'automation_password': keystone['automation_password'],
    'token_service': keystone['admin_token']
}

