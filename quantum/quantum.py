#   Copyright 2012-2013 STACKOPS TECHNOLOGIES S.L.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from fabric.api import *
from cuisine import *

import fabuloso.utils as utils

QUANTUM_API_PASTE_CONF = '/etc/quantum/api-paste.ini'

DHCP_AGENT_CONF = '/etc/quantum/dhcp_agent.ini'

L3_AGENT_CONF = '/etc/quantum/l3_agent.ini'

OVS_PLUGIN_CONF = '/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini'

QUANTUM_CONF = '/etc/quantum/quantum.conf'

def openvswitch_stop():
    with settings(warn_only=True):
        sudo("service openvswitch-switch stop")

def openvswitch_start():
    openvswitch_stop()
    sudo("service openvswitch-switch start")

def quantum_plugin_openvswitch_agent_stop():
    with settings(warn_only=True):
        sudo("service quantum-plugin-openvswitch-agent stop")

def quantum_plugin_openvswitch_agent_start():
    quantum_plugin_openvswitch_agent_stop()
    sudo("service quantum-plugin-openvswitch-agent start")

def quantum_dhcp_agent_stop():
    with settings(warn_only=True):
        sudo("service quantum-dhcp-agent stop")

def quantum_dhcp_agent_start():
    quantum_dhcp_agent_stop()
    sudo("service quantum-dhcp-agent start")

def quantum_l3_agent_stop():
    with settings(warn_only=True):
        sudo("service quantum-l3-agent stop")

def quantum_l3_agent_start():
    quantum_l3_agent_stop()
    sudo("service quantum-l3-agent start")

def quantum_server_stop():
    with settings(warn_only=True):
        sudo("service quantum-server stop")


def quantum_server_start():
    quantum_server_stop()
    sudo("service quantum-server start")
    sudo("sleep 10")

def stop():
    openvswitch_stop()
    quantum_plugin_openvswitch_agent_stop()
    quantum_dhcp_agent_stop()
    quantum_l3_agent_stop()
    quantum_server_stop()

def start():
    openvswitch_start()
    quantum_plugin_openvswitch_agent_start()
    quantum_dhcp_agent_start()
    quantum_l3_agent_start()
    quantum_server_start()

def compile_datapath():
    package_ensure('openvswitch-datapath-source')
    sudo('DEBIAN_FRONTEND=noninteractive module-assistant -fi auto-install openvswitch-datapath')


def configure_ubuntu_packages():
    """Configure openvwsitch and quantum packages"""
    package_ensure('vlan')
    package_ensure('bridge-utils')
    package_ensure('python-cliff')
    package_ensure('python-pyparsing')
    package_ensure('python-amqp')
    package_ensure('python-mysqldb')
    package_ensure('openvswitch-datapath-dkms')
    package_ensure('openvswitch-switch')
    package_ensure('quantum-plugin-openvswitch-agent')
    package_ensure('quantum-l3-agent')
    package_ensure('quantum-dhcp-agent')
    package_ensure('quantum-plugin-openvswitch')
    package_ensure('quantum-server')

def uninstall_ubuntu_packages():
    """Uninstall openvswitch and quantum packages"""
    package_clean('iptables-persistent')
    package_clean('openvswitch-datapath-dkms')
    package_clean('openvswitch-switch')
    package_clean('python-amqp')
    package_clean('python-cliff')
    package_clean('quantum-plugin-openvswitch-agent')
    package_clean('quantum-l3-agent')
    package_clean('quantum-dhcp-agent')
    package_clean('quantum-server')
    package_clean('quantum-plugin-openvswitch')
    package_clean('python-pyparsing')
    package_clean('python-mysqldb')
    package_clean('vlan')
    package_clean('bridge-utils')

def configure_network():
    sudo("sed -i -r 's/^\s*#(net\.ipv4\.ip_forward=1.*)/\\1/' /etc/sysctl.conf")
    sudo("echo 1 > /proc/sys/net/ipv4/ip_forward")

def install(cluster=False, iface_ex="eth1"):
    """Generate quantum configuration. Execute on both servers"""
    if iface_ex is None:
        puts("{'error':'You need to pass the physical interface as argument of the external bridge'}")
        return
    configure_ubuntu_packages()
    if cluster == 'True':
        sudo('echo "manual" >> /etc/init/quantum-l3-agent.override')
        sudo('echo "manual" >> /etc/init/quantum-dhcp-agent.override')
        sudo('echo "manual" >> /etc/init/quantum-plugin-openvswitch-agent.override')
        sudo('update-rc.d -f openvswitch-switch remove')
    configure_network()
    openvswitch_start()
    with settings(warn_only=True):
        sudo('ovs-vsctl del-br br-ex')
    sudo('ovs-vsctl add-br br-ex')
    sudo('ovs-vsctl add-port br-ex %s' % iface_ex)
    sudo('update-rc.d quantum-dhcp-agent defaults 98 02')
    sudo('update-rc.d quantum-l3-agent defaults 98 02')
    sudo('update-rc.d quantum-plugin-openvswitch-agent defaults 98 02')

def set_config_file(service_user='quantum', service_tenant_name='service', service_pass='stackops',auth_host='127.0.0.1',
                        auth_port='35357', auth_protocol='http', rabbit_password='guest',rabbit_host='127.0.0.1',external_network_bridge = 'br-ex'):
    utils.set_option(QUANTUM_API_PASTE_CONF,'admin_tenant_name',service_tenant_name,section='filter:authtoken')
    utils.set_option(QUANTUM_API_PASTE_CONF,'admin_user',service_user,section='filter:authtoken')
    utils.set_option(QUANTUM_API_PASTE_CONF,'admin_password',service_pass,section='filter:authtoken')
    utils.set_option(QUANTUM_API_PASTE_CONF,'auth_host',auth_host,section='filter:authtoken')
    utils.set_option(QUANTUM_API_PASTE_CONF,'auth_port',auth_port,section='filter:authtoken')
    utils.set_option(QUANTUM_API_PASTE_CONF,'auth_protocol',auth_protocol,section='filter:authtoken')
    utils.set_option(QUANTUM_CONF,'fake_rabbit','False')
    utils.set_option(QUANTUM_CONF,'rabbit_password',rabbit_password)
    utils.set_option(QUANTUM_CONF,'rabbit_host',rabbit_host)
    utils.set_option(QUANTUM_CONF,'notification_driver', 'quantum.openstack.common.notifier.rabbit_notifier')
    utils.set_option(QUANTUM_CONF,'notification_topics', 'notifications,monitor')
    utils.set_option(QUANTUM_CONF,'default_notification_level', 'INFO')
    utils.set_option(QUANTUM_CONF,'external_network_bridge', external_network_bridge)
    utils.set_option(QUANTUM_CONF,'allow_overlapping_ips', "True")
    quantum_server_start()

def configure_ovs_plugin_gre(management_ip='127.0.0.1', mysql_username='quantum',tunnel_start='1',tunnel_end='1000',
                             mysql_password='stackops', mysql_host='127.0.0.1', mysql_port='3306', mysql_schema='quantum'):
    utils.set_option(OVS_PLUGIN_CONF,'sql_connection',utils.sql_connect_string(mysql_host, mysql_password, mysql_port, mysql_schema, mysql_username),section='DATABASE')
    utils.set_option(OVS_PLUGIN_CONF,'reconnect_interval','2',section='DATABASE')
    utils.set_option(OVS_PLUGIN_CONF,'tenant_network_type','gre',section='OVS')
    utils.set_option(OVS_PLUGIN_CONF,'tunnel_id_ranges','%s:%s' % (tunnel_start,tunnel_end),section='OVS')
    utils.set_option(OVS_PLUGIN_CONF,'local_ip', management_ip, section='OVS')
    utils.set_option(OVS_PLUGIN_CONF,'integration_bridge','br-int',section='OVS')
    utils.set_option(OVS_PLUGIN_CONF,'tunnel_bridge','br-tun',section='OVS')
    utils.set_option(OVS_PLUGIN_CONF,'enable_tunneling','True',section='OVS')
    utils.set_option(OVS_PLUGIN_CONF,'root_helper','sudo /usr/bin/quantum-rootwrap /etc/quantum/rootwrap.conf',section='AGENT')
    with settings(warn_only=True):
        sudo('ovs-vsctl del-br br-int')
    sudo('ovs-vsctl add-br br-int')
    openvswitch_start()
    quantum_plugin_openvswitch_agent_start()

def configure_l3_agent(service_user='quantum', service_tenant_name='service', service_pass='stackops', admin_user='admin', admin_tenant_name='admin',admin_pass='stackops',auth_url='http://localhost:35357/v2.0',metadata_ip='127.0.0.1',region='RegionOne',metadata_port='8775'):
    router_id = get_router_id('provider-router', admin_user, admin_tenant_name, admin_pass, auth_url)
    utils.set_option(L3_AGENT_CONF,'debug','True')
    utils.set_option(L3_AGENT_CONF,'interface_driver','quantum.agent.linux.interface.OVSInterfaceDriver')
    utils.set_option(L3_AGENT_CONF,'auth_url',auth_url)
    utils.set_option(L3_AGENT_CONF,'auth_region',region)
    utils.set_option(L3_AGENT_CONF,'admin_tenant_name',service_tenant_name)
    utils.set_option(L3_AGENT_CONF,'admin_user',service_user)
    utils.set_option(L3_AGENT_CONF,'admin_password',service_pass)
    utils.set_option(L3_AGENT_CONF,'root_helper','sudo quantum-rootwrap /etc/quantum/rootwrap.conf')
    utils.set_option(L3_AGENT_CONF,'metadata_ip',metadata_ip)
    utils.set_option(L3_AGENT_CONF,'metadata_port',metadata_port)
    utils.set_option(L3_AGENT_CONF,'use_namespaces','False')
    utils.set_option(L3_AGENT_CONF,'router_id',router_id)
    utils.set_option(L3_AGENT_CONF,'handle_internal_only_routers','True')
    utils.set_option(L3_AGENT_CONF,'polling_interval','3')
    quantum_l3_agent_start()

def configure_dhcp_agent(name_server='8.8.8.8'):
    utils.set_option(DHCP_AGENT_CONF,'use_namespaces','False')
    utils.set_option(DHCP_AGENT_CONF,'dnsmasq_dns_server',name_server)
    quantum_dhcp_agent_start()

def get_net_id(network_name, admin_user='admin', admin_tenant_name='admin', admin_pass='stackops', auth_url='http://localhost:5000/v2.0'):
    stdout = sudo("quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s net-list | grep %s | awk '/ | / { print $2 }'" % (auth_url,admin_user,admin_pass, admin_tenant_name, network_name))
    puts(stdout)
    return stdout.replace('\n', '')

def get_subnet_id(subnetwork_name, admin_user='admin', admin_tenant_name='admin', admin_pass='stackops', auth_url='http://localhost:5000/v2.0'):
    stdout = sudo("quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s subnet-list | grep %s | awk '/ | / { print $2 }'" % (auth_url,admin_user,admin_pass, admin_tenant_name, subnetwork_name))
    puts(stdout)
    return stdout.replace('\n', '')

def get_router_id(router_name, admin_user='admin', admin_tenant_name='admin', admin_pass='stackops', auth_url='http://localhost:5000/v2.0'):
    stdout = sudo("quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s router-list | grep %s | awk '/ | / { print $2 }'" % (auth_url,admin_user,admin_pass, admin_tenant_name, router_name))
    puts(stdout)
    return stdout.replace('\n', '')

def configure_external_network(floating_start,floating_end,floating_gw,floating_range, admin_user='admin', admin_tenant_name='admin', admin_pass='stackops', auth_url='http://localhost:5000/v2.0', external_network_name = 'ext-net'):
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s net-create %s --provider:network_type local  --router:external=True' % (auth_url,admin_user,admin_pass, admin_tenant_name, external_network_name))
    external_network_id = get_net_id(external_network_name, admin_user, admin_tenant_name, admin_pass, auth_url)
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s subnet-create --ip_version 4 --allocation-pool start=%s,end=%s --gateway %s --name %s %s %s --enable_dhcp=False' % (auth_url,admin_user,admin_pass, admin_tenant_name, floating_start, floating_end, floating_gw, external_network_name, external_network_id, floating_range))
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s router-create provider-router' % (auth_url,admin_user,admin_pass, admin_tenant_name))
    router_id = get_router_id('provider-router', admin_user, admin_tenant_name, admin_pass, auth_url)
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s router-gateway-set %s %s'  % (auth_url,admin_user,admin_pass, admin_tenant_name,router_id,external_network_name))

def configure_external_bridge():
    sudo('ip addr flush dev br-ex')
    sudo('ip addr add 0.0.0.0 dev br-ex')
    sudo('ip link set br-ex up')

def configure_default_private_network(network_name='default_private_network', private_range='10.0.0.0/24', private_gw='10.0.0.1', admin_user='admin', admin_tenant_name='admin', admin_pass='stackops', auth_url='http://localhost:5000/v2.0', dns_list='8.8.8.8 8.8.4.4'):
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s net-create %s' % (auth_url,admin_user,admin_pass, admin_tenant_name,network_name))
    private_network_id = get_net_id(network_name, admin_user, admin_tenant_name, admin_pass, auth_url)
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s subnet-create --ip_version 4 %s %s --gateway %s --dns_nameservers list=true %s --name %s'  % (auth_url,admin_user,admin_pass, admin_tenant_name,private_network_id,private_range,private_gw, dns_list, network_name))
    private_subnet_id = get_subnet_id(network_name, admin_user, admin_tenant_name, admin_pass, auth_url)
    router_id = get_router_id('provider-router', admin_user, admin_tenant_name, admin_pass, auth_url)
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s router-interface-add %s %s'  % (auth_url,admin_user,admin_pass, admin_tenant_name,router_id,private_subnet_id))

def delete_network(network, admin_user='admin', admin_tenant_name='admin', admin_pass='stackops', auth_url='http://localhost:5000/v2.0'):
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s net-delete %s' % (auth_url,admin_user,admin_pass, admin_tenant_name, network))

def delete_subnetwork(subnetwork, admin_user='admin', admin_tenant_name='admin', admin_pass='stackops', auth_url='http://localhost:5000/v2.0'):
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s subnet-delete %s' % (auth_url,admin_user,admin_pass, admin_tenant_name, subnetwork))

def delete_router(router_id, admin_user='admin', admin_tenant_name='admin', admin_pass='stackops', auth_url='http://localhost:5000/v2.0'):
    sudo('quantum --os-auth-url %s --os-username %s --os-password %s --os-tenant-name %s router-delete %s' % (auth_url,admin_user,admin_pass, admin_tenant_name, router_id))

def delete_gateway(ip):
    sudo('route del default gw %s' % ip)

def delete_default_gateway(management_iface="eth0"):
    with settings(warn_only=True):
        sudo("sudo route del default gw `route | grep 'default' | grep %s | awk '/  / { print $2 }' | tail -1`" % management_iface)
    with settings(warn_only=True):
        sudo("sudo route del default gw `route | grep 'default' | grep %s | awk '/  / { print $2 }' | tail -1`" % management_iface)
