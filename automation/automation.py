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
from fabric.api import settings, sudo
from cuisine import package_ensure, package_clean


def stop():
    with settings(warn_only=True):
        sudo("nohup service apirestd stop")
        sudo("nohup service discovery-agent stop")
        sudo("nohup service events-agent stop")
        sudo("nohup service health-system stop")
        sudo("nohup service celeryd stop")


def start():
    sudo("python /var/lib/stackops-head/bin/head-init initialize all "
         "2>/dev/null")
    sudo("nohup service apirestd restart")
    sudo("nohup service discovery-agent restart")
    sudo("nohup service events-agent restart")
    sudo("nohup service health-system restart")
    sudo("nohup service celeryd restart")


def configure_ubuntu_packages():
    """Configure portal packages"""
    package_ensure('stackops-head')


def uninstall_ubuntu_packages():
    """Uninstall portal packages"""
    package_clean('stackops-head')


def install(dhcp_start, dhcp_end, dhcp_listen_interface, gateway,
            netmask, domain, dns, license_manager_url,
            license_token='vs0QiaN9TA6lIIe3uPSfiG3fs'):

    """Generate automation configuration."""
    sudo('echo stackops-head stackops-head/accepted-stackops-license '
         'boolean true | debconf-set-selections')
    sudo('echo stackops-head stackops-head/dhcp-start string %s | '
         'debconf-set-selections' % dhcp_start)
    sudo('echo stackops-head stackops-head/dhcp-end string %s | '
         'debconf-set-selections' % dhcp_end)
    sudo('echo stackops-head stackops-head/dhcp_listen_interface string %s | '
         'debconf-set-selections' % dhcp_listen_interface)
    sudo('echo stackops-head stackops-head/domain string %s | '
         'debconf-set-selections' % domain)
    sudo('echo stackops-head stackops-head/gateway string %s | '
         'debconf-set-selections' % gateway)
    sudo('echo stackops-head stackops-head/netmask string %s | '
         'debconf-set-selections' % netmask)
    sudo('echo stackops-head stackops-head/dns string %s | '
         'debconf-set-selections' % dns)
    sudo('echo stackops-head stackops-head/download-stackops boolean true '
         '| debconf-set-selections')
    sudo('echo stackops-head stackops-head/license-manager-url string %s | '
         'debconf-set-selections' % license_manager_url)
    sudo('echo stackops-head stackops-head/license-manager-token string %s | '
         'debconf-set-selections' % license_token)
    configure_ubuntu_packages()


def configure(endpoint,
              token_service,
              mysql_username,
              mysql_password,
              automation_user,
              automation_password,
              mysql_schema="stackopshead",
              mysql_host="127.0.0.1",
              mysql_port="3306"):

    """Configure mysql in automation"""
    sql_connection = ("mysql://" + mysql_username + ":" + mysql_password +
                      "@" + mysql_host + ":" + mysql_port + "/" + mysql_schema)
    sudo('sed -e "s,^--sql_connection\s*=\s*.\+$,--sql_connection=%s," '
         '-i /var/lib/stackops-head/etc/*.conf ' % sql_connection)
    """Configure keystone related in automation"""
    sudo('sed -e "s,^--automation_user\s*=\s*.\+$,--automation_user=%s," '
         '-i /var/lib/stackops-head/etc/stackops-head-apirest-daemon.conf'
         % automation_user)
    sudo('sed -e "s,^--automation_password\s*=\s*.\+$,'
         '--automation_password=%s," -i '
         '/var/lib/stackops-head/etc/stackops-head-apirest-daemon.conf'
         % automation_password)
    uri_keystone_validation = endpoint + '/tokens/'
    sudo('sed -e "s,^--use_authorization\s*=\s*.\+$,--use_authorization=%s," '
         '-i /var/lib/stackops-head/etc/stackops-head-apirest-daemon.conf'
         % "True")
    sudo('sed -e "s,^--uri_keystone_validation\s*=\s*.\+$,'
         '--uri_keystone_validation=%s," '
         '-i /var/lib/stackops-head/etc/stackops-head-apirest-daemon.conf '
         % uri_keystone_validation)
    sudo('sed -e "s,^--token_service\s*=\s*.\+$,'
         '--token_service=%s," '
         '-i /var/lib/stackops-head/etc/stackops-head-apirest-daemon.conf '
         % token_service)
