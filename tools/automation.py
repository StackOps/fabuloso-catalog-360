#!/usr/bin/env python
import fabuloso
import properties  # Alert! relative import!
import string,random

automation = {
    'host': 'localhost',
    'port': 22,
    'username': 'stackops',
    'key_name': 'nonsecure'
}

###########################################################
## AUTOMATION
###########################################################

def _generate_token():
  length=25
  letters=string.ascii_letters+string.digits # alphanumeric, upper and lowercase
  return ''.join([random.choice(letters) for _ in range(length)])


fab = fabuloso.Fabuloso()

# Prepare OS
print 'Preparing OS and setting repos...'
os = fab.init_component("folsom.os", properties.os, fabuloso.Environment(automation))
os.install()

# Prepare mysql
print 'Installing MySQL and creating databases...'
mysql = fab.init_component("folsom.mysql", properties.mysql, fabuloso.Environment(automation))
mysql.install()
mysql.set_keystone()
mysql.set_automation()

# Prepare Keystone and register services
print 'Installing Keystone...'
keystone = fab.init_component("folsom.keystone", properties.keystone, fabuloso.Environment(automation))
keystone.install()
keystone.register_automation()

# Install apache
print 'Installing Apache...'
apache = fab.init_component("folsom.apache", properties.apache, fabuloso.Environment(automation))
apache.install()
apache.start()

print 'Installing Portal...'
license_token = _generate_token()
properties.portal['automation_license_token'] = license_token
portal = fab.init_component("folsom.portal", properties.portal, fabuloso.Environment(automation))
portal.install()
portal.start()

# Install automation
print 'Installing Automation...'
properties.automation['license_token'] = license_token
automation_comp = fab.init_component("folsom.automation", properties.automation, fabuloso.Environment(automation))
automation_comp.install()
automation_comp.configure()
automation_comp.start()
