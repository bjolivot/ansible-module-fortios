#!/usr/bin/python
#
# Ansible module to manage IP addresses on fortios devices
# (c) 2016, Benjamin Jolivot <bjolivot@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'version': '0.1'
}

DOCUMENTATION = """
---
module: fortios_address_group
version_added: "2.3"
author: "Benjamin Jolivot (@bjolivot)"
short_description: Manage fortios firewall address group objects
description:
  - This module provide management of firewall address groups on FortiOS devices
options:
  host:
    description:
      - Specifies the DNS hostname or IP address for connecting to the remote fortios device
    required: true
  username:
    description:
      - Configures the username used to authenticate to the remote device.
    required: true
  password:
    description:
      - Specifies the password used to authenticate to the remote device.
    required: true
  timeout
    description:
      - Specifies timeout in seconds for connecting to the remote device.
      required: false 
      default: 60
  vdom
    description:
      - Specifies on which vdom to apply configuration
      required: false
      default: None
  name
    description:
      - Name of the address group
      required: true
  member
    description:
      - Member address name to add/delete
      required: true
  state
    description:
      - Specifies if address need to be added or deleted in group
      required: true
      choices: ['present', 'absent']
  comment
    description:
      - free text to describe address group
      required: false
  logfile
    description:
      - logfile path to log command sent to the device and responses
      required: false 

 
notes:
  - This module requires pyFG and netaddr python library
"""

EXAMPLES = """
- name: Add google DNS address object in dns_servers address group
  fortios_address_group:
    host: 192.168.0.254
    username: admin
    password: password
    state: present
    name: dns_servers
    member: google_dns
    comment: "Public DNS servers"

- name: Remove yahoo from trusted mail providers
  fortios_address_group:
    host: 192.168.0.254
    username: admin
    password: password
    state: absent
    name: trusted_mail_providers
    member: yahoo_server
    comment: "Trusted Email providers"
"""

RETURN = """
firewall_address_config:
  description: full firewall adresses config string
  returned: always
  type: string
change_string:
  description: The commands executed by the module
  returned: only if config changed
  type: string
"""
import logging
import re
import shlex
from ansible.module_utils.basic import AnsibleModule


#check for pyFG lib
try:
    from pyFG import *
    from pyFG.fortios import logger
    from pyFG.exceptions import *
    HAS_PYFG=True
except:
    HAS_PYFG=False

#check for netaddr lib
try:
    from netaddr import *
    HAS_NETADDR=True
except:
    HAS_NETADDR=False

def is_invalid_name(input_str):
  #char must be letters, digits, - , _ , . 
  #must have between 1 and 63 chars 
  reg=re.compile(r'^[a-zA-Z0-9\.\-_]{1,63}$')
  return not reg.match(input_str)

def main():
    #define module params
    argument_spec = dict(
            host             = dict(required=True ),
            username         = dict(required=True ),
            password         = dict(required=True, type='str' ),
            timeout          = dict(type='int', default=60),
            vdom             = dict(type='str', default=None ),
            state            = dict(required=True, choices=['present', 'absent']),
            name             = dict(required=True, type='str'),
            member           = dict(required=True, type='str'),
            comment          = dict(),
            logfile          = dict(type='str')
    )

    #decalre module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    
    #logger
    if module.params['logfile'] is not None:
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(module.params['logfile'])
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)


    #check params
    if is_invalid_name(module.params['name']):
      module.fail_json(msg="Bad name argument value, must contain only letters, digits, -, _, .")

    if is_invalid_name(module.params['member']):
      module.fail_json(msg="Bad member argument value, must contain only letters, digits, -, _, .")

    #prepare return dict
    retkwargs = dict(changed=False)

    # fail if libs not present
    msg = ""
    if not HAS_PYFG:
        msg += 'Could not import the python library pyFG required by this module'
    
    if not HAS_NETADDR:
        msg += 'Could not import the python library netaddr required by this module'    

    if msg != "":
        module.fail_json(msg=msg)
   
    #define device
    f = FortiOS( module.params['host'], 
        username=module.params['username'], 
        password=module.params['password'], 
        timeout=module.params['username'],
        vdom=module.params['vdom'])
    
    path = 'firewall addrgrp'

    #connect
    try: 
        f.open()
    except:
        module.fail_json(
            msg='Error connecting device'
        )

 
    #get  config
    try: 
        f.load_config(path=path)
        retkwargs['firewall_address_config'] = f.running_config.to_text()

    except:
        module.fail_json(
            msg='Error reading running config'
        )


    #load group member list if group exists
    group_members = []
    try:
      group_members = shlex.split(f.running_config[path][module.params['name']].get_param('member'))
    except:
      pass
    
    #generate target group list
    if module.params['state'] == 'absent':
      if module.params['member'] in group_members:
        group_members.remove(module.params['member'])
    else:
      #state = present
      if module.params['member'] not in group_members:
        group_members.append(module.params['member'])


    #delete group if empty
    if len(group_members) == 0:
      f.candidate_config[path].del_block(module.params['name'])
    else:
      #process changes
      new_grp = FortiConfig(module.params['name'], 'edit')
      new_grp.set_param('member', " ".join(group_members) )

      if module.params['comment'] is not None:
          new_grp.set_param('comment', '"{0}"'.format(module.params['comment']))

      #add to candidate config
      f.candidate_config[path][module.params['name']] = new_grp
  
    #compare config
    change_string = f.compare_config()
    if change_string != "":
        retkwargs['change_string'] = change_string
        retkwargs['changed'] = True
    
    #Commit if not check mode
    if module.check_mode == False and change_string != "":
        try:
            f.commit()
        except FailedCommit as e:
            #rollback
            module.fail_json(msg="Unable to commit change, check your args, the error was {0}".format(e.message))

    module.exit_json(**retkwargs)


if __name__ == '__main__':
    main()

