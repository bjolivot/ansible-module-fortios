#!/bin/python

from ansible.module_utils.basic import AnsibleModule

from pyFG import *

try:
    from pyFG import *
    HAS_PYFG=True
except:
    HAS_PYFG=False



def main():
    argument_spec = dict(
            hostname    = dict(required=True ),
            username    = dict(required=True ),
            password    = dict(required=True ),
            filter      = dict(),
            timeout     = dict(type='int', default=60),
            vdom        = dict(),
            backup      = dict(type='bool', default=False),
            backup_dest = dict(),
            src         = dict(default=""),

            # state     = dict(default='present', choices=['present', 'absent']),
            # name      = dict(required=True),
            # enabled   = dict(required=True, type='bool'),
            # something = dict(aliases=['whatever'])
    )


    required_if = [
        ["backup", True, ["backup_dest"] ]
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
    )
    
    retkwargs = dict(changed=False)

    if not HAS_PYFG:
        module.fail_json(msg='could not import the python library '
                         'pyFG required by this module')

    f = FortiOS( module.params['hostname'], 
        username=module.params['username'], 
        password=module.params['password'], 
        timeout=module.params['username'],
        vdom=module.params['vdom'])
    


    try: 
        f.open()
    except:
        module.fail_json(
            msg='Error connecting device'
        )

 
    #Load full running config
    try: 
        f.load_config()
        retkwargs['running_config'] = f.running_config.to_text()

    except:
        module.fail_json(
            msg='Error reading running config'
        )
  


    if module.params['backup'] == True:
        try:
            backup_file = open(module.params['backup_dest'], "w")
            backup_file.write(retkwargs['running_config'])
            backup_file.close()
        except:
            module.fail_json(
                msg='Error writing running config to file {0}'.format(module.params['dest'])
            )

 


    module.exit_json(**retkwargs)


if __name__ == '__main__':
    main()

