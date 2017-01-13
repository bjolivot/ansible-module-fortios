# FortiOS ansible modules repository

Note: This is work in progress so take care of managing production devices /!\

At this moment, only following modules are availlable :

 - fortios_config.py : 
  this module manage import and export configuration files.
 
 - fortios_address:
   This module manage firewall address objects (add, remove, update).
   Currently, it support ipmask, fqdn, geography and ip ranges address types.

 - fortios_address_group:
   This module manage firewall address groups (add & remove members, update).


### Dependencies

Following python library are required :
 - [pyFG](https://github.com/spotify/pyFG)
 - [netaddr](https://pypi.python.org/pypi/netaddr)

These are installed with pip.

### Installation
* Install the dependencies

```sh
$ pip install pyFG
$ pip install netaddr
```
* Clone this repository
```sh
$ git clone https://github.com/bjolivot/ansible-module-fortios /home/ansible/library
```

* update your ansible.cfg file with following line 
```
library = /home/ansible/library/fortios
```

### Documentation

I hope I have respected Ansible Documentation format, included in modules files.

### Todos

 - Add missing modules (users, policies, adom support...)
 - Remove external dependencies
 - Python3 port
 - add tests
 - Ansible community modules integration
 - ...

Feel free to contribute at any level.

License
----

MIT


