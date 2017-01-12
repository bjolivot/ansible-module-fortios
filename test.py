#!/usr/bin/python





from pyFG import *






d = FortiOS('192.168.137.154', username="admin", password="")

d.open()

d.load_config()

running =  d.running_config.to_text()






