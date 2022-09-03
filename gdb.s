#gef config gef.debug 1
source shogun.py
pi gef.gdb.load()
b main 
# b *0x5555555551e9
run
