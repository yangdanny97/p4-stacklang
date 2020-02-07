BMV2_SWITCH_EXE = simple_switch_grpc

include utils/Makefile

setup:
	rm switch.p4; rm controller.py; ./python setup.py
