all:
	$(MAKE) -C lib

.PHONY:
tests:
	KEYSTONE_SDK_DIR=`pwd` ./examples/tests/vault.sh

clean:
	$(MAKE) -C lib clean
