install:
	./buildall.sh
	sudo ./install.sh

clean:
	rm -rf output

.PHONY: install clean
