
all:

deps:
	pip3 install coverage nose

test:
	nosetests --with-coverage --cover-html -v *_test.py

