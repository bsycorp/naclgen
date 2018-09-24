
all: trivial sample1

trivial:
	../naclgen.py trivial.ng trivial.policy > trivial.tf
	terraform fmt trivial.tf

sample1:
	../naclgen.py sample1.ng sample1.policy > sample1.tf
	terraform fmt sample1.tf


