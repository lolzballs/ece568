#This Makefile is mainly used for check your lab
.PHONY: driver, server, grammar, post_library.so, clean
driver:
	cd part2; $(MAKE) clean; $(MAKE) step1
post_library.so:
	cd part2; $(MAKE) clean; $(MAKE) step2
server:
	cd part3/lighttpd-template; $(MAKE) clean; $(MAKE)
grammar:
	cd part3/Grammar-Mutator; $(MAKE) clean; $(MAKE) GRAMMAR_FILE=grammars/http.json
clean:
	cd part2; $(MAKE) clean;
	cd part3/lighttpd-template; $(MAKE) clean;
	cd part3/Grammar-Mutator; $(MAKE) clean;

