# For COPR builds directly from git.
#
# https://docs.pagure.org/copr.copr/user_documentation.html#make-srpm
#

srpm: /usr/bin/git
	./mkspec.sh
	set -x;	if grep -q "global gitsnapshot 1" openconnect.spec; then \
		tarprefix=$$(sed -n '/^%global snapcommit /s/.* //p' openconnect.spec); \
		tarname=$${tarprefix:0:7}; \
	else \
		tarprefix=$$(sed -n '/^%global tagver /s/.* //p' openconnect.spec); \
		tarname=$${tarprefix}; \
	fi; \
	git archive --prefix=openconnect-$${tarprefix}/ HEAD -o .copr/openconnect-$${tarname}.tar.gz
	rpmbuild -bs openconnect.spec --define "_sourcedir .copr" --define "_srcrpmdir $(outdir)"

/usr/bin/git:
	dnf install git

build: srpm
	rpmbuild -bb openconnect.spec --define "_sourcedir `pwd`/.copr"
