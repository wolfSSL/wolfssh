# includes append to these:
bin_PROGRAMS =
noinst_HEADERS =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
nobase_include_HEADERS =
check_PROGRAMS =
dist_noinst_SCRIPTS =
CLEANFILES =

#includes additional rules from aminclude.am
@INC_AMINCLUDE@
DISTCLEANFILES = aminclude.am wolfssh-config

exampledir = $(docdir)/example

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = LICENSING README.md ChangeLog.md

include src/include.am
include wolfssh/include.am
include apps/include.am
include examples/include.am
include tests/include.am
include keys/include.am
include ide/include.am
include scripts/include.am

TEST_EXTENSIONS = .test
check_SCRIPTS = $(dist_noinst_SCRIPTS)
TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

test: check


maintainer-clean-local:
	-rm Makefile.in
	-rm aclocal.m4
	-rm build-aux/compile
	-rm build-aux/config.guess
	-rm build-aux/config.sub
	-rm build-aux/depcomp
	-rm build-aux/install-sh
	-rm build-aux/ltmain.sh
	-rm build-aux/missing
	-rm wolfssh-config
	-rmdir build-aux
	-rm configure
	-rm config.log
	-rm config.status
	-rm config.in
	-rm m4/libtool.m4
	-rm m4/ltoptions.m4
	-rm m4/ltsugar.m4
	-rm m4/ltversion.m4
	-rm m4/lt~obsolete.m4
	find . -type f -name '*~' -exec rm -f '{}' \;
	-rm -f @PACKAGE@-*.tar.gz
	-rm -f @PACKAGE@-*.rpm

install-exec-local:	install-generic-config

install-generic-config:
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	$(INSTALL_SCRIPT) @GENERIC_CONFIG@ $(DESTDIR)$(bindir)

uninstall-local:
	-rm -f $(DESTDIR)$(bindir)/@GENERIC_CONFIG@

merge-clean:
	@find ./ | $(GREP) \.gcda | xargs rm -f
	@find ./ | $(GREP) \.gcno | xargs rm -f
	@find ./ | $(GREP) \.gz | xargs rm -f
	@find ./ | $(GREP) \.orig | xargs rm -f
	@find ./ | $(GREP) \.rej | xargs rm -f
	@find ./ | $(GREP) \.rpm | xargs rm -f
	@find ./ | $(GREP) \.THIS | xargs rm -f
	@find ./ | $(GREP) \.OTHER | xargs rm -f
	@find ./ | $(GREP) \.BASE | xargs rm -f
	@find ./ | $(GREP) \~$$ | xargs rm -f

# SBOM generation (CRA compliance).  The recipe is shared across the wolfSSL
# stack's autotools products in scripts/sbom.am; wolfSSH just declares what it
# is (a library that links wolfSSL) and includes it.  WOLFSSL_DIR must point to
# a wolfssl source tree containing scripts/gen-sbom.
SBOM_PKGNAME      = wolfssh
SBOM_LICENSE_FILE = $(srcdir)/LICENSING
SBOM_DEP_WOLFSSL  = yes

# wolfSSH is GPLv3-or-commercial; its LICENSING uses the "GPLv3" abbreviation
# that older gen-sbom cannot parse (falls back to NOASSERTION).  Default to the
# correct SPDX id so the SBOM is right regardless of gen-sbom version; commercial
# licensees can still override it (e.g. LicenseRef-wolfSSL-Commercial).
# Redundant-but-harmless once the detect_license fix lands in gen-sbom
# (wolfSSL/wolfssl#10343).
SBOM_LICENSE_OVERRIDE ?= GPL-3.0-only

include scripts/sbom.am
