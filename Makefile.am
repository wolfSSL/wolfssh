# includes append to these:
bin_PROGRAMS =
noinst_HEADERS =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
nobase_include_HEADERS =
check_PROGRAMS =
dist_noinst_SCRIPTS =

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

# SBOM generation (CRA compliance)
SBOM_CDX     = wolfssh-$(PACKAGE_VERSION).cdx.json
SBOM_SPDX    = wolfssh-$(PACKAGE_VERSION).spdx.json
SBOM_SPDX_TV = wolfssh-$(PACKAGE_VERSION).spdx
sbomdir      = $(datadir)/doc/$(PACKAGE)

.PHONY: sbom install-sbom uninstall-sbom

sbom:
	@if test -z "$(PYTHON3)"; then \
	    echo ""; \
	    echo "ERROR: 'python3' not found in PATH. Cannot generate SBOM."; \
	    echo ""; \
	    exit 1; \
	fi
	@if test -z "$(PYSPDXTOOLS)"; then \
	    echo ""; \
	    echo "ERROR: 'pyspdxtools' not found in PATH. Cannot validate SBOM."; \
	    echo "       Install: pip install spdx-tools"; \
	    echo ""; \
	    exit 1; \
	fi
	@if test -z "$(WOLFSSL_DIR)"; then \
	    echo ""; \
	    echo "ERROR: WOLFSSL_DIR is not set. Cannot locate gen-sbom."; \
	    echo "       Re-run: make sbom WOLFSSL_DIR=/path/to/wolfssl"; \
	    echo ""; \
	    exit 1; \
	fi
	@if test ! -f "$(WOLFSSL_DIR)/scripts/gen-sbom"; then \
	    echo ""; \
	    echo "ERROR: $(WOLFSSL_DIR)/scripts/gen-sbom not found."; \
	    echo "       Use a wolfSSL tree that includes SBOM support."; \
	    echo ""; \
	    exit 1; \
	fi
	rm -rf $(abs_builddir)/_sbom_staging $(abs_builddir)/_sbom_defines.h
	$(MAKE) install DESTDIR=$(abs_builddir)/_sbom_staging
	$(CC) -dM -E -I$(srcdir) $(CPPFLAGS) -x c /dev/null \
	    > $(abs_builddir)/_sbom_defines.h
	@set -e; \
	_so=$$(ls $(abs_builddir)/_sbom_staging$(libdir)/libwolfssh.so.[0-9]*.[0-9]*.[0-9]* 2>/dev/null | head -1); \
	test -n "$$_so" || { echo "ERROR: libwolfssh.so not found in staging dir" >&2; exit 1; }; \
	$(PYTHON3) $(WOLFSSL_DIR)/scripts/gen-sbom \
	    --name wolfssh \
	    --version $(PACKAGE_VERSION) \
	    --supplier "wolfSSL Inc." \
	    --license-file $(srcdir)/LICENSING \
	    --options-h $(abs_builddir)/_sbom_defines.h \
	    --lib "$$_so" \
	    $(if $(SBOM_LICENSE_OVERRIDE),--license-override $(SBOM_LICENSE_OVERRIDE)) \
	    $(if $(SBOM_LICENSE_TEXT),--license-text $(SBOM_LICENSE_TEXT)) \
	    --cdx-out $(abs_builddir)/$(SBOM_CDX) \
	    --spdx-out $(abs_builddir)/$(SBOM_SPDX)
	rm -rf $(abs_builddir)/_sbom_staging $(abs_builddir)/_sbom_defines.h
	$(PYSPDXTOOLS) --infile $(abs_builddir)/$(SBOM_SPDX) \
	    --outfile $(abs_builddir)/$(SBOM_SPDX_TV)

install-sbom: sbom
	$(MKDIR_P) $(DESTDIR)$(sbomdir)
	$(INSTALL_DATA) $(SBOM_CDX) $(DESTDIR)$(sbomdir)/
	$(INSTALL_DATA) $(SBOM_SPDX) $(DESTDIR)$(sbomdir)/
	$(INSTALL_DATA) $(SBOM_SPDX_TV) $(DESTDIR)$(sbomdir)/

uninstall-sbom:
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_CDX)
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_SPDX)
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_SPDX_TV)

CLEANFILES = $(SBOM_CDX) $(SBOM_SPDX) $(SBOM_SPDX_TV)
