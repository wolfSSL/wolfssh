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

# wolfSSH is licensed GPLv3-or-commercial.  Its LICENSING file uses the
# abbreviation "GPLv3", which older gen-sbom detect_license does not recognise
# (it matches only the long form "GNU General Public License version 3") and so
# falls back to NOASSERTION.  Default the override to the correct SPDX id so the
# SBOM is right regardless of gen-sbom version; commercial licensees can still
# override it (e.g. SBOM_LICENSE_OVERRIDE=LicenseRef-wolfSSL-Commercial).  Once
# the detect_license GPLv-abbreviation fix lands in gen-sbom (wolfSSL/wolfssl#10343)
# this default is redundant-but-harmless (GPL-3.0-only is what detection returns).
SBOM_LICENSE_OVERRIDE ?= GPL-3.0-only

# Shared-library / Mach-O basenames in priority order (versioned first) so
# `make sbom` finds the built artifact on ELF, Mach-O, and PE targets.  Static
# (.a) and Windows (.dll/.lib) variants are appended at the call-site because
# their prefixes differ.
WOLFSSH_LIB_DSO_BASENAMES = \
    libwolfssh.so.[0-9]* \
    libwolfssh.so \
    libwolfssh.[0-9]*.dylib \
    libwolfssh.dylib

.PHONY: sbom install-sbom uninstall-sbom

# Stage a `make install` into a private tree, discover the installed library
# artifact (shared or static, ELF/Mach-O/PE), hash it, capture the configured
# build macros, generate SPDX+CDX, validate the SPDX, then convert to
# tag-value.  The staging tree and temp defines file are removed
# unconditionally via `trap`, even on failure.  Honors SOURCE_DATE_EPOCH for
# reproducible builds (set to the last git commit time when unset and a git
# tree is available), matching wolfssl's `make sbom`.
#
# User-overridable variables:
#   WOLFSSL_DIR            Path to a wolfssl source tree containing
#                          scripts/gen-sbom (required).
#   SBOM_LICENSE_OVERRIDE  SPDX expression to record as the licence.  Defaults
#                          to GPL-3.0-only (wolfSSH's licence); commercial
#                          licensees override it (e.g.
#                          LicenseRef-wolfSSL-Commercial).
#   SBOM_LICENSE_TEXT      Path to the licence text for any LicenseRef-* used
#                          in SBOM_LICENSE_OVERRIDE (required by SPDX 2.3).
#   SBOM_WOLFSSL_VERSION   Version string recorded for the wolfssl dependency.
#                          Auto-detected from WOLFSSL_DIR/wolfssl/version.h or
#                          pkg-config when unset.
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
	@rm -rf $(abs_builddir)/_sbom_staging
	@set -e; \
	_defines=`mktemp $(abs_builddir)/_sbom_defines.XXXXXX`; \
	trap 'rm -rf $(abs_builddir)/_sbom_staging "$$_defines"' EXIT INT TERM HUP; \
	$(MAKE) install DESTDIR=$(abs_builddir)/_sbom_staging; \
	sbom_lib=""; \
	for lib in \
	    $(addprefix "$(abs_builddir)/_sbom_staging$(libdir)"/,$(WOLFSSH_LIB_DSO_BASENAMES)) \
	    "$(abs_builddir)/_sbom_staging$(libdir)"/libwolfssh.dll \
	    "$(abs_builddir)/_sbom_staging$(libdir)"/libwolfssh.dll.a \
	    "$(abs_builddir)/_sbom_staging$(libdir)"/libwolfssh.lib \
	    "$(abs_builddir)/_sbom_staging$(libdir)"/wolfssh.lib \
	    "$(abs_builddir)/_sbom_staging$(libdir)"/libwolfssh.a; do \
	    if test -f "$$lib"; then sbom_lib="$$lib"; break; fi; \
	done; \
	if test -z "$$sbom_lib"; then \
	    echo ""; \
	    echo "ERROR: No installed wolfSSH library artifact found for SBOM."; \
	    echo "       Searched in $(abs_builddir)/_sbom_staging$(libdir)"; \
	    echo "       (configure with --enable-shared or --enable-static)"; \
	    echo ""; \
	    exit 1; \
	fi; \
	echo "SBOM: hashing $$sbom_lib"; \
	$(CC) -dM -E $(DEFAULT_INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	    $(if $(wildcard $(abs_builddir)/config.h),-include $(abs_builddir)/config.h) \
	    -x c /dev/null > "$$_defines"; \
	wolfssl_ver="$(SBOM_WOLFSSL_VERSION)"; \
	if test -z "$$wolfssl_ver" && test -f "$(WOLFSSL_DIR)/wolfssl/version.h"; then \
	    wolfssl_ver=`sed -n 's/.*LIBWOLFSSL_VERSION_STRING[ \t]*"\([^"]*\)".*/\1/p' \
	        "$(WOLFSSL_DIR)/wolfssl/version.h"`; \
	fi; \
	if test -z "$${SOURCE_DATE_EPOCH:-}" && test -n "$(GIT)" && \
	   $(GIT) -C "$(srcdir)" rev-parse --git-dir >/dev/null 2>&1; then \
	    sde=`$(GIT) -C "$(srcdir)" log -1 --format=%ct 2>/dev/null`; \
	    if test -n "$$sde"; then SOURCE_DATE_EPOCH="$$sde"; export SOURCE_DATE_EPOCH; fi; \
	fi; \
	dep_args=""; \
	if $(PYTHON3) $(WOLFSSL_DIR)/scripts/gen-sbom --help 2>/dev/null \
	    | $(GREP) -q -- '--dep-wolfssl'; then \
	    dep_args="--dep-wolfssl yes"; \
	    if test -n "$$wolfssl_ver"; then \
	        dep_args="$$dep_args --dep-version wolfssl=$$wolfssl_ver"; \
	    fi; \
	else \
	    echo "NOTE: this gen-sbom has no --dep-wolfssl support, so the SBOM"; \
	    echo "      will not list wolfssl as a dependency component. That"; \
	    echo "      support is added by wolfSSL/wolfssl#10343; until it merges"; \
	    echo "      to wolfssl master, point WOLFSSL_DIR at that PR's branch to"; \
	    echo "      enable it. The generated SBOM is valid either way."; \
	fi; \
	$(PYTHON3) $(WOLFSSL_DIR)/scripts/gen-sbom \
	    --name wolfssh \
	    --version $(PACKAGE_VERSION) \
	    --supplier "wolfSSL Inc." \
	    --license-file $(srcdir)/LICENSING \
	    --options-h "$$_defines" \
	    --lib "$$sbom_lib" \
	    $$dep_args \
	    $(if $(SBOM_LICENSE_OVERRIDE),--license-override '$(SBOM_LICENSE_OVERRIDE)') \
	    $(if $(SBOM_LICENSE_TEXT),--license-text '$(SBOM_LICENSE_TEXT)') \
	    --cdx-out $(abs_builddir)/$(SBOM_CDX) \
	    --spdx-out $(abs_builddir)/$(SBOM_SPDX); \
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
