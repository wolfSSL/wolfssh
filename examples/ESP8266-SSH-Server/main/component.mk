#
# "main" pseudo-component makefile.
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)

COMPONENT_SRCDIRS +=
CXXFLAGS += $(COMPONENT_PRIV_COMMONFLAGS)
CFLAGS += $(COMPONENT_PRIV_COMMONFLAGS)
