#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

SRC_FILES = $(filter-out $(wildcard mbedtls/*.*))

PROJECT_NAME := ESP8266-SSH-Server
$(info $$PROJECT_NAME is [${PROJECT_NAME}])

# WARNING: component files in this directory are STALE and for demo purposes ONLY
# for a proper SSH server, please install fresh wolfSSL and wolfSSH components
# in the ESP-IDF component directory and REMOVE this line:
EXTRA_COMPONENT_DIRS = ./components/
CPPFLAGS += -DWOLFSSL_STALE_EXAMPLE=YES
CFLAGS   += -DWOLFSSL_STALE_EXAMPLE=YES

# END OF STALE CODE WARNING. Remove above lines once ESP-IDF components installed


# Sysprogs VisualGDB has their own bash instance, so look in /c/workspace
ifeq (/c/workspace/my_private_config.h, $(wildcard /c/workspace/my_private_config.h))
$(info "Found VisualGDB /c/workspace/my_private_config.h")
CPPFLAGS += -DSYSPROGS_MY_PRIVATE_CONFIG=/c/workspace/my_private_config.h
CFLAGS   += -DSYSPROGS_MY_PRIVATE_CONFIG=/c/workspace/my_private_config.h

else
# Windows private config in /workspace/
ifeq (/workspace/my_private_config.h, $(wildcard /workspace/my_private_config.h))
$(info "Found /workspace/my_private_config.h" )
CPPFLAGS += -DWINDOWS_MY_PRIVATE_CONFIG=/workspace/my_private_config.h
CFLAGS   += -DWINDOWS_MY_PRIVATE_CONFIG=/workspace/my_private_config.h

else
# WSL directory is /mnt/c/workspace/
ifeq (/mnt/c/workspace/my_private_config.h, $(wildcard /mnt/c/workspace/my_private_config.h))
$(info "Found WSL /mnt/c/workspace/my_private_config.h")
CPPFLAGS += -DWSL_MY_PRIVATE_CONFIG=/mnt/c/workspace/my_private_config.h
CFLAGS   += -DWSL_MY_PRIVATE_CONFIG=/mnt/c/workspace/my_private_config.h

else
# for Linux, look in home directory ~/
ifeq (~/my_private_config.h, $(wildcard ~/my_private_config.h))
$(info "Found Linux ~/my_private_config.h")
CPPFLAGS += -DWSL_MY_PRIVATE_CONFIG=~/my_private_config.h
CFLAGS   += -DWSL_MY_PRIVATE_CONFIG=~/my_private_config.h

endif
endif
endif
endif

# show what we found
$(info $$CPPFLAGS is [${CPPFLAGS}])

include $(IDF_PATH)/make/project.mk

