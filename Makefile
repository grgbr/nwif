#EBUILDDIR     := $(CURDIR)/ebuild
PACKAGE       := nwif
EXTRA_CFLAGS  := -O2 -DNDEBUG
EXTRA_LDFLAGS := -O2

export EXTRA_CFLAGS EXTRA_LDFLAGS

include $(EBUILDDIR)/main.mk
