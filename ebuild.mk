config-in     := Config.in
#config-h     := nwif/config.h

common-cflags      := -Wall -Wextra \
                      -D_GNU_SOURCE \
                      -DCONFIG_NWIF_LOCALSTATEDIR="\"$(LOCALSTATEDIR)/lib/nwif\""

solibs             := libnwif.so
libnwif.so-objs     = iface.o conf.o
libnwif.so-objs    += $(call kconf_enabled,NWIF_ETHER,ether.o)
libnwif.so-cflags   = $(EXTRA_CFLAGS) $(common-cflags) -DPIC -fpic
libnwif.so-ldflags  = $(EXTRA_LDFLAGS) -shared -fpic -Wl,-soname,libnwif.so
libnwif.so-pkgconf  = libnlink libkvstore

HEADERDIR          := $(CURDIR)/include
headers             = nwif/nwif.h nwif/conf.h
headers            += $(call kconf_enabled,NWIF_ETHER,nwif/ether.h)

define libnwif_pkgconf_tmpl
prefix=$(PREFIX)
exec_prefix=$${prefix}
libdir=$${exec_prefix}/lib
includedir=$${prefix}/include

Name: libnwif
Description: Network interfaces management library
Version: %%PKG_VERSION%%
Requires.private: libnlink libkvstore
Cflags: -I$${includedir}
Libs: -L$${libdir} -lnwif
endef

pkgconfigs         := libnwif.pc
libnwif.pc-tmpl    := libnwif_pkgconf_tmpl

bins               := nwif_conf
nwif_conf-objs     := nwif_conf.o ui.o
nwif_conf-cflags   := $(EXTRA_CFLAGS) $(common-cflags)
nwif_conf-ldflags  := $(EXTRA_LDFLAGS) -lnwif
nwif_conf-pkgconf   = libclui libutils smartcols \
                      $(call kconf_enabled,NWIF_BTRACE,libbtrace)

#bins          := nwifd
#nwifd-objs    := ether.o
#nwifd-cflags  := $(EXTRA_CFLAGS) -Wall -Wextra -D_GNU_SOURCE
#nwifd-ldflags := $(EXTRA_LDFLAGS)
#nwifd-pkgconf := libnlink
#nwifd-path    := $(SBINDIR)/nwifd
