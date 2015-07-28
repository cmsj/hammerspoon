mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))

MODULE = $(current_dir)

PREFIX  ?= .
OBJCFILE = internal.m snej/CollectionUtils.m snej/Logging.m snej/MYASN1Object.m snej/MYBERParser.m snej/MYCertificateInfo.m snej/MYDEREncoder.m snej/MYDigest.m snej/MYErrorUtils.m snej/MYKey.m snej/MYOID.m snej/MYPrivateKey.m snej/Test.m snej/Test_Assertions.m snej/MYCertificate.m snej/MYKeychainItem.m snej/MyPublicKey.m snej/MyKeychain.m snej/MySymmetricKey.m snej/MYIdentity.m snej/MYCryptor.m
LUAFILE  = init.lua
SOFILE  := $(OBJCFILE:m=so)

CC?=cc
EXTRA_CFLAGS ?= -fobjc-arc

#TODO: Put this back for 1.0
#DEBUG_CFLAGS ?= -g
DEBUG_CFLAGS = -g

CFLAGS  += $(DEBUG_CFLAGS) -Wall -Wextra -I ../../Pods/Headers/Public -F../../ -framework LuaSkin -framework Fabric -framework MultipeerConnectivity $(EXTRA_CFLAGS)
LDFLAGS += -dynamiclib -undefined dynamic_lookup $(EXTRA_LDFLAGS)

all: $(SOFILE)

$(SOFILE): $(OBJCFILE) $(HEADERS)
	$(CC) $(@:so=m) $(CFLAGS) $(LDFLAGS) -o $@

install: install-objc install-lua

install-objc: $(SOFILE)
	mkdir -p $(PREFIX)/$(MODULE)
	install -m 0644 $(SOFILE) $(PREFIX)/$(MODULE)

install-lua: $(LUAFILE)
	mkdir -p $(PREFIX)/$(MODULE)
	install -m 0644 $(LUAFILE) $(PREFIX)/$(MODULE)

clean:
	rm -f $(SOFILE)

.PHONY: all clean
