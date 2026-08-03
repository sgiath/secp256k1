# C library source
LIB_VERSION := v0.7.1
LIB_COMMIT := 1a53f4961f337b4d166c25fce72ef0dc88806618
LIB_SHA256 := 0f587e73557494d423beeeaa0a4c4c0331bb612880c330fdc99dfd902e9ce020

.DEFAULT_GOAL := all

# --- Tools ---
CC ?= gcc
MAKE := $(MAKE)

# --- Directories ---
TARGET_DIR := ./priv
SRC_DIR := ./c_src
LIB_SRC_DIR := $(SRC_DIR)/secp256k1
LIB_TARBALL := $(SRC_DIR)/secp256k1-$(LIB_VERSION).tar.gz
LIB_BUILD_DIR := $(LIB_SRC_DIR)/.libs
LIB_STATIC_LIB := $(LIB_BUILD_DIR)/libsecp256k1.a

# --- Verbosity Control ---
# Default to quiet execution. Run `make V=1` for verbose output.
ifndef V
  QUIET_CMD = > /dev/null 2>&1
  QUIET_MAKE = --silent
  ECHO = @echo
else
  QUIET_CMD =
  QUIET_MAKE =
  ECHO = @\# # Echo command becomes a comment (no-op)
endif

# --- Build Flags ---
# Check for required Erlang include directory
ifeq ($(MAKECMDGOALS),)
  ERTS_REQUIRED := yes
else ifneq ($(filter-out vendor clean distclean,$(MAKECMDGOALS)),)
  ERTS_REQUIRED := yes
endif

ifeq ($(ERTS_REQUIRED),yes)
  ifeq ($(ERTS_INCLUDE_DIR),)
    $(error ERTS_INCLUDE_DIR is not set. Please set it, e.g., ERTS_INCLUDE_DIR=$$(erl -eval 'io:format("~s/erts-~s/include",[code:root_dir(), erlang:system_info(version)]).' -noshell -s init stop))
  endif
endif

CPPFLAGS += -I$(ERTS_INCLUDE_DIR)
CPPFLAGS += -I$(LIB_SRC_DIR)/include

CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
CFLAGS += -fPIC # Required for shared objects

LDFLAGS ?=
LIBS ?=

# add macOS specific LDFLAGS
# `uname -s` describes the build host, not the build target, so it must not be
# used on its own to pick target specific flags. When cross compiling (e.g.
# building for Nerves/Linux from macOS) the toolchain sets CROSSCOMPILE, and
# passing `-undefined dynamic_lookup` to the target's GNU ld makes it look for a
# file named `dynamic_lookup` and fail with "C compiler cannot create
# executables". Only add the flag for native macOS builds.
OS := $(shell uname -s)
ifeq ($(CROSSCOMPILE),)
  ifeq ($(OS), Darwin)
    LDFLAGS += -undefined dynamic_lookup
  endif
endif

# --- secp256k1 Library Options ---
CONFIG_OPTS = --disable-benchmark --disable-tests --disable-fast-install --with-pic --enable-experimental --enable-module-musig

# autotools needs `--host` when cross compiling, otherwise configure tries to
# run the test binaries it just built for the target and aborts with "cannot run
# C compiled programs". CROSSCOMPILE holds the toolchain prefix (for example
# /path/to/bin/aarch64-nerves-linux-gnu), so its basename is the target triplet.
ifneq ($(CROSSCOMPILE),)
  CONFIG_OPTS += --host=$(notdir $(CROSSCOMPILE))
endif

# --- Source Files & Targets ---
NIF_SOURCES = $(wildcard $(SRC_DIR)/*.c)
NIF_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(SRC_DIR)/%.o,$(NIF_SOURCES))
NIF_TARGET = $(TARGET_DIR)/secp256k1_nif.so

# Utility headers (used as dependencies to trigger rebuilds)
UTILS = $(SRC_DIR)/random.h $(SRC_DIR)/utils.h $(SRC_DIR)/nifs.h

# Version- and checksum-specific stamp indicating verified source extraction
EXTRACT_STAMP = $(LIB_SRC_DIR)/.extracted-$(LIB_VERSION)-$(LIB_SHA256)

# --- Default Target ---
.PHONY: all
all: $(NIF_TARGET)

# --- NIF Compilation and Link Rules ---
# $@ = target file ($(SRC_DIR)/%.o)
# $< = first prerequisite ($(SRC_DIR)/%.c)
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(UTILS) $(EXTRACT_STAMP)
	$(ECHO) "  CC       $@"
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(NIF_TARGET): $(NIF_OBJECTS) $(LIB_STATIC_LIB)
	@mkdir -p $(@D)
	$(ECHO) "  LD       $@"
	@$(CC) $(CFLAGS) -shared -o $@ $(NIF_OBJECTS) $(LIB_STATIC_LIB) $(LDFLAGS) $(LIBS)
	@rm -f $(TARGET_DIR)/ecdsa.so $(TARGET_DIR)/schnorrsig.so $(TARGET_DIR)/ecdh.so $(TARGET_DIR)/extrakeys.so $(TARGET_DIR)/musig.so

# --- secp256k1 Library Compilation Chain ---

# The static library depends on the Makefile existing *and* being configured
$(LIB_STATIC_LIB): $(LIB_SRC_DIR)/Makefile
	$(ECHO) "  MAKE     libsecp256k1"
	@$(MAKE) -C $(LIB_SRC_DIR) $(QUIET_MAKE) $(QUIET_CMD)

# The Makefile is created by configure after verified source extraction
$(LIB_SRC_DIR)/Makefile: $(EXTRACT_STAMP)
	$(ECHO) "  CONFIG   libsecp256k1"
	@cd $(LIB_SRC_DIR) && ./configure $(CONFIG_OPTS) $(QUIET_CMD)

# Verification happens at extraction time, not on every no-op compile.
$(EXTRACT_STAMP): $(LIB_TARBALL)
	$(ECHO) "  EXTRACT  libsecp256k1 ($(LIB_VERSION))"
	@tmp="$(LIB_SRC_DIR).tmp"; stamp="$@"; installed=no; committed=no; \
	cleanup_paths() { \
		rm -rf "$$tmp" || :; \
		if [ "$$committed" != yes ]; then \
			rm -f "$$stamp" || :; \
			if [ "$$installed" = yes ]; then rm -rf "$(LIB_SRC_DIR)" || :; fi; \
		fi; \
	}; \
	on_exit() { status=$$?; trap - 0 1 2 15; cleanup_paths; exit "$$status"; }; \
	on_signal() { trap - 0 1 2 15; cleanup_paths; exit 1; }; \
	trap on_exit 0; \
	trap on_signal 1 2 15; \
	if command -v sha256sum >/dev/null 2>&1; then actual=$$(sha256sum "$(LIB_TARBALL)" | awk '{print $$1}'); \
	elif command -v shasum >/dev/null 2>&1; then actual=$$(shasum -a 256 "$(LIB_TARBALL)" | awk '{print $$1}'); \
	else echo "libsecp256k1: need sha256sum or shasum on PATH" >&2; exit 1; fi; \
	if [ "$$actual" != "$(LIB_SHA256)" ]; then \
		echo "libsecp256k1 tarball checksum mismatch: expected $(LIB_SHA256), got $$actual" >&2; \
		exit 1; \
	fi; \
	rm -rf "$(LIB_SRC_DIR)" "$$tmp" && \
	mkdir -p "$$tmp" && \
	tar -xzf "$(LIB_TARBALL)" -C "$$tmp" --strip-components=1 && \
	mv "$$tmp" "$(LIB_SRC_DIR)" && \
	installed=yes && \
	touch "$$stamp" && \
	committed=yes && \
	trap - 0 1 2 15

.PHONY: vendor
vendor:
	$(if $(VERSION),,$(error VERSION is required, e.g. make vendor VERSION=v0.8.0))
	@./scripts/vendor-secp256k1.sh $(VERSION)

# --- Cleaning Targets ---
.PHONY: clean distclean

# clean: Remove built NIFs and clean the library build artifacts
clean:
	$(ECHO) "  CLEAN    build artifacts"
	@rm -f $(TARGET_DIR)/*.so
	@rm -f $(SRC_DIR)/*.o
	@if [ -f "$(LIB_SRC_DIR)/Makefile" ]; then \
		$(MAKE) -C $(LIB_SRC_DIR) clean $(QUIET_MAKE) $(QUIET_CMD); \
	fi

# distclean: Remove everything clean does, plus the extracted library source
distclean: clean
	$(ECHO) "  CLEAN    extracted sources"
	@rm -rf $(LIB_SRC_DIR) $(LIB_SRC_DIR).tmp
