# C library source
LIB_VERSION := v0.7.1
LIB_COMMIT := 1a53f4961f337b4d166c25fce72ef0dc88806618
LIB_SHA256 := 0f587e73557494d423beeeaa0a4c4c0331bb612880c330fdc99dfd902e9ce020

# --- Tools ---
CC ?= gcc

# --- Directories ---
TARGET_DIR := ./priv
SRC_DIR := ./c_src
LIB_SRC_DIR := $(SRC_DIR)/secp256k1
LIB_TARBALL := $(SRC_DIR)/secp256k1-$(LIB_VERSION).tar.gz
LIB_BUILD_DIR := $(LIB_SRC_DIR)/.libs
LIB_STATIC_LIB := $(LIB_BUILD_DIR)/libsecp256k1.a

# Logs of the upstream configure/make steps (inside the extracted tree).
LIB_CONFIGURE_LOG := $(LIB_SRC_DIR)/.nif-configure.log
LIB_MAKE_LOG := $(LIB_SRC_DIR)/.nif-make.log

# Build configuration fingerprints. Each file holds the build variables that
# affect its consumers and is only rewritten when that content changes, so a
# changed compiler or flag set rebuilds exactly what it affects while a repeated
# `make` stays a no-op.
NIF_BUILD_CONFIG := $(SRC_DIR)/.build-config
LIB_BUILD_CONFIG := $(SRC_DIR)/.build-config-libsecp256k1

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

# $(call logged,LOGFILE,COMMAND)
# Quiet builds capture COMMAND output in LOGFILE and print it only on failure.
# Verbose builds (V=1) stream the output directly.
ifndef V
  logged = ( $(2) ) > $(1) 2>&1 || { status=$$?; cat $(1) >&2; echo "  FAILED   (log: $(1))" >&2; exit $$status; }
else
  logged = $(2)
endif

# Quote a value for use inside a single-quoted shell string.
sq = $(subst ','\'',$(1))

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

# --- Opt-in developer/CI flags (first-party NIF code only) ---
# SECP256K1_NIF_WERROR=1   turn warnings into errors when compiling c_src/*.c.
#                          Never applied to the upstream configure/make.
# SECP256K1_NIF_SANITIZE=1 compile and link the NIF with ASan + UBSan. The BEAM
#                          is not instrumented, so the ASan runtime must be
#                          preloaded, e.g. LD_PRELOAD=$(gcc -print-file-name=libasan.so).
NIF_WERROR_FLAGS :=
ifeq ($(SECP256K1_NIF_WERROR),1)
  NIF_WERROR_FLAGS := -Werror
endif

NIF_SANITIZE_FLAGS :=
ifeq ($(SECP256K1_NIF_SANITIZE),1)
  NIF_SANITIZE_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -g
endif

NIF_CFLAGS = $(CFLAGS) $(NIF_WERROR_FLAGS) $(NIF_SANITIZE_FLAGS)
NIF_LDFLAGS = $(CFLAGS) $(NIF_SANITIZE_FLAGS)

# --- secp256k1 Library Options ---
CONFIG_OPTS = --disable-benchmark --disable-tests --disable-fast-install --with-pic --enable-experimental --enable-module-musig

# autotools needs `--host` when cross compiling, otherwise configure tries to
# run the test binaries it just built for the target and aborts with "cannot run
# C compiled programs". CROSSCOMPILE holds the toolchain prefix (for example
# /path/to/bin/aarch64-nerves-linux-gnu), so its basename is the target triplet.
ifneq ($(CROSSCOMPILE),)
  CONFIG_OPTS += --host=$(notdir $(CROSSCOMPILE))
endif

# --- Fingerprint Contents ---
# Upstream configure reads CC/CFLAGS/CPPFLAGS/LDFLAGS from the environment when
# they are exported, so they are part of its fingerprint alongside the options.
LIB_BUILD_CONFIG_LINES = \
	'CC=$(call sq,$(CC))' \
	'CFLAGS=$(call sq,$(CFLAGS))' \
	'CPPFLAGS=$(call sq,$(CPPFLAGS))' \
	'LDFLAGS=$(call sq,$(LDFLAGS))' \
	'CONFIG_OPTS=$(call sq,$(CONFIG_OPTS))' \
	'CROSSCOMPILE=$(call sq,$(CROSSCOMPILE))'

NIF_BUILD_CONFIG_LINES = \
	$(LIB_BUILD_CONFIG_LINES) \
	'LIBS=$(call sq,$(LIBS))' \
	'SECP256K1_NIF_WERROR=$(call sq,$(NIF_WERROR_FLAGS))' \
	'SECP256K1_NIF_SANITIZE=$(call sq,$(NIF_SANITIZE_FLAGS))'

# $(call write_if_changed,FILE,LINES)
# The temporary name is per-process because Mix may run make concurrently for
# different environments (e.g. `mix check` runs credo and ex_unit in parallel).
write_if_changed = tmp="$(1).tmp.$$$$"; \
	printf '%s\n' $(2) > "$$tmp" && \
	if cmp -s "$$tmp" "$(1)"; then rm -f "$$tmp"; else mv -f "$$tmp" "$(1)"; fi

# --- Source Files & Targets ---
NIF_SOURCES = $(wildcard $(SRC_DIR)/*.c)
NIF_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(SRC_DIR)/%.o,$(NIF_SOURCES))
NIF_TARGET = $(TARGET_DIR)/secp256k1_nif.so

# Every first-party header is a dependency of every first-party object.
NIF_HEADERS = $(wildcard $(SRC_DIR)/*.h)

# Version- and checksum-specific stamp indicating verified source extraction
EXTRACT_STAMP = $(LIB_SRC_DIR)/.extracted-$(LIB_VERSION)-$(LIB_SHA256)

# Remove a target whose recipe failed so a partial output is never reused.
.DELETE_ON_ERROR:

# --- Default Target ---
.PHONY: all
all: $(NIF_TARGET)

# --- Build Configuration Fingerprints ---
.PHONY: FORCE
FORCE:

$(NIF_BUILD_CONFIG): FORCE
	@$(call write_if_changed,$@,$(NIF_BUILD_CONFIG_LINES))

$(LIB_BUILD_CONFIG): FORCE
	@$(call write_if_changed,$@,$(LIB_BUILD_CONFIG_LINES))

# --- NIF Compilation and Link Rules ---
# $@ = target file ($(SRC_DIR)/%.o)
# $< = first prerequisite ($(SRC_DIR)/%.c)
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(NIF_HEADERS) $(EXTRACT_STAMP) $(NIF_BUILD_CONFIG)
	$(ECHO) "  CC       $@"
	@$(CC) $(CPPFLAGS) $(NIF_CFLAGS) -c -o $@ $<

$(NIF_TARGET): $(NIF_OBJECTS) $(LIB_STATIC_LIB) $(NIF_BUILD_CONFIG)
	@mkdir -p $(@D)
	$(ECHO) "  LD       $@"
	@$(CC) $(NIF_LDFLAGS) -shared -o $@ $(NIF_OBJECTS) $(LIB_STATIC_LIB) $(LDFLAGS) $(LIBS)
	@rm -f $(TARGET_DIR)/ecdsa.so $(TARGET_DIR)/schnorrsig.so $(TARGET_DIR)/ecdh.so $(TARGET_DIR)/extrakeys.so $(TARGET_DIR)/musig.so

# --- secp256k1 Library Compilation Chain ---

# The static library depends on the Makefile existing *and* being configured
$(LIB_STATIC_LIB): $(LIB_SRC_DIR)/Makefile
	$(ECHO) "  MAKE     libsecp256k1"
	@$(call logged,$(LIB_MAKE_LOG),$(MAKE) -C $(LIB_SRC_DIR) $(QUIET_MAKE))

# The Makefile is created by configure after verified source extraction and is
# regenerated (from a clean upstream tree) whenever the configure fingerprint
# changes.
$(LIB_SRC_DIR)/Makefile: $(EXTRACT_STAMP) $(LIB_BUILD_CONFIG)
	$(ECHO) "  CONFIG   libsecp256k1"
	@if [ -f "$@" ]; then $(MAKE) -C $(LIB_SRC_DIR) distclean $(QUIET_MAKE) $(QUIET_CMD) || rm -f "$@"; fi
	@$(call logged,$(LIB_CONFIGURE_LOG),cd $(LIB_SRC_DIR) && ./configure $(CONFIG_OPTS))

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

# clean: Remove built NIFs, build fingerprints, and the library build artifacts
clean:
	$(ECHO) "  CLEAN    build artifacts"
	@rm -f $(TARGET_DIR)/*.so
	@rm -f $(SRC_DIR)/*.o
	@rm -f $(NIF_BUILD_CONFIG) $(NIF_BUILD_CONFIG).tmp.* $(LIB_BUILD_CONFIG) $(LIB_BUILD_CONFIG).tmp.*
	@if [ -f "$(LIB_SRC_DIR)/Makefile" ]; then \
		$(MAKE) -C $(LIB_SRC_DIR) clean $(QUIET_MAKE) $(QUIET_CMD); \
	fi

# distclean: Remove everything clean does, plus the extracted library source
distclean: clean
	$(ECHO) "  CLEAN    extracted sources"
	@rm -rf $(LIB_SRC_DIR) $(LIB_SRC_DIR).tmp
