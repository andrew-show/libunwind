ifeq ($(BUILD_TARGET),)

###############################################################################
# define rules for multiple targets
###############################################################################

ifeq ($(BUILD_TARGET_LIST),)
$(error "Please define BUILD_TARGET_LIST variable")
endif

.PHONY: $(MAKECMDGOALS)
$(MAKECMDGOALS): $(BUILD_TARGET_LIST)

.PHONY: $(BUILD_TARGET_LIST)
$(BUILD_TARGET_LIST):
	@echo =================================================
	@echo Build $@: $(MAKECMDGOALS)
	@echo =================================================
	@$(MAKE) BUILD_TARGET=$@ $(MAKECMDGOALS)

else

###############################################################################
# define rules for single target
###############################################################################

# The following variables should be defined before include this file
# TOPDIR: The top most directory of the source tree 
# CC: C compiler
# CXX: C++ compiler
# BUILD_TARGET: The target to build

BUILDDIR := $(TOPDIR)/build/$(BUILD_TARGET)
DESTDIR ?= /usr

# Disable debug and enable optimize by default
DEBUG ?= no
OPTIMIZE ?=yes

# get target file list from source list
# $1: the target program/library
# $2: list of source pattern
# $3: target pattern. 
SRCS_2x = $(addprefix $(BUILDDIR)/.$(1)/,$(foreach i,$(2),$(patsubst $(i),$(3),$(filter $(i),$(SRCS) $($(1)_SRCS)))))

# get object file list from source list
# $1: the target program/library
SRCS_o = $(call SRCS_2x,$(1),%.S %.c %.cc %.cpp %.cxx,%.o)

# get depenency file list from source list
# $1: the target program/library
SRCS_d = $(call SRCS_2x,$(1),%.S %.c %.cc %.cpp %.cxx,%.d)

# get dependency archive file list from source list
SRCS_a = $(addprefix $(BUILDDIR)/lib/,$(filter %.a,$(SRCS) $($(1)_SRCS)))

# get dependency shared library list from source list
SRCS_so = $(addprefix $(BUILDDIR)/lib/,$(filter %.so,$(SRCS) $($(1)_SRCS)))

# get cxx files from source list
SRCS_cxx = $(filter %.cc %.cpp %.cxx,$(SRCS) $($(1)_SRCS))

# raise exception
# $1: the result to be check
# $2: raise an exception if this parameter is not empty
RAISE_exception = $(if $(strip $(1)),\
    $(1),\
    $(if $(strip $(2)),$(error $(2))))

# get package version
# $1: pkg-config parameters
pkgconfig = $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --define-variable=topdir=$(TOPDIR) $(1))

# pkg-config
# $1: pkg-config options
# $2: pkg-config packages
# $3: error message, if empty, the error will be ignored
CMD_pkgconfig = $(call RAISE_exception,\
    $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --define-variable=topdir=$(TOPDIR) $(1) $(2) && \
        echo $(2) | tr 'a-z+-.' 'A-Zx__' | awk '{ for (i=1;i<=NF;i++) printf("-DHAVE_%s ", $$i); }'),\
        $(if $(3), $(3): $(strip PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --define-variable=topdir=$(TOPDIR) $(1) $(2))))

# compile command for C source file, if the destination file is %.o, the comand
# will compile the source to target, otherwise it will generate dependency file.
# $1: the target program/library
# $2: source file
# $3: destination file
CMD_cc = $(CC) \
    $(if $(filter 1 y yes on,$(DEBUG)),-g,-DNDEBUG) \
    $(if $(filter 1 y yes on,$(OPTIMIZE)),-O3) \
    $($(2)_CPPFLAGS) $($(1)_CPPFLAGS) $(CPPFLAGS) \
    $($(2)_CFLAGS) $($(1)_PKGS_CFLAGS) $($(1)_CFLAGS) $(CFLAGS) \
    $(if $(filter %.o,$(3)),\
        -o $(3) -c $(2),\
        -MM $(2) > $(3))

# compile command for CPP source file, if the destination file is %.o, the comand
# will compile the source to target, otherwise it will generate dependency file.
# $1: the target program/library
# $2: source file
# $3: destination file
CMD_cxx = $(CXX) \
    $(if $(filter 1 y yes on,$(DEBUG)),-g,-DNDEBUG) \
    $(if $(filter 1 y yes on,$(OPTIMIZE)),-O3) \
    $($(2)_CPPFLAGS) $($(1)_CPPFLAGS) $(CPPFLAGS) \
    $($(2)_CXXFLAGS) $($(1)_PKGS_CFLAGS) $($(1)_CXXFLAGS) $(CXXFLAGS) \
    $(if $(filter %.o,$(3)),\
        -o $(3) -c $(2),\
        -MM $(2) > $(3))

# compile command for assembler source file
# $1: the target program/library
# $2: source file
# $3: destination file
CMD_as = $(CC) \
    $(if $(filter 1 y yes on,$(DEBUG)),-g,-DNDEBUG) \
    $($(2)_CPPFLAGS) $($(1)_CPPFLAGS) $(CPPFLAGS) \
    $($(2)_ASFLAGS) $($(1)_ASFLAGS) $(ASFLAGS) \
    $(if $(filter %.o,$(3)),\
        -o $(3) -c $(2),\
        -MM $(2) > $(3))

# link command
# $1: the target binary or shared library
# $2: extra link options
CMD_ld = $(CC) \
    $(if $(filter 1 y yes on,$(DEBUG)), -g) \
    $(2) \
    -L$(BUILDDIR)/lib \
    -o $@ $(call SRCS_o,$(1)) \
    -Wl,--start-group $(call SRCS_a,$(1)) -Wl,--end-group \
    $(call SRCS_so,$(1)) \
    $($(1)_PKGS_LIBS) \
    $($(1)_LDFLAGS) $(LDFLAGS) \
    $($(1)_LIBS) $(LIBS)

# $1: the target static library
CMD_ar = ar rcs $@ $(call SRCS_o,$(1))

comma=,

# pkg-config get cflags
# use pkg-config to get CFLAGS and replace -I options with -isystem options
# to avoid compile warning generated by headers of third party packages
# $1: static packages
# $2: shared packages
# $3: optional packages
PKGCONF_cflags = $(patsubst -I%,-isystem %,\
    $(if $(strip $(1) $(2)),\
        $(call CMD_pkgconfig,--cflags,$(1) $(2),pkg-config error)) \
    $(foreach i,$(3),$(if $(strip $(i)), $(call CMD_pkgconfig,--cflags,$(i)))))

# parse library link option
# $1: link option
# $2: path list to search libraries
# $3: library name extension
PARSE_pkgconf_lib_option = $(if $(filter -l:%,$(1)),\
    $(1),\
    $(if $(filter -l%,$(1)),\
        $(if $(wildcard $(foreach i,$(2),$(i)/$(patsubst -l%,lib%$(3),$(1)))),\
            $(patsubst -l%,-l:lib%$(3),$(1)),\
            $(1)),\
        $(1)))

# parse library link options.
# this function will try to find the preferred library in search directories
# witch is specified in -L options, if the preferred library exists in one of
# the search directories, the -lxxx option will be replaced with -l:libxxx.a
# or -l:llibxxx.so option.
# $1: link options
# $2: library name extension, .a or .so
PARSE_pkgconf_lib_options = $(foreach \
    i,\
    $(1), \
    $(call PARSE_pkgconf_lib_option,\
        $(i),\
        $(patsubst -L%,%,$(filter -L%, $(1))),$(2)))

# $1: link options of static packages
# $2: link options of shared packages
# $3: link options of optional packages
# $4: libs options of manually specified link options
PARSE_pkgconf_libs = \
	$(call PARSE_pkgconf_lib_options, $(filter-out $(4) -D%, $(1)),.a) \
	$(call PARSE_pkgconf_lib_options, $(filter-out $(4) -D%, $(2)),.so) \
	$(call PARSE_pkgconf_lib_options, $(filter-out $(4) -D%, $(3)),.so)

# parse link options for packages.
# this function use pkg-config get the link options for all packages, if
# a library also exist in manually specified link options, the link option
# specified manually will overwrite the link options provided by pkg-config.
# $1: static packages
# $2: shared packages
# $3: optional packages
# $4: other manually specified link options
PKGCONF_libs = $(call PARSE_pkgconf_libs,\
    $(patsubst -Wl$(comma)-l%,-l%,$(if $(strip $(1)), $(call CMD_pkgconfig,--static --libs,$(1),pkg-config error))),\
	$(patsubst -Wl$(comma)-l%,-l%,$(if $(strip $(2)), $(call CMD_pkgconfig,--libs,$(2),pkg-config error))), \
    $(patsubst -Wl$(comma)-l%,-l%,$(foreach i,$(3),$(if $(strip $(i)),$(call CMD_pkgconfig,--libs,$(i))))), \
    $(patsubst -Wl$(comma)-l%,-l%,$(filter -l% -Wl$(comma)-l%, $(4))))

#=============================================================================
# template to define %.S to %.o rules
# $1: The program/library name that depends on the %.S
define S2O_rules

$$(call SRCS_2x,$(1),%.S,%.d) : $$(BUILDDIR)/.$(1)/%.d: %.S
	@set -e; mkdir -p $$(@D); rm -f $$@; \
	$$(call CMD_as,$(1),$$<,$$@); \
	sed -i 's%\($$*\)\.o[ :]*%$$(BUILDDIR)/.$(1)/\1.o $$@: %g' $$@

$$(call SRCS_2x,$(1),%.S,%.o): $$(BUILDDIR)/.$(1)/%.o: %.S
	@set -e; mkdir -p $$(@D); \
	echo $$(if $$(filter 1 y yes on, $$(VERBOSE)),$$(strip $$(call CMD_as,$(1),$$<,$$@)),'AS $$(notdir $$@)'); \
	$$(call CMD_as,$(1),$$<,$$@); \
	echo cmd_$$@ = $$(call CMD_as,$(1),$$(abspath $$<),$$@) > $$(BUILDDIR)/.$(1)/$$(@F).cmd

endef

#=============================================================================
# template to define %.c to %.o rules
# $1: The program/library name that depends on the %.c
define C2O_rules

# Make dependency
$$(call SRCS_2x,$(1),%.c,%.d) : $$(BUILDDIR)/.$(1)/%.d: %.c
	@set -e; mkdir -p $$(@D); rm -f $$@; \
	$$(call CMD_cc,$(1),$$<,$$@); \
	sed -i 's%\($$*\)\.o[ :]*%$$(BUILDDIR)/.$(1)/\1.o $$@: %g' $$@

# Make object files
$$(call SRCS_2x,$(1),%.c,%.o): $$(BUILDDIR)/.$(1)/%.o: %.c
	@set -e; mkdir -p $$(@D); \
	echo $$(if $$(filter 1 y yes on, $$(VERBOSE)),$$(strip $$(call CMD_cc,$(1),$$<,$$@)),'CC $$(notdir $$@)'); \
	$$(call CMD_cc,$(1),$$<,$$@); \
	echo cmd_$$@ = $$(call CMD_cc,$(1),$$(abspath $$<),$$@) > $$(BUILDDIR)/.$(1)/$$(@F).cmd

endef

#=============================================================================
# template to define %.cc %.cpp to %.o rules
# $1: The program/library name that depends on the %.cc %.cpp
# $2: The file extension
define CXX2O_rules

# Make dependency
$$(call SRCS_2x,$(1),$(2),%.d): $$(BUILDDIR)/.$(1)/%.d: $(2)
	@set -e; mkdir -p $$(@D); rm -f $$@; \
	$$(call CMD_cxx,$(1),$$<,$$@); \
	sed -i 's%\($$*\)\.o[ :]*%$$(BUILDDIR)/.$(1)/\1.o $$@: %g' $$@

$$(call SRCS_2x,$(1),$(2),%.o): $$(BUILDDIR)/.$(1)/%.o: $(2)
	@set -e; mkdir -p $$(@D); \
	echo $$(if $$(filter 1 y yes on, $$(VERBOSE)),$$(strip $$(call CMD_cxx,$(1),$$<,$$@)),'CXX $$(notdir $$@)'); \
	$$(call CMD_cxx,$(1),$$<,$$@); \
	echo cmd_$$@ = $$(call CMD_cxx,$(1),$$(abspath $$<),$$@) > $$(BUILDDIR)/.$(1)/$$(@F).cmd

endef

#=============================================================================
# template to define pkg-config variables
# $1: The target  name
# $2: The target type: program | library | archive
define PKG_CONFIG_rules

$(1)_PKGS_CFLAGS := $$(call PKGCONF_cflags,\
    $$($(1)_STATIC_PKGS) $$(STATIC_PKGS), \
    $$($(1)_PKGS) $$(PKGS), \
    $$($(1)_OPTIONAL_PKGS) $$(OPTIONAL_PKGS))

ifneq ($(suffix $(2)),.a)
$(1)_PKGS_LIBS := $$(call PKGCONF_libs,\
    $$($(1)_STATIC_PKGS) $$(STATIC_PKGS),\
    $$($(1)_PKGS) $$(PKGS),\
	$$($(1)_OPTIONAL_PKGS) $$(OPTIONAL_PKGS),\
    $$($(1)_LDFLAGS) $$(LDFLAGS) $$($(1)_LIBS) $$(LIBS))
endif

endef

#=============================================================================
# template to define binary rules
# $1: The program name
define PROGRAM_rules

$$(eval $$(call PKG_CONFIG_rules,$(1)))
$$(eval $$(call S2O_rules,$(1)))
$$(eval $$(call C2O_rules,$(1)))
$$(eval $$(call CXX2O_rules,$(1),%.cc))
$$(eval $$(call CXX2O_rules,$(1),%.cpp))
$$(eval $$(call CXX2O_rules,$(1),%.cxx))

$$(BUILDDIR)/bin/$(1): $$(call SRCS_o,$(1)) $$(call SRCS_a,$(1)) $$(call SRCS_so,$(1))
	@set -e; mkdir -p $$(@D); \
	echo $$(if $$(filter 1 y yes on, $$(VERBOSE)),$$(strip $$(call CMD_ld,$(1))),'LD $$(notdir $$@)'); \
	$$(call CMD_ld,$(1))

endef

#=============================================================================
# template to define shared library rules
# $1: The library name

define SHAREDLIB_rules

$$(eval $$(call PKG_CONFIG_rules,$(1)))
$$(eval $$(call S2O_rules,$(1)))
$$(eval $$(call C2O_rules,$(1)))
$$(eval $$(call CXX2O_rules,$(1),%.cc))
$$(eval $$(call CXX2O_rules,$(1),%.cpp))

$$(BUILDDIR)/lib/$(1): $$(call SRCS_o,$(1)) $$(call SRCS_a,$(1)) $$(call SRCS_so,$(1))
	@set -e; mkdir -p $$(@D); \
	echo $$(if $$(filter 1 y yes on, $$(VERBOSE)),$$(strip $$(call CMD_ld, $(1),-shared)), 'LD $$(notdir $$@)'); \
	$$(call CMD_ld,$(1),-shared)

endef

#=============================================================================
# template to define statistics library rules
# $1: The library name

define ARCHIVE_rules

$$(eval $$(call PKG_CONFIG_rules,$(1)))
$$(eval $$(call S2O_rules,$(1)))
$$(eval $$(call C2O_rules,$(1)))
$$(eval $$(call CXX2O_rules,$(1),%.cc))
$$(eval $$(call CXX2O_rules,$(1),%.cpp))

$$(BUILDDIR)/lib/$(1): $$(call SRCS_o,$(1))
	@set -e; mkdir -p $$(@D); \
	echo $$(if $$(filter 1 y yes on, $$(VERBOSE)),$$(strip $$(call CMD_ar,$(1))),'AR $$(notdir $$@)'); \
	$$(call CMD_ar,$(1))

endef

#=============================================================================
# define all build targets

.PHONY: all
all: build

SUBDIRS = $(subdirs)
BUILD_ALL = $(foreach i,$(bin) $(dist_bin),$(call SRCS_d,$(i))) \
            $(foreach i,$(lib) $(dist_lib),$(call SRCS_d,$(i))) \
            $(foreach i,$(bin) $(dist_bin),$(call SRCS_o,$(i))) \
            $(foreach i,$(lib) $(dist_lib),$(call SRCS_o,$(i))) \
            $(addprefix $(BUILDDIR)/bin/,$(bin) $(dist_bin)) \
            $(addprefix $(BUILDDIR)/lib/,$(filter %.a %.so,$(lib) $(dist_lib)))

.PHONY: pre-build
$(SUBDIRS) $(BUILD_ALL): | pre-build

.PHONY: build
build: $(SUBDIRS) $(BUILD_ALL)
	@$(MAKE) BUILD_TARGET=$(BUILD_TARGET) post-build

.PHONY: post-build

.PHONY: FORCE

#=============================================================================
# template to define statistics library rules
# $1: The source file name
# $2: The destination file name
define DIST_rules
$(2): $(1) FORCE
	@set -e; mkdir -p $$(@D); \
	echo distributing $(2); \
	cp -d $(1) $(2)
endef

#=============================================================================
# define all installation targets

dist_dirs += bin lib include share

DIST_ALL = $(addprefix $(DESTDIR)/bin/,$(dist_bin)) \
           $(addprefix $(DESTDIR)/lib/,$(dist_lib)) \
           $(foreach i,$(dist_dirs), $(addprefix $(DESTDIR)/$(i)/, $($(i)_SRCS)))

.PHONY: pre-install
$(DIST_ALL): |pre-install

.PHONY: install
install: $(SUBDIRS) $(DIST_ALL)
	@$(MAKE) BUILD_TARGET=$(BUILD_TARGET) post-install

.PHONY: post-install

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	@$(MAKE) -C $@ BUILD_TARGET=$(BUILD_TARGET) $(MAKECMDGOALS)

.PHONY: clean
clean: $(SUBDIRS)

ifneq ($(strip $(BUILD_ALL)),)
clean:
	@set -e; echo rm $(patsubst $(TOPDIR)/%,%,$(BUILD_ALL)); \
	rm -f $(BUILD_ALL)
endif

ifneq ($(MAKECMDGOALS),clean)

$(foreach i,$(bin) $(dist_bin),$(eval $(call PROGRAM_rules,$(i))))
$(foreach i,$(filter %.so,$(lib) $(dist_lib)),$(eval $(call SHAREDLIB_rules,$(i))))
$(foreach i,$(filter %.a,$(lib) $(dist_lib)),$(eval $(call ARCHIVE_rules,$(i))))

$(foreach i,$(dist_lib),$(eval $(call DIST_rules,$(BUILDDIR)/lib/$(i),$(DESTDIR)/lib/$(i))))
$(foreach i,$(dist_bin),$(eval $(call DIST_rules,$(BUILDDIR)/bin/$(i),$(DESTDIR)/bin/$(i))))
$(foreach dir,$(dist_dirs),$(foreach file,$($(dir)_SRCS),$(eval $(call DIST_rules,$(file),$(DESTDIR)/$(dir)/$(file)))))

sinclude $(foreach i,$(bin) $(dist_bin) $(lib) $(dist_lib),$(call SRCS_d,$(i)))

endif

endif

.PHONY: help
help:
	@echo "Usage: make [Options]"
	@echo "Options:"
	@echo "  DEBUG=yes|no            Enable/disable debug"
	@echo "  OPTIMIZE=yes|no         Enable/disable optimize"
	@echo "  VERBOSE=yes|no          Enable/disable verbose mode"
