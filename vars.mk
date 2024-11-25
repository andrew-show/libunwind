TOPDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifeq ($(BUILD_TARGET),)

BUILD_TARGET_LIST=$(shell cc -dumpmachine)

else

AS=cc
CC=cc
CXX=c++
LD=cc

CPPFLAGS = -I$(TOPDIR)/include
CFLAGS = -std=c99 -fno-stack-protector
CXXFLAGS = -std=c++11 -fno-exceptions -fno-rtti -fno-stack-protector

ifeq ($(D),)
CFLAGS += -O3
CXXFLAGS += -O3
else
CFLAGS += -g
CXXFLAGS += -g
ASFLAGS += -g
endif

endif
