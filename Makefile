include ./vars.mk

subdirs = src test

include $(TOPDIR)/rules.mk

test: src

