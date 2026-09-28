# 크로스 컴파일: make CROSS_COMPILE=aarch64-openwrt-linux-musl-  (또는 OpenWrt SDK toolchain)
CC      := $(CROSS_COMPILE)gcc
CFLAGS  ?= -O2 -Wall -Wextra
BUILD   := build

all: $(BUILD)/xgw_agent $(BUILD)/xgw_seclog_test

$(BUILD)/xgw_agent: agent/xgw_agent.c | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD)/xgw_seclog_test: tools/xgw_seclog_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean
