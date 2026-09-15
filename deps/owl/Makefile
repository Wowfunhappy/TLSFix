# Hand-written build for owl on Mac OS X 10.9.
#
# Upstream builds with CMake 3.5+, which is not available here and would be a
# sizeable detour to bootstrap. The source list is small and static, so it is
# transcribed directly from the CMakeLists.txt files instead.

CC      := clang
CXX     := clang++
CFLAGS  := -Wall -Wextra -O2 -g -MMD -MP
LDFLAGS :=

TOPDIR  := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD   := $(TOPDIR)build

# libev is installed under /usr/local; libpcap comes from the system.
INCLUDES := -I$(TOPDIR)src -I$(TOPDIR)radiotap -I$(TOPDIR)daemon -I/usr/local/include
LIBS     := -lpcap /usr/local/lib/libev.a \
            -framework Foundation -framework CoreWLAN -framework SystemConfiguration

RADIOTAP_SRC := radiotap/radiotap.c
RADIOTAP_DEFS := -D_BSD_SOURCE -D_DEFAULT_SOURCE -DRADIOTAP_SUPPORT_OVERRIDES

AWDL_SRC := \
	src/log.c src/state.c src/election.c src/sync.c src/channel.c \
	src/schedule.c src/tx.c src/rx.c src/frame.c src/crc32.c src/wire.c \
	src/peers.c src/version.c src/hashmap.c src/siphash24.c \
	src/circular_buffer.c

DAEMON_SRC := daemon/io.c daemon/core.c daemon/netutils.c daemon/owl.c
DAEMON_OBJC := daemon/corewlan.m

SRC  := $(RADIOTAP_SRC) $(AWDL_SRC) $(DAEMON_SRC)
OBJS := $(addprefix $(BUILD)/,$(SRC:.c=.o)) $(addprefix $(BUILD)/,$(DAEMON_OBJC:.m=.o))

TARGET := $(BUILD)/owl

.PHONY: all clean install test

all: $(TARGET)

TEST_SRC := $(wildcard tests/test_*.cpp)
TEST_OBJS := $(addprefix $(BUILD)/,$(TEST_SRC:.cpp=.o))
-include $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)
GTEST := $(TOPDIR)googletest/googletest
TEST_INCLUDES := $(INCLUDES) -I$(GTEST)/include -I$(GTEST)

test: $(BUILD)/tests/owl_tests
	$(BUILD)/tests/owl_tests

$(BUILD)/tests/owl_tests: $(TEST_OBJS) $(BUILD)/tests/gtest-all.o $(BUILD)/tests/gtest_main.o $(addprefix $(BUILD)/,$(AWDL_SRC:.c=.o)) $(BUILD)/radiotap/radiotap.o
	$(CXX) -o $@ $^ -lpthread

$(BUILD)/tests/%.o: $(TOPDIR)tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CFLAGS) -std=c++11 $(TEST_INCLUDES) -c -o $@ $<

$(BUILD)/tests/gtest%.o: $(GTEST)/src/gtest%.cc
	@mkdir -p $(dir $@)
	$(CXX) $(CFLAGS) -std=c++11 $(TEST_INCLUDES) -c -o $@ $<

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)
	@echo "built $@"

# radiotap needs its own defines, so it gets a rule ahead of the generic one.
$(BUILD)/radiotap/%.o: $(TOPDIR)radiotap/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(RADIOTAP_DEFS) $(INCLUDES) -c -o $@ $<

$(BUILD)/%.o: $(TOPDIR)%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(BUILD)/%.o: $(TOPDIR)%.m
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/owl

clean:
	rm -rf $(BUILD)
