# Static variables
src_dir = src
inc_dir = include
test_dir = tests
build_dir = build

# Flags
DEBUG = -g
CC = gcc
CFLAGS = -Wall -Werror -Wextra --std=c11 -I$(inc_dir) $(DEBUG)
LDFLAGS =

# Dinamic variables
target = firewall
sources = $(wildcard $(src_dir)/*.c)
objects = $(addprefix $(build_dir)/, $(patsubst %.c, %.o, $(sources)))
test_sources = $(wildcard $(test_dir)/*.c)
test_objects = $(patsubst %.c, %.o, $(test_sources))

# Targets
.PHONY: all clean

all: $(target)

$(build_dir)/$(src_dir)/%.o: $(src_dir)/%.c
	@mkdir -p $(build_dir)/$(src_dir)
	$(CC) $(CFLAGS) -c $< -o $@

$(build_dir)/$(test_dir)/%.o: $(test_dir)/%.c
	@mkdir -p $(build_dir)/$(test_dir)
	$(CC) $(CFLAGS) -c $< -o $@

$(target): $(objects)
	$(CC) $(LDFLAGS) $^ -o $(target)

clean:
	@rm -rf build/*
	@rm -rf $(target)