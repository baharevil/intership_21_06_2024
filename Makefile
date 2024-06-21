# Static variables
src_dir = src
inc_dir = include
test_dir = tests
build_dir = build

# Flags
DEBUG =
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
.PHONY: all clean rebuild

all: $(target) generator

$(build_dir)/$(src_dir)/%.o: $(src_dir)/%.c
	@mkdir -p $(build_dir)/$(src_dir)
	$(CC) $(CFLAGS) -c $< -o $@

$(build_dir)/$(test_dir)/%.o: $(test_dir)/%.c
	@mkdir -p $(build_dir)/$(test_dir)
	$(CC) $(CFLAGS) -c $< -o $@

$(target): $(objects)
	$(CC) $(LDFLAGS) $^ -o $(target)

debug: DEBUG = -g
debug: rebuild

rebuild: clean all

generator: gen/generator.c
	$(CC) $(CFLAGS) $< -o $@

valgrind: firewall
	valgrind --tool=memcheck --leak-check=yes ./firewall --file rules2.fw < dump2.txt

clean:
	@echo "Making clean"
	@rm -rf build/*
	@rm -rf $(target)
	@rm -rf generator