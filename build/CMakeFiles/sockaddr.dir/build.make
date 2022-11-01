# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/samples

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/samples/build

# Include any dependencies generated for this target.
include CMakeFiles/sockaddr.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/sockaddr.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/sockaddr.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sockaddr.dir/flags.make

sockaddr.skel.h: sockaddr.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: sockaddr"
	bash -c "/usr/sbin/bpftool gen skeleton /root/samples/build/sockaddr.bpf.o > /root/samples/build/sockaddr.skel.h"

sockaddr.bpf.o: ../sockaddr.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: sockaddr"
	/usr/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 "-idirafter /usr/local/include -idirafter /usr/lib64/clang/12.0.1/include -idirafter /usr/include" -I/root/samples -isystem /root/samples /root/kernel//include/uapi/ /root/kernel//include/ /usr/include/bpf/ -c /root/samples/sockaddr.bpf.c -o /root/samples/build/sockaddr.bpf.o

CMakeFiles/sockaddr.dir/sockaddr.c.o: CMakeFiles/sockaddr.dir/flags.make
CMakeFiles/sockaddr.dir/sockaddr.c.o: ../sockaddr.c
CMakeFiles/sockaddr.dir/sockaddr.c.o: CMakeFiles/sockaddr.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/sockaddr.dir/sockaddr.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/sockaddr.dir/sockaddr.c.o -MF CMakeFiles/sockaddr.dir/sockaddr.c.o.d -o CMakeFiles/sockaddr.dir/sockaddr.c.o -c /root/samples/sockaddr.c

CMakeFiles/sockaddr.dir/sockaddr.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sockaddr.dir/sockaddr.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/samples/sockaddr.c > CMakeFiles/sockaddr.dir/sockaddr.c.i

CMakeFiles/sockaddr.dir/sockaddr.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sockaddr.dir/sockaddr.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/samples/sockaddr.c -o CMakeFiles/sockaddr.dir/sockaddr.c.s

CMakeFiles/sockaddr.dir/bpf_utils.c.o: CMakeFiles/sockaddr.dir/flags.make
CMakeFiles/sockaddr.dir/bpf_utils.c.o: ../bpf_utils.c
CMakeFiles/sockaddr.dir/bpf_utils.c.o: CMakeFiles/sockaddr.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/sockaddr.dir/bpf_utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/sockaddr.dir/bpf_utils.c.o -MF CMakeFiles/sockaddr.dir/bpf_utils.c.o.d -o CMakeFiles/sockaddr.dir/bpf_utils.c.o -c /root/samples/bpf_utils.c

CMakeFiles/sockaddr.dir/bpf_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sockaddr.dir/bpf_utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/samples/bpf_utils.c > CMakeFiles/sockaddr.dir/bpf_utils.c.i

CMakeFiles/sockaddr.dir/bpf_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sockaddr.dir/bpf_utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/samples/bpf_utils.c -o CMakeFiles/sockaddr.dir/bpf_utils.c.s

# Object files for target sockaddr
sockaddr_OBJECTS = \
"CMakeFiles/sockaddr.dir/sockaddr.c.o" \
"CMakeFiles/sockaddr.dir/bpf_utils.c.o"

# External object files for target sockaddr
sockaddr_EXTERNAL_OBJECTS =

sockaddr: CMakeFiles/sockaddr.dir/sockaddr.c.o
sockaddr: CMakeFiles/sockaddr.dir/bpf_utils.c.o
sockaddr: CMakeFiles/sockaddr.dir/build.make
sockaddr: /usr/lib64/libbpf.so
sockaddr: CMakeFiles/sockaddr.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable sockaddr"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sockaddr.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sockaddr.dir/build: sockaddr
.PHONY : CMakeFiles/sockaddr.dir/build

CMakeFiles/sockaddr.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sockaddr.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sockaddr.dir/clean

CMakeFiles/sockaddr.dir/depend: sockaddr.bpf.o
CMakeFiles/sockaddr.dir/depend: sockaddr.skel.h
	cd /root/samples/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/samples /root/samples /root/samples/build /root/samples/build /root/samples/build/CMakeFiles/sockaddr.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sockaddr.dir/depend

