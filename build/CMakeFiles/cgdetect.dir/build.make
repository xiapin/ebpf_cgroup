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
include CMakeFiles/cgdetect.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/cgdetect.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/cgdetect.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/cgdetect.dir/flags.make

cgdetect.skel.h: cgdetect.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: cgdetect"
	bash -c "/usr/sbin/bpftool gen skeleton /root/samples/build/cgdetect.bpf.o > /root/samples/build/cgdetect.skel.h"

cgdetect.bpf.o: ../cgdetect.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: cgdetect"
	/usr/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 "-idirafter /usr/local/include -idirafter /usr/lib64/clang/12.0.1/include -idirafter /usr/include" -I/root/samples -isystem /root/samples /root/kernel//include/uapi/ /root/kernel//include/ /usr/include/bpf/ -c /root/samples/cgdetect.bpf.c -o /root/samples/build/cgdetect.bpf.o

CMakeFiles/cgdetect.dir/cgdetect.c.o: CMakeFiles/cgdetect.dir/flags.make
CMakeFiles/cgdetect.dir/cgdetect.c.o: ../cgdetect.c
CMakeFiles/cgdetect.dir/cgdetect.c.o: CMakeFiles/cgdetect.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/cgdetect.dir/cgdetect.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/cgdetect.dir/cgdetect.c.o -MF CMakeFiles/cgdetect.dir/cgdetect.c.o.d -o CMakeFiles/cgdetect.dir/cgdetect.c.o -c /root/samples/cgdetect.c

CMakeFiles/cgdetect.dir/cgdetect.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/cgdetect.dir/cgdetect.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/samples/cgdetect.c > CMakeFiles/cgdetect.dir/cgdetect.c.i

CMakeFiles/cgdetect.dir/cgdetect.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/cgdetect.dir/cgdetect.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/samples/cgdetect.c -o CMakeFiles/cgdetect.dir/cgdetect.c.s

CMakeFiles/cgdetect.dir/bpf_utils.c.o: CMakeFiles/cgdetect.dir/flags.make
CMakeFiles/cgdetect.dir/bpf_utils.c.o: ../bpf_utils.c
CMakeFiles/cgdetect.dir/bpf_utils.c.o: CMakeFiles/cgdetect.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/cgdetect.dir/bpf_utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/cgdetect.dir/bpf_utils.c.o -MF CMakeFiles/cgdetect.dir/bpf_utils.c.o.d -o CMakeFiles/cgdetect.dir/bpf_utils.c.o -c /root/samples/bpf_utils.c

CMakeFiles/cgdetect.dir/bpf_utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/cgdetect.dir/bpf_utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /root/samples/bpf_utils.c > CMakeFiles/cgdetect.dir/bpf_utils.c.i

CMakeFiles/cgdetect.dir/bpf_utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/cgdetect.dir/bpf_utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /root/samples/bpf_utils.c -o CMakeFiles/cgdetect.dir/bpf_utils.c.s

# Object files for target cgdetect
cgdetect_OBJECTS = \
"CMakeFiles/cgdetect.dir/cgdetect.c.o" \
"CMakeFiles/cgdetect.dir/bpf_utils.c.o"

# External object files for target cgdetect
cgdetect_EXTERNAL_OBJECTS =

cgdetect: CMakeFiles/cgdetect.dir/cgdetect.c.o
cgdetect: CMakeFiles/cgdetect.dir/bpf_utils.c.o
cgdetect: CMakeFiles/cgdetect.dir/build.make
cgdetect: /usr/lib64/libbpf.so
cgdetect: CMakeFiles/cgdetect.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/samples/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable cgdetect"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/cgdetect.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/cgdetect.dir/build: cgdetect
.PHONY : CMakeFiles/cgdetect.dir/build

CMakeFiles/cgdetect.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/cgdetect.dir/cmake_clean.cmake
.PHONY : CMakeFiles/cgdetect.dir/clean

CMakeFiles/cgdetect.dir/depend: cgdetect.bpf.o
CMakeFiles/cgdetect.dir/depend: cgdetect.skel.h
	cd /root/samples/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/samples /root/samples /root/samples/build /root/samples/build /root/samples/build/CMakeFiles/cgdetect.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/cgdetect.dir/depend

