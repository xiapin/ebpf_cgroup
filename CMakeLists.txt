# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)
project(examples)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

#EXECUTE_PROCESS(COMMAND uname -r
#	OUTPUT_VARIABLE KERN
#	OUTPUT_STRIP_TRAILING_WHITESPACE
#)
set(KERN "5.10.0-60.57.0.85.oe2203.x86_64")
MESSAGE(STATUS "kernel version: ${KERN}")

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
set(BPFOBJECT_BPFTOOL_EXE /usr/sbin/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}
	/usr/src/kernels/${KERN}/include/uapi/
	/usr/src/kernels/${KERN}/include/
        /usr/include/bpf/)
set(LIBBPF_LIBRARIES /usr/lib64/libbpf.so)
find_package(BpfObject REQUIRED)

# Create an executable for each application
file(GLOB apps *.bpf.c)
foreach(app ${apps})
  get_filename_component(app_stem ${app} NAME_WE)

  # Build object skeleton and depend skeleton on libbpf build
  bpf_object(${app_stem} ${app_stem}.bpf.c)
  add_dependencies(${app_stem}_skel libbpf-build)

  add_executable(${app_stem} ${app_stem}.c bpf_utils.c)
  target_link_libraries(${app_stem} ${app_stem}_skel)
endforeach()
