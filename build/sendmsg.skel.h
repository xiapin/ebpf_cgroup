/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __SENDMSG_BPF_SKEL_H__
#define __SENDMSG_BPF_SKEL_H__

#include <stdlib.h>
#include <bpf/libbpf.h>

struct sendmsg_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_program *sendmsg_v4_prog;
		struct bpf_program *connect4;
	} progs;
	struct {
		struct bpf_link *sendmsg_v4_prog;
		struct bpf_link *connect4;
	} links;
};

static void
sendmsg_bpf__destroy(struct sendmsg_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
sendmsg_bpf__create_skeleton(struct sendmsg_bpf *obj);

static inline struct sendmsg_bpf *
sendmsg_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct sendmsg_bpf *obj;

	obj = (struct sendmsg_bpf *)calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;
	if (sendmsg_bpf__create_skeleton(obj))
		goto err;
	if (bpf_object__open_skeleton(obj->skeleton, opts))
		goto err;

	return obj;
err:
	sendmsg_bpf__destroy(obj);
	return NULL;
}

static inline struct sendmsg_bpf *
sendmsg_bpf__open(void)
{
	return sendmsg_bpf__open_opts(NULL);
}

static inline int
sendmsg_bpf__load(struct sendmsg_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct sendmsg_bpf *
sendmsg_bpf__open_and_load(void)
{
	struct sendmsg_bpf *obj;

	obj = sendmsg_bpf__open();
	if (!obj)
		return NULL;
	if (sendmsg_bpf__load(obj)) {
		sendmsg_bpf__destroy(obj);
		return NULL;
	}
	return obj;
}

static inline int
sendmsg_bpf__attach(struct sendmsg_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
sendmsg_bpf__detach(struct sendmsg_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline int
sendmsg_bpf__create_skeleton(struct sendmsg_bpf *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		return -1;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "sendmsg_bpf";
	s->obj = &obj->obj;

	/* programs */
	s->prog_cnt = 2;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "sendmsg_v4_prog";
	s->progs[0].prog = &obj->progs.sendmsg_v4_prog;
	s->progs[0].link = &obj->links.sendmsg_v4_prog;

	s->progs[1].name = "connect4";
	s->progs[1].prog = &obj->progs.connect4;
	s->progs[1].link = &obj->links.connect4;

	s->data_sz = 7264;
	s->data = (void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xe0\x15\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1a\0\
\x01\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\xb7\0\0\0\x01\0\0\0\x61\x12\x04\0\0\
\0\0\0\x55\x02\x14\0\xdf\x05\x05\x05\x18\x02\0\0\x6f\x72\x74\x3a\0\0\0\0\x25\
\x64\x0a\0\x7b\x2a\xf8\xff\0\0\0\0\x18\x02\0\0\x70\x3a\x30\x78\0\0\0\0\x25\x78\
\x20\x70\x7b\x2a\xf0\xff\0\0\0\0\x18\x02\0\0\x65\x6e\x69\x65\0\0\0\0\x64\x3a\
\x20\x69\x7b\x2a\xe8\xff\0\0\0\0\x18\x02\0\0\x61\x63\x63\x65\0\0\0\0\x73\x73\
\x20\x64\x7b\x2a\xe0\xff\0\0\0\0\x61\x14\x18\0\0\0\0\0\x61\x13\x04\0\0\0\0\0\
\xdc\x03\0\0\x20\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xe0\xff\xff\xff\xb7\x02\
\0\0\x20\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x44\x75\
\x61\x6c\x20\x42\x53\x44\x2f\x47\x50\x4c\0\0\0\0\x01\0\0\0\x61\x63\x63\x65\x73\
\x73\x20\x64\x65\x6e\x69\x65\x64\x3a\x20\x69\x70\x3a\x30\x78\x25\x78\x20\x70\
\x6f\x72\x74\x3a\x25\x64\x0a\0\xff\xff\xff\xff\xff\xff\xff\xff\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x98\0\0\0\0\0\0\0\x01\0\x51\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\x11\x01\x25\x0e\x13\x05\x03\x0e\x10\x17\x1b\x0e\x11\x01\x55\x17\0\0\x02\
\x34\0\x03\x0e\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x03\x01\x01\x49\x13\
\0\0\x04\x21\0\x49\x13\x37\x0b\0\0\x05\x24\0\x03\x0e\x3e\x0b\x0b\x0b\0\0\x06\
\x24\0\x03\x0e\x0b\x0b\x3e\x0b\0\0\x07\x34\0\x03\x0e\x49\x13\x3a\x0b\x3b\x0b\0\
\0\x08\x0f\0\x49\x13\0\0\x09\x15\x01\x49\x13\x27\x19\0\0\x0a\x05\0\x49\x13\0\0\
\x0b\x18\0\0\0\x0c\x26\0\x49\x13\0\0\x0d\x16\0\x49\x13\x03\x0e\x3a\x0b\x3b\x0b\
\0\0\x0e\x04\x01\x49\x13\x03\x0e\x0b\x0b\x3a\x0b\x3b\x05\0\0\x0f\x28\0\x03\x0e\
\x1c\x0f\0\0\x10\x2e\x01\x11\x01\x12\x06\x40\x18\x97\x42\x19\x03\x0e\x3a\x0b\
\x3b\x0b\x27\x19\x49\x13\x3f\x19\0\0\x11\x05\0\x02\x18\x03\x0e\x3a\x0b\x3b\x0b\
\x49\x13\0\0\x12\x05\0\x02\x17\x03\x0e\x3a\x0b\x3b\x0b\x49\x13\0\0\x13\x0b\x01\
\x11\x01\x12\x06\0\0\x14\x34\0\x02\x18\x03\x0e\x3a\x0b\x3b\x0b\x49\x13\0\0\x15\
\x13\x01\x03\x0e\x0b\x0b\x3a\x0b\x3b\x05\0\0\x16\x0d\0\x03\x0e\x49\x13\x3a\x0b\
\x3b\x05\x38\x0b\0\0\x17\x0d\0\x49\x13\x3a\x0b\x3b\x05\x38\x0b\0\0\x18\x17\x01\
\x0b\x0b\x3a\x0b\x3b\x05\0\0\x19\x16\0\x49\x13\x03\x0e\x3a\x0b\x3b\x05\0\0\0\0\
\x03\0\0\x04\0\0\0\0\0\x08\x01\0\0\0\0\x0c\0\x5a\0\0\0\0\0\0\0\x76\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x02\x8a\0\0\0\x3f\0\0\0\x01\x07\x09\x03\0\0\0\0\0\0\0\0\x03\
\x4b\0\0\0\x04\x52\0\0\0\x0d\0\x05\x92\0\0\0\x06\x01\x06\x97\0\0\0\x08\x07\x02\
\xab\0\0\0\x6e\0\0\0\x01\x09\x09\x03\0\0\0\0\0\0\0\0\x05\xb4\0\0\0\x05\x04\x07\
\xb8\0\0\0\x80\0\0\0\x03\xaa\x08\x85\0\0\0\x09\x96\0\0\0\x0a\x9d\0\0\0\x0a\xa7\
\0\0\0\x0b\0\x05\xc9\0\0\0\x05\x08\x08\xa2\0\0\0\x0c\x4b\0\0\0\x0d\xb2\0\0\0\
\xdf\0\0\0\x02\x12\x05\xd2\0\0\0\x07\x04\x0e\xb2\0\0\0\x33\x01\0\0\x04\x02\x4f\
\xb6\x0f\xe5\0\0\0\x01\x0f\xf1\0\0\0\x02\x0f\xfc\0\0\0\x03\x0f\x05\x01\0\0\x04\
\x0f\x0e\x01\0\0\x05\x0f\x1d\x01\0\0\x06\x0f\x27\x01\0\0\x0a\0\x10\0\0\0\0\0\0\
\0\0\x10\0\0\0\x01\x5a\x3d\x01\0\0\x01\x15\x6e\0\0\0\x11\x01\x51\x56\x01\0\0\
\x01\x15\x5d\x01\0\0\0\x10\0\0\0\0\0\0\0\0\xc0\0\0\0\x01\x5a\x4d\x01\0\0\x01\
\x31\x6e\0\0\0\x12\0\0\0\0\x56\x01\0\0\x01\x31\x5d\x01\0\0\x13\x28\0\0\0\0\0\0\
\0\x90\0\0\0\x14\x02\x91\0\x4f\x02\0\0\x01\x4e\xf7\x02\0\0\0\0\x08\x62\x01\0\0\
\x15\x41\x02\0\0\x48\x02\xb5\xb1\x16\x5a\x01\0\0\xa7\0\0\0\x02\xb6\xb1\0\x16\
\x66\x01\0\0\xa7\0\0\0\x02\xb7\xb1\x04\x16\x6f\x01\0\0\xfd\x01\0\0\x02\xb8\xb1\
\x08\x16\x78\x01\0\0\xa7\0\0\0\x02\xb9\xb1\x18\x16\x82\x01\0\0\xa7\0\0\0\x02\
\xba\xb1\x1c\x16\x89\x01\0\0\xa7\0\0\0\x02\xbb\xb1\x20\x16\x8e\x01\0\0\xa7\0\0\
\0\x02\xbc\xb1\x24\x16\x97\x01\0\0\xa7\0\0\0\x02\xbd\xb1\x28\x16\xa3\x01\0\0\
\xfd\x01\0\0\x02\xbe\xb1\x2c\x17\xe9\x01\0\0\x02\xbf\xb1\x40\x18\x08\x02\xbf\
\xb1\x16\xaf\x01\0\0\x09\x02\0\0\x02\xc0\xb1\0\0\0\x03\xa7\0\0\0\x04\x52\0\0\0\
\x04\0\x08\x0e\x02\0\0\x15\x38\x02\0\0\x50\x02\x4a\xb1\x16\xb2\x01\0\0\xa7\0\0\
\0\x02\x4b\xb1\0\x16\x82\x01\0\0\xa7\0\0\0\x02\x4c\xb1\x04\x16\x89\x01\0\0\xa7\
\0\0\0\x02\x4d\xb1\x08\x16\x8e\x01\0\0\xa7\0\0\0\x02\x4e\xb1\x0c\x16\xbf\x01\0\
\0\xa7\0\0\0\x02\x4f\xb1\x10\x16\xc4\x01\0\0\xa7\0\0\0\x02\x50\xb1\x14\x16\xcd\
\x01\0\0\xa7\0\0\0\x02\x51\xb1\x18\x16\xd5\x01\0\0\xfd\x01\0\0\x02\x52\xb1\x1c\
\x16\xdd\x01\0\0\xa7\0\0\0\x02\x53\xb1\x2c\x16\xe6\x01\0\0\xce\x02\0\0\x02\x54\
\xb1\x30\x16\x0b\x02\0\0\xa7\0\0\0\x02\x55\xb1\x34\x16\x13\x02\0\0\xfd\x01\0\0\
\x02\x56\xb1\x38\x16\x1b\x02\0\0\xa7\0\0\0\x02\x57\xb1\x48\x16\x21\x02\0\0\xec\
\x02\0\0\x02\x58\xb1\x4c\0\x19\xda\x02\0\0\x04\x02\0\0\x02\x22\x12\x0d\xe5\x02\
\0\0\xfe\x01\0\0\x02\x0e\x05\xef\x01\0\0\x07\x02\x0d\x6e\0\0\0\x32\x02\0\0\x02\
\x10\x03\x4b\0\0\0\x04\x52\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x63\x6c\x61\x6e\
\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\x32\x2e\x30\x2e\x31\x20\x28\x6f\
\x70\x65\x6e\x45\x75\x6c\x65\x72\x20\x31\x32\x2e\x30\x2e\x31\x2d\x31\x2e\x6f\
\x65\x32\x32\x30\x33\x20\x34\x66\x64\x35\x66\x62\x33\x38\x34\x62\x31\x38\x30\
\x63\x38\x35\x34\x64\x66\x39\x62\x64\x65\x32\x39\x61\x66\x62\x64\x61\x36\x64\
\x34\x30\x65\x38\x38\x33\x36\x66\x29\0\x2f\x72\x6f\x6f\x74\x2f\x73\x61\x6d\x70\
\x6c\x65\x73\x2f\x73\x65\x6e\x64\x6d\x73\x67\x2e\x62\x70\x66\x2e\x63\0\x2f\x72\
\x6f\x6f\x74\x2f\x73\x61\x6d\x70\x6c\x65\x73\x2f\x62\x75\x69\x6c\x64\0\x4c\x49\
\x43\x45\x4e\x53\x45\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\
\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x5f\x76\x65\x72\x73\x69\x6f\x6e\0\
\x69\x6e\x74\0\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\x6b\
\0\x6c\x6f\x6e\x67\x20\x69\x6e\x74\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x5f\x5f\x75\x33\x32\0\x53\x4f\x43\x4b\x5f\x53\x54\x52\x45\x41\x4d\0\
\x53\x4f\x43\x4b\x5f\x44\x47\x52\x41\x4d\0\x53\x4f\x43\x4b\x5f\x52\x41\x57\0\
\x53\x4f\x43\x4b\x5f\x52\x44\x4d\0\x53\x4f\x43\x4b\x5f\x53\x45\x51\x50\x41\x43\
\x4b\x45\x54\0\x53\x4f\x43\x4b\x5f\x44\x43\x43\x50\0\x53\x4f\x43\x4b\x5f\x50\
\x41\x43\x4b\x45\x54\0\x73\x6f\x63\x6b\x5f\x74\x79\x70\x65\0\x73\x65\x6e\x64\
\x6d\x73\x67\x5f\x76\x34\x5f\x70\x72\x6f\x67\0\x63\x6f\x6e\x6e\x65\x63\x74\x34\
\0\x63\x74\x78\0\x75\x73\x65\x72\x5f\x66\x61\x6d\x69\x6c\x79\0\x75\x73\x65\x72\
\x5f\x69\x70\x34\0\x75\x73\x65\x72\x5f\x69\x70\x36\0\x75\x73\x65\x72\x5f\x70\
\x6f\x72\x74\0\x66\x61\x6d\x69\x6c\x79\0\x74\x79\x70\x65\0\x70\x72\x6f\x74\x6f\
\x63\x6f\x6c\0\x6d\x73\x67\x5f\x73\x72\x63\x5f\x69\x70\x34\0\x6d\x73\x67\x5f\
\x73\x72\x63\x5f\x69\x70\x36\0\x73\x6b\0\x62\x6f\x75\x6e\x64\x5f\x64\x65\x76\
\x5f\x69\x66\0\x6d\x61\x72\x6b\0\x70\x72\x69\x6f\x72\x69\x74\x79\0\x73\x72\x63\
\x5f\x69\x70\x34\0\x73\x72\x63\x5f\x69\x70\x36\0\x73\x72\x63\x5f\x70\x6f\x72\
\x74\0\x64\x73\x74\x5f\x70\x6f\x72\x74\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\
\x73\x68\x6f\x72\x74\0\x5f\x5f\x75\x31\x36\0\x5f\x5f\x62\x65\x31\x36\0\x64\x73\
\x74\x5f\x69\x70\x34\0\x64\x73\x74\x5f\x69\x70\x36\0\x73\x74\x61\x74\x65\0\x72\
\x78\x5f\x71\x75\x65\x75\x65\x5f\x6d\x61\x70\x70\x69\x6e\x67\0\x5f\x5f\x73\x33\
\x32\0\x62\x70\x66\x5f\x73\x6f\x63\x6b\0\x62\x70\x66\x5f\x73\x6f\x63\x6b\x5f\
\x61\x64\x64\x72\0\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\
\0\xcc\x01\0\0\xcc\x01\0\0\xd4\x01\0\0\0\0\0\0\0\0\0\x02\x02\0\0\0\x01\0\0\0\
\x0a\0\0\x04\x48\0\0\0\x0f\0\0\0\x03\0\0\0\0\0\0\0\x1b\0\0\0\x03\0\0\0\x20\0\0\
\0\x24\0\0\0\x05\0\0\0\x40\0\0\0\x2d\0\0\0\x03\0\0\0\xc0\0\0\0\x37\0\0\0\x03\0\
\0\0\xe0\0\0\0\x3e\0\0\0\x03\0\0\0\0\x01\0\0\x43\0\0\0\x03\0\0\0\x20\x01\0\0\
\x4c\0\0\0\x03\0\0\0\x40\x01\0\0\x58\0\0\0\x05\0\0\0\x60\x01\0\0\0\0\0\0\x07\0\
\0\0\0\x02\0\0\x64\0\0\0\0\0\0\x08\x04\0\0\0\x6a\0\0\0\0\0\0\x01\x04\0\0\0\x20\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x03\0\0\0\x06\0\0\0\x04\0\0\0\x77\0\0\0\0\0\0\
\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\x01\0\0\x05\x08\0\0\0\x8b\0\0\0\x08\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x02\x14\0\0\0\0\0\0\0\x01\0\0\x0d\x0a\0\0\0\x8e\0\0\0\x01\0\
\0\0\x92\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x96\0\0\0\x01\0\0\x0c\x09\0\0\0\
\0\0\0\0\x01\0\0\x0d\x0a\0\0\0\x8e\0\0\0\x01\0\0\0\xd4\0\0\0\x01\0\0\x0c\x0c\0\
\0\0\xa5\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x0e\
\0\0\0\x06\0\0\0\x0d\0\0\0\xaa\x01\0\0\0\0\0\x0e\x0f\0\0\0\x01\0\0\0\xb2\x01\0\
\0\0\0\0\x0e\x0a\0\0\0\x01\0\0\0\xbb\x01\0\0\x01\0\0\x0f\0\0\0\0\x10\0\0\0\0\0\
\0\0\x0d\0\0\0\xc3\x01\0\0\x01\0\0\x0f\0\0\0\0\x11\0\0\0\0\0\0\0\x04\0\0\0\xcb\
\x01\0\0\0\0\0\x07\0\0\0\0\0\x62\x70\x66\x5f\x73\x6f\x63\x6b\x5f\x61\x64\x64\
\x72\0\x75\x73\x65\x72\x5f\x66\x61\x6d\x69\x6c\x79\0\x75\x73\x65\x72\x5f\x69\
\x70\x34\0\x75\x73\x65\x72\x5f\x69\x70\x36\0\x75\x73\x65\x72\x5f\x70\x6f\x72\
\x74\0\x66\x61\x6d\x69\x6c\x79\0\x74\x79\x70\x65\0\x70\x72\x6f\x74\x6f\x63\x6f\
\x6c\0\x6d\x73\x67\x5f\x73\x72\x63\x5f\x69\x70\x34\0\x6d\x73\x67\x5f\x73\x72\
\x63\x5f\x69\x70\x36\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\
\x20\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\
\x50\x45\x5f\x5f\0\x73\x6b\0\x63\x74\x78\0\x69\x6e\x74\0\x73\x65\x6e\x64\x6d\
\x73\x67\x5f\x76\x34\x5f\x70\x72\x6f\x67\0\x63\x67\x72\x6f\x75\x70\x2f\x73\x65\
\x6e\x64\x6d\x73\x67\x34\0\x2f\x72\x6f\x6f\x74\x2f\x73\x61\x6d\x70\x6c\x65\x73\
\x2f\x73\x65\x6e\x64\x6d\x73\x67\x2e\x62\x70\x66\x2e\x63\0\x7d\0\x63\x6f\x6e\
\x6e\x65\x63\x74\x34\0\x63\x67\x72\x6f\x75\x70\x2f\x63\x6f\x6e\x6e\x65\x63\x74\
\x34\0\x69\x6e\x74\x20\x63\x6f\x6e\x6e\x65\x63\x74\x34\x28\x73\x74\x72\x75\x63\
\x74\x20\x62\x70\x66\x5f\x73\x6f\x63\x6b\x5f\x61\x64\x64\x72\x20\x2a\x63\x74\
\x78\x29\0\x30\x3a\x31\0\x20\x20\x20\x20\x69\x66\x20\x28\x63\x74\x78\x2d\x3e\
\x75\x73\x65\x72\x5f\x69\x70\x34\x20\x3d\x3d\x20\x30\x78\x35\x30\x35\x30\x35\
\x64\x66\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\
\x69\x6e\x74\x6b\x28\x22\x61\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\
\x3a\x20\x69\x70\x3a\x30\x78\x25\x78\x20\x70\x6f\x72\x74\x3a\x25\x64\x5c\x6e\
\x22\x2c\x20\x62\x70\x66\x5f\x6e\x74\x6f\x68\x6c\x28\x63\x74\x78\x2d\x3e\x75\
\x73\x65\x72\x5f\x69\x70\x34\x29\x2c\x20\x63\x74\x78\x2d\x3e\x75\x73\x65\x72\
\x5f\x70\x6f\x72\x74\x29\x3b\0\x30\x3a\x33\0\x63\x68\x61\x72\0\x4c\x49\x43\x45\
\x4e\x53\x45\0\x5f\x76\x65\x72\x73\x69\x6f\x6e\0\x6c\x69\x63\x65\x6e\x73\x65\0\
\x76\x65\x72\x73\x69\x6f\x6e\0\x62\x70\x66\x5f\x73\x6f\x63\x6b\0\x9f\xeb\x01\0\
\x20\0\0\0\0\0\0\0\x24\0\0\0\x24\0\0\0\x74\0\0\0\x98\0\0\0\x3c\0\0\0\x08\0\0\0\
\xa6\0\0\0\x01\0\0\0\0\0\0\0\x0b\0\0\0\xdd\0\0\0\x01\0\0\0\0\0\0\0\x0d\0\0\0\
\x10\0\0\0\xa6\0\0\0\x01\0\0\0\0\0\0\0\xb6\0\0\0\xd2\0\0\0\x01\xb8\0\0\xdd\0\0\
\0\x05\0\0\0\0\0\0\0\xb6\0\0\0\xed\0\0\0\0\xc4\0\0\x08\0\0\0\xb6\0\0\0\x19\x01\
\0\0\x0e\x34\x01\0\x10\0\0\0\xb6\0\0\0\x19\x01\0\0\x09\x34\x01\0\x28\0\0\0\xb6\
\0\0\0\x3f\x01\0\0\x09\x38\x01\0\xb8\0\0\0\xb6\0\0\0\xd2\0\0\0\x01\x4c\x01\0\
\x10\0\0\0\xdd\0\0\0\x03\0\0\0\x08\0\0\0\x02\0\0\0\x15\x01\0\0\0\0\0\0\x78\0\0\
\0\x02\0\0\0\xa1\x01\0\0\0\0\0\0\x80\0\0\0\x02\0\0\0\x15\x01\0\0\0\0\0\0\0\x0c\
\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\xb8\
\0\0\0\x04\0\x66\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\
\x01\x2f\x72\x6f\x6f\x74\x2f\x73\x61\x6d\x70\x6c\x65\x73\0\x2f\x75\x73\x72\x2f\
\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\x70\x66\0\0\x73\x65\x6e\x64\x6d\x73\x67\
\x2e\x62\x70\x66\x2e\x63\0\x01\0\0\x76\x6d\x6c\x69\x6e\x75\x78\x2e\x68\0\x01\0\
\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\0\x02\0\
\0\0\0\x09\x02\0\0\0\0\0\0\0\0\x03\x15\x01\x05\x01\x0a\x03\x18\x01\x02\x02\0\
\x01\x01\0\x09\x02\0\0\0\0\0\0\0\0\x03\x31\x01\x05\x0e\x0a\x03\x1b\x20\x05\x09\
\x06\x20\x03\xb3\x7f\x20\x06\x03\xce\0\x2e\x06\x03\xb2\x7f\x08\x12\x05\x01\x06\
\x03\xd3\0\x20\x02\x01\0\x01\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xae\0\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfd\0\0\0\0\
\0\x04\0\xb8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0a\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x14\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x16\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd5\0\0\
\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x4f\0\0\0\x11\0\x06\0\0\0\0\0\
\0\0\0\0\x04\0\0\0\0\0\0\0\xe4\0\0\0\x12\0\x04\0\0\0\0\0\0\0\0\0\xc0\0\0\0\0\0\
\0\0\x58\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\
\x01\0\0\0\x04\0\0\0\x06\0\0\0\0\0\0\0\x0a\0\0\0\x06\0\0\0\x0c\0\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\x12\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x16\0\0\0\0\0\0\0\
\x0a\0\0\0\x0a\0\0\0\x1a\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x26\0\0\0\0\0\0\0\
\x0a\0\0\0\x07\0\0\0\x2b\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x37\0\0\0\0\0\0\0\
\x01\0\0\0\x0b\0\0\0\x4c\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x53\0\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\x5a\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x66\0\0\0\0\0\0\0\
\x01\0\0\0\x0c\0\0\0\x6f\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x76\0\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\x97\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xac\0\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\xb3\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xbe\0\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\xc7\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xcd\0\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\xd3\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xd9\0\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\xdf\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xe5\0\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\xeb\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xf2\0\0\0\0\0\0\0\
\x01\0\0\0\x03\0\0\0\0\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x0d\x01\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\x19\x01\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x27\x01\0\0\0\0\0\
\0\x0a\0\0\0\x08\0\0\0\x32\x01\0\0\0\0\0\0\x0a\0\0\0\x05\0\0\0\x36\x01\0\0\0\0\
\0\0\x0a\0\0\0\x08\0\0\0\x41\x01\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x51\x01\0\0\0\
\0\0\0\x0a\0\0\0\x08\0\0\0\x63\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x6c\x01\0\0\
\0\0\0\0\x0a\0\0\0\x08\0\0\0\x79\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x86\x01\0\
\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x93\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xa0\x01\
\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xad\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xba\
\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xc7\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\
\xd4\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xef\x01\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\
\0\x0f\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x18\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\
\0\0\x25\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x32\x02\0\0\0\0\0\0\x0a\0\0\0\x08\
\0\0\0\x3f\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x4c\x02\0\0\0\0\0\0\x0a\0\0\0\
\x08\0\0\0\x59\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x66\x02\0\0\0\0\0\0\x0a\0\0\
\0\x08\0\0\0\x73\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x80\x02\0\0\0\0\0\0\x0a\0\
\0\0\x08\0\0\0\x8d\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\x9a\x02\0\0\0\0\0\0\x0a\
\0\0\0\x08\0\0\0\xa7\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xb4\x02\0\0\0\0\0\0\
\x0a\0\0\0\x08\0\0\0\xc1\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xd3\x02\0\0\0\0\0\
\0\x0a\0\0\0\x08\0\0\0\xdf\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\xe6\x02\0\0\0\0\
\0\0\x0a\0\0\0\x08\0\0\0\xf1\x02\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x01\0\0\0\x03\0\0\0\x10\0\0\0\0\0\0\0\
\x01\0\0\0\x04\0\0\0\x18\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\xb8\x01\0\0\0\0\0\0\
\0\0\0\0\x0b\0\0\0\xd0\x01\0\0\0\0\0\0\0\0\0\0\x0c\0\0\0\x2c\0\0\0\0\0\0\0\0\0\
\0\0\x03\0\0\0\x3c\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x50\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\x68\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x78\0\0\0\0\0\0\0\0\0\0\0\x04\0\
\0\0\x88\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x98\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\
\xa8\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\xc4\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\xd4\0\
\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\xe4\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x14\0\0\0\0\
\0\0\0\x0a\0\0\0\x09\0\0\0\x18\0\0\0\0\0\0\0\x01\0\0\0\x03\0\0\0\x2c\0\0\0\0\0\
\0\0\x0a\0\0\0\x09\0\0\0\x30\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x73\0\0\0\0\0\0\
\0\x01\0\0\0\x03\0\0\0\x8c\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x0e\x0d\x0b\x0c\0\
\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\
\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x64\x65\
\x62\x75\x67\x5f\x72\x61\x6e\x67\x65\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\
\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x5f\x76\
\x65\x72\x73\x69\x6f\x6e\0\x73\x65\x6e\x64\x6d\x73\x67\x5f\x76\x34\x5f\x70\x72\
\x6f\x67\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\
\x65\x6e\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\
\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x2e\x72\
\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x6f\x63\0\x73\x65\x6e\x64\x6d\x73\x67\
\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\
\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\x63\
\x67\x72\x6f\x75\x70\x2f\x63\x6f\x6e\x6e\x65\x63\x74\x34\0\x63\x67\x72\x6f\x75\
\x70\x2f\x73\x65\x6e\x64\x6d\x73\x67\x34\0\x4c\x42\x42\x31\x5f\x32\0\x2e\x72\
\x6f\x64\x61\x74\x61\x2e\x73\x74\x72\x31\x2e\x31\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xbc\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xcc\x14\0\0\0\0\0\0\x13\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xed\0\
\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x10\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdd\0\0\0\x01\0\0\0\
\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x76\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x10\x01\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x20\x01\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x04\x01\0\0\x01\0\0\0\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x24\x01\
\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\xa3\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x44\x01\0\0\0\0\0\0\
\x33\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\0\0\0\
\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x0f\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\x19\0\0\0\x08\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x77\x01\0\0\0\0\0\0\x31\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x43\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\xa8\x02\0\0\0\0\0\0\x04\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3f\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x58\x0f\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\x19\0\0\0\x0b\0\0\0\x08\0\0\0\0\0\0\
\0\x10\0\0\0\0\0\0\0\x26\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xac\
\x05\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x22\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x13\0\0\0\0\0\0\
\x40\0\0\0\0\0\0\0\x19\0\0\0\x0d\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x34\
\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xdc\x05\0\0\0\0\0\0\x57\x02\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xd0\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x33\x08\0\0\0\0\0\0\xb8\x03\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcc\0\0\0\x09\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x98\x13\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x19\0\0\0\x10\0\
\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xeb\x0b\0\0\0\0\0\0\xf4\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xb8\x13\0\0\0\0\0\0\xb0\0\0\0\0\0\0\0\x19\0\0\0\x12\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x92\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\x0c\
\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x8e\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x68\x14\0\0\0\0\0\0\x40\
\0\0\0\0\0\0\0\x19\0\0\0\x14\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x82\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x0d\0\0\0\0\0\0\xbc\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7e\0\0\0\x09\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\x14\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x19\0\0\0\
\x16\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x68\0\0\0\x03\x4c\xff\x6f\0\0\0\
\x80\0\0\0\0\0\0\0\0\0\0\0\0\xc8\x14\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x19\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc4\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xe0\x0d\0\0\0\0\0\0\x68\x01\0\0\0\0\0\0\x01\0\0\0\x0b\0\0\0\x08\
\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -1;
}

#endif /* __SENDMSG_BPF_SKEL_H__ */