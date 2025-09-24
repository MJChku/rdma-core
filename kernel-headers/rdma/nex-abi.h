/*
 * NEX RDMA Emulation Kernel ABI Header
 *
 * Copyright (c) 2025 NEX Project
 */

#ifndef NEX_ABI_USER_H
#define NEX_ABI_USER_H

#include <linux/types.h>
#include <rdma/ib_user_verbs.h>

/* NEX-specific commands */
enum {
	NEX_IB_USER_VERBS_CMD_FIRST = IB_USER_VERBS_CMD_FIRST + 100,
	NEX_IB_USER_VERBS_CMD_ALLOC_CONTEXT,
	NEX_IB_USER_VERBS_CMD_CREATE_CQ,
	NEX_IB_USER_VERBS_CMD_CREATE_QP,
	NEX_IB_USER_VERBS_CMD_CREATE_SRQ,
	NEX_IB_USER_VERBS_CMD_REG_MR,
	NEX_IB_USER_VERBS_CMD_CREATE_AH,
};

/* NEX context allocation response */
struct nex_uresp_alloc_ctx {
	__u32 async_fd;
};

/* NEX CQ creation response */
struct nex_uresp_create_cq {
	__u32 cq_handle;
};

/* NEX QP creation response */
struct nex_uresp_create_qp {
	__u32 qp_handle;
	__u32 qp_num;
};

/* NEX SRQ creation response */
struct nex_uresp_create_srq {
	__u32 srq_handle;
	__u32 srq_num;
};

/* NEX MR registration request */
struct nex_ureq_reg_mr {
	__u64 start;
	__u64 length;
	__u64 hca_va;
	__u32 pd_handle;
	__u32 access_flags;
};

/* NEX MR registration response */
struct nex_uresp_reg_mr {
	__u32 mr_handle;
	__u32 lkey;
	__u32 rkey;
};

/* NEX AH creation response */
struct nex_uresp_create_ah {
	__u32 ah_handle;
	__u32 ah_num;
};

#endif /* NEX_ABI_USER_H */