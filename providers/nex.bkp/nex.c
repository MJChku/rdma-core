/*
 * NEX RDMA Provider - TCP/IP Emulation
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <infiniband/driver.h>
#include <infiniband/verbs.h>

#include "nex.h"
#include "nex-abi.h"

static void nex_free_context(struct ibv_context *ibctx);

static const struct verbs_match_ent hca_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_RXE),
	VERBS_NAME_MATCH("nex", NULL),
	{},
};

static int nex_query_device(struct ibv_context *context,
			    const struct ibv_query_device_ex_input *input,
			    struct ibv_device_attr_ex *attr, size_t attr_size)
{
	return ibv_cmd_query_device_any(context, input, attr, attr_size, NULL, 0);
}

static int nex_query_port(struct ibv_context *context, uint8_t port,
			  struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port, attr, &cmd, sizeof(cmd));
}

static struct ibv_pd *nex_alloc_pd(struct ibv_context *context)
{
	struct ibv_alloc_pd cmd;
	struct ib_uverbs_alloc_pd_resp resp;
	struct ibv_pd *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(context, pd, &cmd, sizeof(cmd),
					&resp, sizeof(resp))) {
		free(pd);
		return NULL;
	}

	return pd;
}

static int nex_dealloc_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);
	if (!ret)
		free(pd);

	return ret;
}

static struct ibv_mr *nex_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 uint64_t hca_va, int access)
{
	struct verbs_mr *vmr;
	struct ibv_reg_mr cmd;
	struct ib_uverbs_reg_mr_resp resp;
	int ret;

	vmr = calloc(1, sizeof(*vmr));
	if (!vmr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length, hca_va, access, vmr, &cmd,
			     sizeof(cmd), &resp, sizeof(resp));
	if (ret) {
		free(vmr);
		return NULL;
	}

	return &vmr->ibv_mr;
}

static int nex_dereg_mr(struct verbs_mr *vmr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(vmr);
	if (!ret)
		free(vmr);

	return ret;
}

static struct ibv_cq *nex_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct ibv_create_cq cmd;
	struct ib_uverbs_create_cq_resp resp;
	struct ibv_cq *cq;

	cq = calloc(1, sizeof(struct ibv_cq));
	if (!cq)
		return NULL;

	if (ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				cq, &cmd, sizeof(cmd),
				&resp, sizeof(resp))) {
		free(cq);
		return NULL;
	}

	return cq;
}

static int nex_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);
	if (!ret)
		free(cq);

	return ret;
}

static struct ibv_qp *nex_create_qp(struct ibv_pd *pd,
				    struct ibv_qp_init_attr *attr)
{
	struct ibv_create_qp cmd;
	struct ib_uverbs_create_qp_resp resp;
	struct ibv_qp *qp;

	qp = calloc(1, sizeof(struct ibv_qp));
	if (!qp)
		return NULL;

	if (ibv_cmd_create_qp(pd, qp, attr, &cmd, sizeof(cmd),
					&resp, sizeof(resp))) {
		free(qp);
		return NULL;
	}

	return qp;
}

static int nex_destroy_qp(struct ibv_qp *qp)
{
	int ret;

	ret = ibv_cmd_destroy_qp(qp);
	if (!ret)
		free(qp);

	return ret;
}

static int nex_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			 int attr_mask)
{
	struct ibv_modify_qp cmd;

	return ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));
}

static int nex_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr,
				&cmd, sizeof(cmd));
}

static int nex_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
			 struct ibv_send_wr **bad_wr)
{
	return ibv_cmd_post_send(qp, wr, bad_wr);
}

static int nex_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr)
{
	return ibv_cmd_post_recv(qp, wr, bad_wr);
}

static int nex_poll_cq(struct ibv_cq *cq, int num_entries,
		       struct ibv_wc *wc)
{
	return ibv_cmd_poll_cq(cq, num_entries, wc);
}

static int nex_req_notify_cq(struct ibv_cq *cq, int solicited_only)
{
	return ibv_cmd_req_notify_cq(cq, solicited_only);
}

static struct ibv_ah *nex_create_ah(struct ibv_pd *pd,
				    struct ibv_ah_attr *attr)
{
	struct ib_uverbs_create_ah_resp resp;
	struct ibv_ah *ah;

	ah = calloc(1, sizeof(struct ibv_ah));
	if (!ah)
		return NULL;

	if (ibv_cmd_create_ah(pd, ah, attr, &resp, sizeof(resp))) {
		free(ah);
		return NULL;
	}

	return ah;
}

static int nex_destroy_ah(struct ibv_ah *ah)
{
	int ret;

	ret = ibv_cmd_destroy_ah(ah);
	if (!ret)
		free(ah);

	return ret;
}

static const struct verbs_context_ops nex_ctx_ops = {
	.query_device_ex = nex_query_device,
	.query_port = nex_query_port,
	.alloc_pd = nex_alloc_pd,
	.dealloc_pd = nex_dealloc_pd,
	.reg_mr = nex_reg_mr,
	.dereg_mr = nex_dereg_mr,
	.create_cq = nex_create_cq,
	.destroy_cq = nex_destroy_cq,
	.create_qp = nex_create_qp,
	.destroy_qp = nex_destroy_qp,
	.modify_qp = nex_modify_qp,
	.query_qp = nex_query_qp,
	.post_send = nex_post_send,
	.post_recv = nex_post_recv,
	.poll_cq = nex_poll_cq,
	.req_notify_cq = nex_req_notify_cq,
	.create_ah = nex_create_ah,
	.destroy_ah = nex_destroy_ah,
	.free_context = nex_free_context,
};

static struct verbs_context *nex_alloc_context(struct ibv_device *ibdev,
					       int cmd_fd,
					       void *private_data)
{
	struct nex_context *context;
	struct ibv_get_context cmd;
	struct ib_uverbs_get_context_resp resp;

	context = verbs_init_and_alloc_context(ibdev, cmd_fd, context, ibv_ctx,
					       RDMA_DRIVER_RXE);
	if (!context)
		return NULL;

	if (ibv_cmd_get_context(&context->ibv_ctx, &cmd, sizeof(cmd),
				NULL, &resp, sizeof(resp)))
		goto out;

	verbs_set_ops(&context->ibv_ctx, &nex_ctx_ops);

	return &context->ibv_ctx;

out:
	verbs_uninit_context(&context->ibv_ctx);
	free(context);
	return NULL;
}

static void nex_free_context(struct ibv_context *ibctx)
{
	struct nex_context *context = to_nctx(ibctx);

	verbs_uninit_context(&context->ibv_ctx);
	free(context);
}

static void nex_uninit_device(struct verbs_device *verbs_device)
{
	struct nex_device *dev = to_ndev(&verbs_device->device);

	free(dev);
}

static struct verbs_device *nex_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct nex_device *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	return &dev->ibv_dev;
}

static const struct verbs_device_ops nex_dev_ops = {
	.name = "nex",
	.match_min_abi_version = 1,
	.match_max_abi_version = 1,
	.match_table = hca_table,
	.alloc_device = nex_device_alloc,
	.uninit_device = nex_uninit_device,
	.alloc_context = nex_alloc_context,
};

PROVIDER_DRIVER(nex, nex_dev_ops);