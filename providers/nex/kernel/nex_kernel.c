// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal NEX RDMA Emu Device (modeled after upstream siw patterns)
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <rdma/ib_verbs.h>

#define NEX_NAME "nex0"

static char *ifname;
module_param(ifname, charp, 0444);
MODULE_PARM_DESC(ifname, "netdev to bind (e.g., eth0)");

struct nex_dev {
	struct ib_device base_dev;     /* must match ib_alloc_device(...) member */
	s8           numa_node;
	u8           raw_gid[ETH_ALEN];
	struct net_device *netdev;     /* held while device is registered */
};


struct nex_ucontext {
	struct ib_ucontext ibucontext;
};

struct nex_pd {
	struct ib_pd ibpd;
};

struct nex_cq {
	struct ib_cq ibcq;
};

struct nex_qp {
	struct ib_qp ibqp;
};

#define to_nex(ibdev) container_of(ibdev, struct nex_dev, base_dev)

static struct nex_dev *nex_singleton;

/* exported sanity bit (optional) */
int nex_kernel_loaded;
EXPORT_SYMBOL(nex_kernel_loaded);

/* ---- ops (all stubbed) ---- */
static int nex_query_device(struct ib_device *dev, struct ib_device_attr *a,
			    struct ib_udata *udata)
{
	memset(a, 0, sizeof(*a));
	a->fw_ver            = 0x010000;
	a->max_mr_size       = ~0ULL;
	a->page_size_cap     = PAGE_SIZE;
	a->vendor_id         = 0x1234;
	a->vendor_part_id    = 0x5678;
	a->hw_ver            = 1;
	a->max_qp            = 1; a->max_qp_wr = 1;
	a->max_cq            = 1; a->max_cqe   = 1;
	a->max_pd            = 1; a->max_mr    = 1;
	a->atomic_cap        = IB_ATOMIC_NONE;
	a->masked_atomic_cap = IB_ATOMIC_NONE;
	a->max_pkeys         = 1;
	return 0;
}

static int nex_query_port(struct ib_device *dev, u32 port, struct ib_port_attr *p)
{
	if (port != 1) return -EINVAL;
	memset(p, 0, sizeof(*p));
	p->state        = IB_PORT_ACTIVE;
	p->max_mtu      = IB_MTU_4096;
	p->active_mtu   = IB_MTU_1024;
	p->gid_tbl_len  = 1;
	p->pkey_tbl_len = 1;
	p->active_width = IB_WIDTH_1X;
	p->active_speed = IB_SPEED_SDR;
	p->phys_state   = IB_PORT_PHYS_STATE_LINK_UP;
	return 0;
}

static int nex_get_port_immutable(struct ib_device *dev, u32 port,
				  struct ib_port_immutable *imm)
{
	if (port != 1) return -EINVAL;
	memset(imm, 0, sizeof(*imm));
	imm->pkey_tbl_len = 1;
	imm->gid_tbl_len  = 1;
	return 0;
}

static enum rdma_link_layer nex_get_link_layer(struct ib_device *d, u32 port)
{
	return IB_LINK_LAYER_ETHERNET;
}

static int nex_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	return 0;
}

static void nex_dealloc_ucontext(struct ib_ucontext *uctx)
{
}

static int nex_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	return 0;
}

static int nex_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	return 0;
}

static int nex_create_cq(struct ib_cq *cq, const struct ib_cq_init_attr *attr,
			  struct ib_udata *udata)
{
	return 0;
}

static int nex_destroy_cq(struct ib_cq *cq, struct ib_udata *udata)
{
	return 0;
}

static int nex_poll_cq(struct ib_cq *cq, int num_entries, struct ib_wc *wc)
{
	return 0;
}

static int nex_req_notify_cq(struct ib_cq *cq, enum ib_cq_notify_flags flags)
{
	return 0;
}

static int nex_create_qp(struct ib_qp *qp, struct ib_qp_init_attr *attr,
			 struct ib_udata *udata)
{
	return -EOPNOTSUPP;
}

static int nex_modify_qp(struct ib_qp *qp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_udata *udata)
{
	return -EOPNOTSUPP;
}

static int nex_query_qp(struct ib_qp *qp, struct ib_qp_attr *attr,
			int attr_mask, struct ib_qp_init_attr *init_attr)
{
	return -EOPNOTSUPP;
}

static int nex_destroy_qp(struct ib_qp *qp, struct ib_udata *udata)
{
	return 0;
}

static int nex_post_send(struct ib_qp *qp, const struct ib_send_wr *wr,
			 const struct ib_send_wr **bad_wr)
{
	return -EOPNOTSUPP;
}

static int nex_post_recv(struct ib_qp *qp, const struct ib_recv_wr *wr,
			 const struct ib_recv_wr **bad_wr)
{
	return -EOPNOTSUPP;
}

static struct ib_mr *nex_get_dma_mr(struct ib_pd *pd, int access)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static struct ib_mr *nex_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				      u64 virt_addr, int access,
				      struct ib_udata *udata)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static int nex_dereg_mr(struct ib_mr *mr, struct ib_udata *udata)
{
	return -EOPNOTSUPP;
}

static int nex_query_gid(struct ib_device *d, u32 port, int idx, union ib_gid *gid)
{
	struct nex_dev *n = to_nex(d);
	if (port != 1 || idx != 0) return -EINVAL;
	memset(gid, 0, sizeof(*gid));
	/* RoCE v1-style local-ID hack: just stash MAC in low bytes */
	memcpy(gid->raw, n->raw_gid, ETH_ALEN);
	return 0;
}

static int nex_query_pkey(struct ib_device *d, u32 port, u16 idx, u16 *pkey)
{
	if (port != 1 || idx != 0) return -EINVAL;
	*pkey = 0xFFFF;
	return 0;
}

static const struct ib_device_ops nex_ops = {
	.owner               = THIS_MODULE,
	.driver_id           = RDMA_DRIVER_UNKNOWN,
	.uverbs_abi_ver      = 1,

	.alloc_ucontext      = nex_alloc_ucontext,
	.dealloc_ucontext    = nex_dealloc_ucontext,
	.alloc_pd            = nex_alloc_pd,
	.dealloc_pd          = nex_dealloc_pd,
	.create_cq           = nex_create_cq,
	.destroy_cq          = nex_destroy_cq,
	.poll_cq             = nex_poll_cq,
	.req_notify_cq       = nex_req_notify_cq,
	.create_qp           = nex_create_qp,
	.modify_qp           = nex_modify_qp,
	.query_qp            = nex_query_qp,
	.destroy_qp          = nex_destroy_qp,
	.post_send           = nex_post_send,
	.post_recv           = nex_post_recv,
	.get_dma_mr          = nex_get_dma_mr,
	.reg_user_mr         = nex_reg_user_mr,
	.dereg_mr            = nex_dereg_mr,
	.query_device        = nex_query_device,
	.query_port          = nex_query_port,
	.get_port_immutable  = nex_get_port_immutable,
	.get_link_layer      = nex_get_link_layer,
	.query_gid           = nex_query_gid,
	.query_pkey          = nex_query_pkey,

	INIT_RDMA_OBJ_SIZE(ib_ucontext, nex_ucontext, ibucontext),
	INIT_RDMA_OBJ_SIZE(ib_pd, nex_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_cq, nex_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_qp, nex_qp, ibqp),
};

/* ---- init / exit ---- */
static int __init nex_init(void)
{
	struct nex_dev *nex;
	struct ib_device *ibd;
	struct net_device *ndev = NULL;
	__be64 node_guid = cpu_to_be64(0x1122334455667788ULL);
	int ret;

	pr_info("nex: loading minimal RDMA emu device\n");

	/* allocate full parent object (siw uses this pattern) */
	/* sdev = ib_alloc_device(siw_device, base_dev);  — per siw */ /* :contentReference[oaicite:1]{index=1} */
	nex = ib_alloc_device(nex_dev, base_dev);
	if (!nex)
		return -ENOMEM;

	ibd = &nex->base_dev;
	nex->numa_node = NUMA_NO_NODE;
	nex->netdev = NULL;

	/* optional netdev binding (like siw’s ib_device_set_netdev) */
	if (ifname && *ifname) {
		ndev = dev_get_by_name(&init_net, ifname);
		if (!ndev)
			pr_warn("nex: ifname=%s not found; continuing unbound\n", ifname);
	}

	/* fill identity */
	strscpy(ibd->name, NEX_NAME, IB_DEVICE_NAME_MAX);
	ibd->node_type      = RDMA_NODE_IB_CA;
	ibd->phys_port_cnt  = 1;
	ibd->num_comp_vectors = 1;
	ibd->local_dma_lkey = 0;
	memset(nex->raw_gid, 0, ETH_ALEN);
	ibd->dev.parent = NULL;
	ibd->dma_device = NULL;

	if (ndev) {
		u8 mac[ETH_ALEN] = {};
		nex->numa_node = dev_to_node(&ndev->dev);
		if (ndev->addr_len) {
			memcpy(mac, ndev->dev_addr,
			       min_t(unsigned int, ndev->addr_len, ETH_ALEN));
			memcpy(nex->raw_gid, mac, ETH_ALEN);
			if (is_valid_ether_addr(mac))
				node_guid = cpu_to_be64(((u64)mac[0] << 56) |
						((u64)mac[1] << 48) |
						((u64)mac[2] << 40) |
						((u64)mac[3] << 32) |
						((u64)mac[4] << 24) |
						((u64)mac[5] << 16));
		}
		ret = ib_device_set_netdev(ibd, ndev, 1);
		if (ret) {
			pr_warn("nex: ib_device_set_netdev failed: %d\n", ret);
			dev_put(ndev);
			ndev = NULL;
		} else {
			memcpy(ibd->iw_ifname, ndev->name, sizeof(ibd->iw_ifname));
			ibd->dev.parent = &ndev->dev;
			ibd->dma_device = &ndev->dev;
			nex->netdev = ndev;
		}
	}

	ib_set_device_ops(ibd, &nex_ops);
	strscpy(ibd->node_desc, "NEX minimal RDMA", sizeof(ibd->node_desc));
	ibd->node_guid = node_guid;

	ret = ib_register_device(ibd, "nex%d", NULL);
	if (ret) {
		pr_err("nex: ib_register_device failed: %d\n", ret);
		if (nex->netdev) {
			ib_device_set_netdev(ibd, NULL, 1);
			dev_put(nex->netdev);
			nex->netdev = NULL;
		}
		ib_dealloc_device(ibd);
		return ret;
	}
	nex_singleton = nex;

	nex_kernel_loaded = 1;
	pr_info("nex: registered as %s (if=%s)\n", NEX_NAME, ifname ? ifname : "none");
	return 0;
}

static void __exit nex_exit(void)
{
	struct nex_dev *nex = nex_singleton;

	if (!nex)
		return;

	pr_info("nex: unloading\n");
	ib_unregister_device(&nex->base_dev);
	if (nex->netdev) {
		ib_device_set_netdev(&nex->base_dev, NULL, 1);
		dev_put(nex->netdev);
		nex->netdev = NULL;
	}
	ib_dealloc_device(&nex->base_dev);
	nex_singleton = NULL;
	nex_kernel_loaded = 0;
}

module_init(nex_init);
module_exit(nex_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NEX Project");
MODULE_DESCRIPTION("Minimal NEX RDMA Emu Device");
