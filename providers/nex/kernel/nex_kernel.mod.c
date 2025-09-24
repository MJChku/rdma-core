#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_MITIGATION_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

KSYMTAB_DATA(nex_kernel_loaded, "", "");

SYMBOL_CRC(nex_kernel_loaded, 0x96238b4f, "");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xdf15898d, "_ib_alloc_device" },
	{ 0xb6ccdb14, "init_net" },
	{ 0x84c03ca0, "dev_get_by_name" },
	{ 0xac399d15, "ib_set_device_ops" },
	{ 0x7e923efc, "ib_register_device" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xe414b76d, "param_ops_charp" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x122c3a7e, "_printk" },
	{ 0x4083fd0d, "ib_unregister_device" },
	{ 0xdfa4ca61, "ib_device_set_netdev" },
	{ 0xfe279e96, "ib_dealloc_device" },
	{ 0x4ba2ce0f, "module_layout" },
};

MODULE_INFO(depends, "ib_core");


MODULE_INFO(srcversion, "A0333D86D50CA5D79A2D4FF");
