#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kexec.h>
#include <linux/mutex.h>
#include <linux/capability.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/err.h>

#include "kernel_h.h"

static int kimage_alloc_init(struct kimage **out_image, unsigned long entry,
			     unsigned long nr_segments,
			     struct kexec_segment *segments,
			     unsigned long flags)
{
	struct kimage *image;
	int ret;

	bool kexec_on_panic = flags & KEXEC_ON_CRASH;

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		if (!crashk_res.start || !crashk_res.end)
			return -EINVAL;

		if ((entry < phys_to_boot_phys(crashk_res.start)) ||
		    (entry > phys_to_boot_phys(crashk_res.end)))
			return -EADDRNOTAVAIL;
	}
#endif

	image = do_kimage_alloc_init();
	if (!image)
		return -ENOMEM;

	image->start = entry;
	image->nr_segments = nr_segments;

	ret = -EINVAL;
	if (!segments || nr_segments > KEXEC_SEGMENT_MAX)
		goto err_free;

	memcpy(image->segment, segments, nr_segments * sizeof(*segments));

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		image->control_page = crashk_res.start;
		image->type = KEXEC_TYPE_CRASH;
	}
#endif

	ret = sanity_check_segment_list(image);
	if (ret)
		goto err_free;

	image->control_code_page = kimage_alloc_control_pages(image,
				 get_order(KEXEC_CONTROL_PAGE_SIZE));
	if (!image->control_code_page) {
		ret = -ENOMEM;
		goto err_free;
	}

	if (!kexec_on_panic) {
		image->swap_page = kimage_alloc_control_pages(image, 0);
		if (!image->swap_page) {
			ret = -ENOMEM;
			goto err_free_control;
		}
	}

	*out_image = image;
	return 0;

err_free_control:
	kimage_free_page_list(&image->control_pages);
err_free:
	kfree(image);
	return ret;
}

static int do_kexec_load(unsigned long entry, unsigned long nr_segments,
			 struct kexec_segment *segments, unsigned long flags)
{
	struct kimage **dest_image;
	struct kimage *image = NULL;
	unsigned long i;
	int ret;

	if (!kexec_trylock())
		return -EBUSY;

#ifdef CONFIG_CRASH_DUMP
	if (flags & KEXEC_ON_CRASH) {
		dest_image = &kexec_crash_image;
		if (*dest_image)
			arch_kexec_unprotect_crashkres();
	} else
#endif
		dest_image = &kexec_image;

	if (nr_segments == 0) {
		kimage_free(xchg(dest_image, NULL));
		ret = 0;
		goto out_unlock;
	}

	if (flags & KEXEC_ON_CRASH) {
		kimage_free(xchg(&kexec_crash_image, NULL));
	}

	ret = kimage_alloc_init(&image, entry, nr_segments, segments, flags);
	if (ret)
		goto out_unlock;

	if (flags & KEXEC_PRESERVE_CONTEXT)
		image->preserve_context = 1;

#ifdef CONFIG_CRASH_HOTPLUG
	if ((flags & KEXEC_ON_CRASH) && arch_crash_hotplug_support(image, flags))
		image->hotplug_support = 1;
#endif

	ret = machine_kexec_prepare(image);
	if (ret)
		goto out_free;

	ret = kimage_crash_copy_vmcoreinfo(image);
	if (ret)
		goto out_free;

	for (i = 0; i < nr_segments; i++) {
		ret = kimage_load_segment(image, i);
		if (ret)
			goto out_free;
	}

	kimage_terminate(image);

	ret = machine_kexec_post_load(image);
	if (ret)
		goto out_free;

	image = xchg(dest_image, image);
	ret = 0;

out_free:
#ifdef CONFIG_CRASH_DUMP
	if ((flags & KEXEC_ON_CRASH) && kexec_crash_image)
		arch_kexec_protect_crashkres();
#endif
	kimage_free(image);
out_unlock:
	kexec_unlock();
	return ret;
}

static inline int kexec_load_check(unsigned long nr_segments,
				   unsigned long flags)
{
	int image_type = (flags & KEXEC_ON_CRASH) ? KEXEC_TYPE_CRASH :
						     KEXEC_TYPE_DEFAULT;
	int result;

	if (!kexec_load_permitted(image_type))
		return -EPERM;

	result = security_kernel_load_data(LOADING_KEXEC_IMAGE, false);
	if (result < 0)
		return result;

	result = security_locked_down(LOCKDOWN_KEXEC);
	if (result)
		return result;

	if ((flags & KEXEC_FLAGS) != (flags & ~KEXEC_ARCH_MASK))
		return -EINVAL;

	if (nr_segments > KEXEC_SEGMENT_MAX)
		return -EINVAL;

	return 0;
}

SYSCALL_DEFINE4(kexec_load,
		unsigned long, entry,
		unsigned long, nr_segments,
		struct kexec_segment __user *, segments,
		unsigned long, flags)
{
	struct kexec_segment *ksegments = NULL;
	int ret;

	ret = kexec_load_check(nr_segments, flags);
	if (ret)
		return ret;

#ifdef KEXEC_ARCH_MASK
	if (((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH) &&
	    ((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH_DEFAULT))
		return -EINVAL;
#endif

	ksegments = memdup_array_user(segments, nr_segments,
				      sizeof(struct kexec_segment));
	if (IS_ERR(ksegments))
		return PTR_ERR(ksegments);

	ret = do_kexec_load(entry, nr_segments, ksegments, flags);

	kfree(ksegments);
	return ret;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(kexec_load, compat_ulong_t, entry,
		       compat_ulong_t, nr_segments,
		       struct compat_kexec_segment __user *, segments,
		       compat_ulong_t, flags)
{
	struct compat_kexec_segment in;
	struct kexec_segment *ksegments = NULL;
	unsigned long i;
	int ret;

	ret = kexec_load_check(nr_segments, flags);
	if (ret)
		return ret;

	if ((flags & KEXEC_ARCH_MASK) == KEXEC_ARCH_DEFAULT)
		return -EINVAL;

	ksegments = kcalloc(nr_segments, sizeof(*ksegments), GFP_KERNEL);
	if (!ksegments)
		return -ENOMEM;

	for (i = 0; i < nr_segments; i++) {
		if (copy_from_user(&in, &segments[i], sizeof(in))) {
			ret = -EFAULT;
			goto out_free;
		}

		ksegments[i].buf   = compat_ptr(in.buf);
		ksegments[i].bufsz = in.bufsz;
		ksegments[i].mem   = in.mem;
		ksegments[i].memsz = in.memsz;
	}

	ret = do_kexec_load(entry, nr_segments, ksegments, flags);

out_free:
	kfree(ksegments);
	return ret;
}
#endif

#ifdef CONFIG_KEXEC_FILE
SYSCALL_DEFINE5(kexec_file_load, int, kernel_fd, int, initrd_fd,
		unsigned long, cmdline_len, const char __user *, cmdline_ptr,
		unsigned long, flags)
{
	void __user *ubuf_cmdline = NULL;
	char *kbuf_cmdline = NULL;
	int ret;

	if (!kexec_file_load_permitted())
		return -EPERM;

	if ((flags & KEXEC_FILE_FLAGS) != flags)
		return -EINVAL;

	if (cmdline_len) {
		if (cmdline_len > COMMAND_LINE_SIZE)
			return -EINVAL;

		kbuf_cmdline = memdup_user_nul((const char __user *)cmdline_ptr,
					       cmdline_len);
		if (IS_ERR(kbuf_cmdline))
			return PTR_ERR(kbuf_cmdline);
	}

	ret = kernel_kexec_file_load(kernel_fd, initrd_fd, kbuf_cmdline, flags);

	kfree(kbuf_cmdline);
	return ret;
}
#endif

