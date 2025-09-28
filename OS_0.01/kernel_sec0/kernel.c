#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/security.h>
#include <linux/kexec.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "kernel_h.h"

static int kimage_alloc_init(struct kimage **rimage, unsigned long entry,
			     unsigned long nr_segments,
			     struct kexec_segment *segments,
			     unsigned long flags)
{
	int ret;
	struct kimage *image;
	bool kexec_on_panic = flags & KEXEC_ON_CRASH;

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		/* Verify we have a valid entry point */
		if ((entry < phys_to_boot_phys(crashk_res.start)) ||
		    (entry > phys_to_boot_phys(crashk_res.end)))
			return -EADDRNOTAVAIL;
	}
#endif

	/* Allocate and initialize a controlling structure */
	image = do_kimage_alloc_init();
	if (!image)
		return -ENOMEM;

	image->start = entry;
	image->nr_segments = nr_segments;
	memcpy(image->segment, segments, nr_segments * sizeof(*segments));

#ifdef CONFIG_CRASH_DUMP
	if (kexec_on_panic) {
		
		image->control_page = crashk_res.start;
		image->type = KEXEC_TYPE_CRASH;
	}
#endif

	ret = sanity_check_segment_list(image);
	if (ret)
		goto out_free_image;


	ret = -ENOMEM;
	image->control_code_page = kimage_alloc_control_pages(image,
					   get_order(KEXEC_CONTROL_PAGE_SIZE));
	if (!image->control_code_page) {
		pr_err("Could not allocate control_code_buffer\n");
		goto out_free_image;
	}

	if (!kexec_on_panic) {
		image->swap_page = kimage_alloc_control_pages(image, 0);
		if (!image->swap_page) {
			pr_err("Could not allocate swap buffer\n");
			goto out_free_control_pages;
		}
	}

	*rimage = image;
	return 0;
out_free_control_pages:
	kimage_free_page_list(&image->control_pages);
out_free_image:
	kfree(image);
	return ret;
}

static int do_kexec_load(unsigned long entry, unsigned long nr_segments,
		struct kexec_segment *segments, unsigned long flags)
{
	struct kimage **dest_image, *image;
	unsigned long i;
	int ret;


	if (!kexec_trylock())
		return -EBUSY;

#ifdef CONFIG_CRASH_DUMP
	if (flags & KEXEC_ON_CRASH) {
		dest_image = &kexec_crash_image;
		if (kexec_crash_image)
			arch_kexec_unprotect_crashkres();
	} else
#endif
		dest_image = &kexec_image;

	if (nr_segments == 0) {
		/* Uninstall image */
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
		goto out;


	ret = kimage_crash_copy_vmcoreinfo(image);
	if (ret)
		goto out;

	for (i = 0; i < nr_segments; i++) {
		ret = kimage_load_segment(image, i);
		if (ret)
			goto out;
	}

	kimage_terminate(image);

	ret = machine_kexec_post_load(image);
	if (ret)
		goto out;

	image = xchg(dest_image, image);

out:
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
	int image_type = (flags & KEXEC_ON_CRASH) ?
			 KEXEC_TYPE_CRASH : KEXEC_TYPE_DEFAULT;
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

SYSCALL_DEFINE4(kexec_load, unsigned long, entry, unsigned long, nr_segments,
		struct kexec_segment __user *, segments, unsigned long, flags)
{
	struct kexec_segment *ksegments;
	unsigned long result;

	result = kexec_load_check(nr_segments, flags);
	if (result)
		return result;


	if (((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH) &&
		((flags & KEXEC_ARCH_MASK) != KEXEC_ARCH_DEFAULT))
		return -EINVAL;

	ksegments = memdup_array_user(segments, nr_segments, sizeof(ksegments[0]));
	if (IS_ERR(ksegments))
		return PTR_ERR(ksegments);

	result = do_kexec_load(entry, nr_segments, ksegments, flags);
	kfree(ksegments);

	return result;
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE4(kexec_load, compat_ulong_t, entry,
		       compat_ulong_t, nr_segments,
		       struct compat_kexec_segment __user *, segments,
		       compat_ulong_t, flags)
{
	struct compat_kexec_segment in;
	struct kexec_segment *ksegments;
	unsigned long i, result;

	result = kexec_load_check(nr_segments, flags);
	if (result)
		return result;
	if ((flags & KEXEC_ARCH_MASK) == KEXEC_ARCH_DEFAULT)
		return -EINVAL;

	ksegments = kmalloc_array(nr_segments, sizeof(ksegments[0]),
			GFP_KERNEL);
	if (!ksegments)
		return -ENOMEM;

	for (i = 0; i < nr_segments; i++) {
		result = copy_from_user(&in, &segments[i], sizeof(in));
		if (result)
			goto fail;

		ksegments[i].buf   = compat_ptr(in.buf);
		ksegments[i].bufsz = in.bufsz;
		ksegments[i].mem   = in.mem;
		ksegments[i].memsz = in.memsz;
	}

	result = do_kexec_load(entry, nr_segments, ksegments, flags);

fail:
	kfree(ksegments);
	return result;
}
#endif

#ifdef CONFIG_KEXEC_FILE
/*
 * kexec_file_load:
 *  System call to load a new kernel image using file descriptors instead of
 *  user-provided memory segments. This is a safer and more modern interface
 *  compared to the legacy kexec_load().
 *
 *  Arguments:
 *    @kernel_fd   - file descriptor for the new kernel image
 *    @initrd_fd   - optional initrd image file descriptor (or -1 if none)
 *    @cmdline_len - length of command line string
 *    @cmdline_ptr - user pointer to command line string
 *    @flags       - kexec flags (must be validated)
 */
SYSCALL_DEFINE5(kexec_file_load, int, kernel_fd, int, initrd_fd,
                unsigned long, cmdline_len, const char __user *, cmdline_ptr,
                unsigned long, flags)
{
    void __user *ubuf_cmdline;
    char *kbuf_cmdline;
    int ret;

    /* Check whether this syscall is permitted under current security policy */
    if (!kexec_file_load_permitted())
        return -EPERM;

    /* Validate flags: reject unsupported bits */
    if ((flags & KEXEC_FILE_FLAGS) != flags)
        return -EINVAL;

    /* Copy kernel command line from userspace, if provided */
    if (cmdline_len) {
        if (cmdline_len > COMMAND_LINE_SIZE)
            return -EINVAL;

        ubuf_cmdline = (void __user *)cmdline_ptr;
        kbuf_cmdline = memdup_user_nul(ubuf_cmdline, cmdline_len);
        if (IS_ERR(kbuf_cmdline))
            return PTR_ERR(kbuf_cmdline);
    } else {
        kbuf_cmdline = NULL;
    }

    /* Delegate actual image loading to kernel helper */
    ret = kernel_kexec_file_load(kernel_fd, initrd_fd, kbuf_cmdline, flags);

    kfree(kbuf_cmdline);
    return ret;
}
#endif /* CONFIG_KEXEC_FILE */
