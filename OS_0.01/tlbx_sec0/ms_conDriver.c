/*
 * ms_Driver
 * Rewritten by Lyli.
 */

#include <linux/device.h>
#include <linux/enclosure.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/string_helpers.h>
#include <linux/sysfs.h>
#include <linux/ctype.h>

static LIST_HEAD(container_list);
static DEFINE_MUTEX(container_list_lock);

/* Forward declarations for groups used by class and component devices */
static struct attribute *enclosure_class_attrs[];
static const struct attribute_group *enclosure_class_groups[];
static struct attribute *enclosure_component_attrs[];
static const struct attribute_group *enclosure_component_groups[];


static struct class enclosure_class = {
	.name			= "enclosure",
	.dev_release		= NULL, /* release provided via enclosure_release */
	.dev_groups		= enclosure_class_groups,
};

/* find enclosure device by traversing parent chain starting from 'start' */
struct enclosure_device *enclosure_find(struct device *dev,
					struct enclosure_device *start)
{
	struct enclosure_device *edev;

	mutex_lock(&container_list_lock);

	/* If caller provided 'start', drop their reference and prepare iteration */
	if (start)
		put_device(&start->edev);

	edev = list_prepare_entry(start, &container_list, node);

	list_for_each_entry_continue(edev, &container_list, node) {
		struct device *parent = edev->edev.parent;

		while (parent) {
			if (parent == dev) {
				get_device(&edev->edev);
				mutex_unlock(&container_list_lock);
				return edev;
			}
			parent = parent->parent;
		}
	}

	mutex_unlock(&container_list_lock);
	return NULL;
}
EXPORT_SYMBOL_GPL(enclosure_find);

/* iterate all enclosure devices, calling fn(edev, data) for each until error */
int enclosure_for_each_device(int (*fn)(struct enclosure_device *, void *),
			      void *data)
{
	int error = 0;
	struct enclosure_device *edev;

	mutex_lock(&container_list_lock);
	list_for_each_entry(edev, &container_list, node) {
		error = fn(edev, data);
		if (error)
			break;
	}
	mutex_unlock(&container_list_lock);

	return error;
}
EXPORT_SYMBOL_GPL(enclosure_for_each_device);

/* Register a new enclosure device */
struct enclosure_device *
enclosure_register(struct device *dev, const char *name, int components,
                   struct enclosure_component_callbacks *cb)
{
	struct enclosure_device *edev;
	int err, i;

	if (!cb)
		return ERR_PTR(-EINVAL);

	edev = kzalloc(struct_size(edev, component, components), GFP_KERNEL);
	if (!edev)
		return ERR_PTR(-ENOMEM);

	edev->components = components;
	edev->cb = cb;
	edev->edev.class = &enclosure_class;
	edev->edev.parent = get_device(dev);

	/* set device name */
	dev_set_name(&edev->edev, "%s", name);

	err = device_register(&edev->edev);
	if (err) {
		put_device(edev->edev.parent);
		kfree(edev);
		return ERR_PTR(err);
	}

	/* initialize component slots */
	for (i = 0; i < components; i++) {
		edev->component[i].number = -1;
		edev->component[i].slot = -1;
		edev->component[i].power_status = -1;
	}

	mutex_lock(&container_list_lock);
	list_add_tail(&edev->node, &container_list);
	mutex_unlock(&container_list_lock);

	return edev;
}
EXPORT_SYMBOL_GPL(enclosure_register);

/* Null-callback placeholder to avoid calling into freed callbacks */
static struct enclosure_component_callbacks enclosure_null_callbacks = {};

void enclosure_unregister(struct enclosure_device *edev)
{
	int i;

	if (!edev)
		return;

	/* prevent any future callbacks immediately */
	edev->cb = &enclosure_null_callbacks;

	/* detach from global list */
	mutex_lock(&container_list_lock);
	list_del_init(&edev->node);
	mutex_unlock(&container_list_lock);

	/* unregister all associated components */
	for (i = 0; i < edev->components; i++) {
		struct enclosure_component *c = &edev->component[i];

		if (!c)
			continue;

		/* skip unused / uninitialized slots */
		if (c->number < 0)
			continue;

		/* remove sysfs links before unregistration (new safety step) */
		enclosure_remove_links(c);

		/* unregister the actual component device */
		device_unregister(&c->cdev);

		/* drop its kobject reference */
		put_device(&c->cdev);
	}

	/* unregister the enclosure device itself */
	device_unregister(&edev->edev);

	/* drop enclosure device reference */
	put_device(&edev->edev);
}
EXPORT_SYMBOL_GPL(enclosure_unregister);


/* helper to create a stable link name: "enclosure_device:<devname>" */
#define ENCLOSURE_NAME_SIZE	64
#define COMPONENT_NAME_SIZE	64

static void enclosure_link_name(struct enclosure_component *cdev, char *name)
{
	const char *dname = dev_name(&cdev->cdev);

	snprintf(name, ENCLOSURE_NAME_SIZE,
		 "enclosure_device:%s", dname ? dname : "unknown");
}

/*
 * Remove all bidirectional sysfs links for a component.
 * Now includes:
 * - stronger NULL checks,
 * - ensures links are removed only when present,
 * - cleans up both ways symmetrically.
 */
static void enclosure_remove_links(struct enclosure_component *cdev)
{
	char name[ENCLOSURE_NAME_SIZE];

	if (!cdev)
		return;

	enclosure_link_name(cdev, name);

	/* remove device -> component link */
	if (cdev->dev && cdev->dev->kobj.sd)
		sysfs_remove_link(&cdev->dev->kobj, name);

	/* remove component -> device link */
	if (cdev->cdev.kobj.sd)
		sysfs_remove_link(&cdev->cdev.kobj, "device");
}

/*
 *
 * Improvements:
 * - complete rollback on partial failure
 * - consistent naming
 * - stronger null guards
 */
static int enclosure_add_links(struct enclosure_component *cdev)
{
	int err;
	char name[ENCLOSURE_NAME_SIZE];

	if (!cdev || !cdev->dev)
		return -EINVAL;

	/* component -> device */
	err = sysfs_create_link(&cdev->cdev.kobj, &cdev->dev->kobj, "device");
	if (err)
		return err;

	/* device -> component */
	enclosure_link_name(cdev, name);
	err = sysfs_create_link(&cdev->dev->kobj, &cdev->cdev.kobj, name);
	if (err) {
		/* rollback */
		sysfs_remove_link(&cdev->cdev.kobj, "device");
		return err;
	}

	return 0;
}


/* release callback for enclosure device */
static void enclosure_release(struct device *cdev)
{
	struct enclosure_device *edev = to_enclosure_device(cdev);

	/* drop parent device reference held during registration */
	put_device(cdev->parent);
	kfree(edev);
}

/* release callback for enclosure component device */
static void enclosure_component_release(struct device *dev)
{
	struct enclosure_component *cdev = to_enclosure_component(dev);

	if (cdev->dev) {
		enclosure_remove_links(cdev);
		put_device(cdev->dev);
	}

	/* drop parent reference */
	put_device(dev->parent);
}

/* find component in enclosure by name */
static struct enclosure_component *
enclosure_component_find_by_name(struct enclosure_device *edev,
				const char *name)
{
	int i;
	const char *cname;
	struct enclosure_component *ecomp;

	if (!edev || !name || name[0] == '\0')
		return NULL;

	for (i = 0; i < edev->components; i++) {
		ecomp = &edev->component[i];
		cname = dev_name(&ecomp->cdev);
		if (ecomp->number != -1 &&
		    cname && cname[0] &&
		    strcmp(cname, name) == 0)
			return ecomp;
	}

	return NULL;
}

/* allocate and initialize an enclosure_component structure */
struct enclosure_component *
enclosure_component_alloc(struct enclosure_device *edev,
			  unsigned int number,
			  enum enclosure_component_type type,
			  const char *name)
{
	struct enclosure_component *ecomp;
	struct device *cdev;
	int i;
	char newname[COMPONENT_NAME_SIZE];

	if (!edev || number >= edev->components)
		return ERR_PTR(-EINVAL);

	ecomp = &edev->component[number];

	if (ecomp->number != -1)
		return ERR_PTR(-EINVAL);

	ecomp->type = type;
	ecomp->number = number;

	cdev = &ecomp->cdev;
	cdev->parent = get_device(&edev->edev);

	/* choose a unique name if requested */
	if (name && name[0]) {
		i = 1;
		snprintf(newname, COMPONENT_NAME_SIZE, "%s", name);
		while (enclosure_component_find_by_name(edev, newname))
			snprintf(newname, COMPONENT_NAME_SIZE, "%s-%i", name, i++);
		dev_set_name(cdev, "%s", newname);
	} else {
		dev_set_name(cdev, "%u", number);
	}

	cdev->release = enclosure_component_release;
	cdev->groups = enclosure_component_groups;

	return ecomp;
}
EXPORT_SYMBOL_GPL(enclosure_component_alloc);

/* register a previously allocated component device */
int enclosure_component_register(struct enclosure_component *ecomp)
{
	struct device *cdev;
	int err;

	if (!ecomp)
		return -EINVAL;

	cdev = &ecomp->cdev;
	err = device_register(cdev);
	if (err) {
		ecomp->number = -1;
		put_device(cdev);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(enclosure_component_register);

/* add a child device to an enclosure component (and create sysfs links) */
int enclosure_add_device(struct enclosure_device *edev, int component,
			 struct device *dev)
{
	struct enclosure_component *cdev;
	int err;

	if (!edev || component >= edev->components)
		return -EINVAL;

	cdev = &edev->component[component];

	/* already present? */
	if (cdev->dev == dev)
		return -EEXIST;

	/* if previously bound, remove that binding first */
	if (cdev->dev) {
		enclosure_remove_links(cdev);
		put_device(cdev->dev);
	}

	cdev->dev = get_device(dev);
	err = enclosure_add_links(cdev);
	if (err) {
		put_device(cdev->dev);
		cdev->dev = NULL;
	}

	return err;
}
EXPORT_SYMBOL_GPL(enclosure_add_device);

/* remove a device previously added to an enclosure component */
int enclosure_remove_device(struct enclosure_device *edev, struct device *dev)
{
	struct enclosure_component *cdev;
	int i;

	if (!edev || !dev)
		return -EINVAL;

	for (i = 0; i < edev->components; i++) {
		cdev = &edev->component[i];
		if (cdev->dev == dev) {
			enclosure_remove_links(cdev);
			put_device(dev);
			cdev->dev = NULL;
			return 0;
		}
	}
	return -ENODEV;
}
EXPORT_SYMBOL_GPL(enclosure_remove_device);

/* sysfs attribute: components (read-only) */
static ssize_t components_show(struct device *cdev,
			       struct device_attribute *attr, char *buf)
{
	struct enclosure_device *edev = to_enclosure_device(cdev);

	return sysfs_emit(buf, "%d\n", edev->components);
}
static DEVICE_ATTR_RO(components);

/* sysfs attribute: id (read-only, delegated to callback) */
static ssize_t id_show(struct device *cdev,
		       struct device_attribute *attr,
		       char *buf)
{
	struct enclosure_device *edev = to_enclosure_device(cdev);

	if (edev->cb && edev->cb->show_id)
		return edev->cb->show_id(edev, buf);
	return -EINVAL;
}
static DEVICE_ATTR_RO(id);

/* class attributes for enclosure devices */
static struct attribute *enclosure_class_attrs[] = {
	&dev_attr_components.attr,
	&dev_attr_id.attr,
	NULL,
};
ATTRIBUTE_GROUPS(enclosure_class);

/* define the class properly with the release callback assigned */
static void enclosure_class_release(struct device *dev) { /* nop */ }

/* mapping for component status strings */
static const char *const enclosure_status[] = {
	[ENCLOSURE_STATUS_UNSUPPORTED] = "unsupported",
	[ENCLOSURE_STATUS_OK] = "OK",
	[ENCLOSURE_STATUS_CRITICAL] = "critical",
	[ENCLOSURE_STATUS_NON_CRITICAL] = "non-critical",
	[ENCLOSURE_STATUS_UNRECOVERABLE] = "unrecoverable",
	[ENCLOSURE_STATUS_NOT_INSTALLED] = "not installed",
	[ENCLOSURE_STATUS_UNKNOWN] = "unknown",
	[ENCLOSURE_STATUS_UNAVAILABLE] = "unavailable",
	[ENCLOSURE_STATUS_MAX] = NULL,
};

static const char *const enclosure_type[] = {
	[ENCLOSURE_COMPONENT_DEVICE] = "device",
	[ENCLOSURE_COMPONENT_ARRAY_DEVICE] = "array device",
};

/* component attribute: fault */
static ssize_t get_component_fault(struct device *cdev,
				   struct device_attribute *attr, char *buf)
{
	struct enclosure_device *edev = to_enclosure_device(cdev->parent);
	struct enclosure_component *ecomp = to_enclosure_component(cdev);

	if (edev->cb && edev->cb->get_fault)
		edev->cb->get_fault(edev, ecomp);
	return sysfs_emit(buf, "%d\n", ecomp->fault);
}

static ssize_t set_component_fault(struct device *cdev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct enclosure_device *edev = to_enclosure_device(cdev->parent);
	struct enclosure_component *ecomp = to_enclosure_component(cdev);
	unsigned long val;

	if (!edev->cb || !edev->cb->set_fault)
		return -EOPNOTSUPP;

	val = simple_strtoul(buf, NULL, 0);
	edev->cb->set_fault(edev, ecomp, (int)val);

	return count;
}

/* component attribute: status */
static ssize_t get_component_status(struct device *cdev,
				    struct device_attribute *attr, char *buf)
{
	struct enclosure_device *edev = to_enclosure_device(cdev->parent);
	struct enclosure_component *ecomp = to_enclosure_component(cdev);

	if (edev->cb && edev->cb->get_status)
		edev->cb->get_status(edev, ecomp);
	return sysfs_emit(buf, "%s\n", enclosure_status[ecomp->status]);
}

static ssize_t set_component_status(struct device *cdev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct enclosure_device *edev = to_enclosure_device(cdev->parent);
	struct enclosure_component *ecomp = to_enclosure_component(cdev);
	int i;

	for (i = 0; enclosure_status[i]; i++) {
		size_t len = strlen(enclosure_status[i]);

		if (strncmp(buf, enclosure_status[i], len) == 0 &&
		    (buf[len] == '\n' || buf[len] == '\0'))
			break;
	}

	if (enclosure_status[i] && edev->cb && edev->cb->set_status) {
		edev->cb->set_status(edev, ecomp, i);
		return count;
	}

	return -EINVAL;
}

/* component attribute: active */
static ssize_t get_component_active(struct device *cdev,
				    struct device_attribute *attr, char *buf)
{
	struct enclosure_device *edev = to_enclosure_device(cdev->parent);
	struct enclosure_component *ecomp = to_enclosure_component(cdev);

	if (edev->cb && edev->cb->get_active)
		edev->cb->get_active(edev, ecomp);
	return sysfs_emit(buf, "%d\n", ecomp->active);
}

/* component attribute: locate (get only, set omitted in many implementations) */
static ssize_t get_component_locate(struct device *cdev,
				    struct device_attribute *attr, char *buf)
{
	struct enclosure_device *edev = to_enclosure_device(cdev->parent);
	struct enclosure_component *ecomp = to_enclosure_component(cdev);

	if (edev->cb && edev->cb->get_locate)
		edev->cb->get_locate(edev, ecomp);
	return sysfs_emit(buf, "%d\n", ecomp->locate);
}

/* component attribute: power_status */
static ssize_t get_component_power_status(struct device *cdev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct enclosure_device *edev = to_enclosure_device(cdev->parent);
	struct enclosure_component *ecomp = to_enclosure_component(cdev);

	if (edev->cb && edev->cb->get_power_status)
		edev->cb->get_power_status(edev, ecomp);

	/* If still uninitialized, the callback failed or does not exist. */
	if (ecomp->power_status == -1)
		return (edev->cb && edev->cb->get_power_status) ? -EIO : -ENOTTY;

	return sysfs_emit(buf, "%s\n", str_on_off(ecomp->power_status));
}

static ssize_t set_component_power_status(struct device *cdev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	struct enclosure_device *edev = to_enclosure_device(cdev->parent);
	struct enclosure_component *ecomp = to_enclosure_component(cdev);
	int val, ret;

	/* trim leading whitespace */
	while (isspace(*buf))
		buf++;

	if (sysfs_streq(buf, "on"))
		val = 1;
	else if (sysfs_streq(buf, "off"))
		val = 0;
	else
		return -EINVAL;

	if (!edev->cb || !edev->cb->set_power_status)
		return -EOPNOTSUPP;

	ret = edev->cb->set_power_status(edev, ecomp, val);
	if (ret)
		return ret;

	return count;
}

/* component attribute: type (read-only) */
static ssize_t get_component_type(struct device *cdev,
				  struct device_attribute *attr, char *buf)
{
	struct enclosure_component *ecomp = to_enclosure_component(cdev);

	return sysfs_emit(buf, "%s\n", enclosure_type[ecomp->type]);
}

/* component attribute: slot (read-only) */
static ssize_t get_component_slot(struct device *cdev,
				  struct device_attribute *attr, char *buf)
{
	struct enclosure_component *ecomp = to_enclosure_component(cdev);
	int slot;

	/* if the enclosure does not override then use 'number' as a stand-in */
	if (ecomp->slot >= 0)
		slot = ecomp->slot;
	else
		slot = ecomp->number;

	return sysfs_emit(buf, "%d\n", slot);
}

/* Declare component device attributes */
static DEVICE_ATTR(fault, S_IRUGO | S_IWUSR, get_component_fault,
		    set_component_fault);
static DEVICE_ATTR(status, S_IRUGO | S_IWUSR, get_component_status,
		   set_component_status);
static DEVICE_ATTR(active, S_IRUGO | S_IWUSR, get_component_active,
		   NULL);
static DEVICE_ATTR(locate, S_IRUGO | S_IWUSR, get_component_locate,
		   NULL);
static DEVICE_ATTR(power_status, S_IRUGO | S_IWUSR, get_component_power_status,
		   set_component_power_status);
static DEVICE_ATTR(type, S_IRUGO, get_component_type, NULL);
static DEVICE_ATTR(slot, S_IRUGO, get_component_slot, NULL);

/* array of attributes for component devices */
static struct attribute *enclosure_component_attrs[] = {
	&dev_attr_fault.attr,
	&dev_attr_status.attr,
	&dev_attr_active.attr,
	&dev_attr_locate.attr,
	&dev_attr_power_status.attr,
	&dev_attr_type.attr,
	&dev_attr_slot.attr,
	NULL
};
ATTRIBUTE_GROUPS(enclosure_component);

/* groups for class and component devices (populated via ATTRIBUTE_GROUPS macros) */
static const struct attribute_group *enclosure_class_groups[] = {
	&enclosure_class_group,
	NULL,
};

static const struct attribute_group *enclosure_component_groups[] = {
	&enclosure_component_group,
	NULL,
};

/* register/unregister the enclosure class at module load/unload */
static int __init enclosure_init(void)
{
	/* assign release callback for enclosure devices */
	enclosure_class.dev_release = enclosure_release;

	return class_register(&enclosure_class);
}

static void __exit enclosure_exit(void)
{
	class_unregister(&enclosure_class);
}

module_init(enclosure_init);
module_exit(enclosure_exit);

MODULE_AUTHOR("Lyliana");
MODULE_DESCRIPTION("Custom Enclosure Services");
MODULE_LICENSE("GPL");
