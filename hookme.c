#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>

//include for the read/write semaphore
#include <linux/rwsem.h>

//needed for set_memory_rw
#include <asm/cacheflush.h>

#include "offsets.h"


#include <linux/highmem.h>
#include <asm/unistd.h>

//These two definitions and the one for set_addr_rw and ro are from
// http://stackoverflow.com/questions/2103315/linux-kernel-system-call-hooking-example
#define GPF_DISABLE() write_cr0(read_cr0() & (~0x10000))
#define GPF_ENABLE() write_cr0(read_cr0() | 0x10000)

//Access Control Matrix Data structure 
typedef struct 
{
	unsigned int _uid;
	char* _filename;
	bool _r;
	bool _w;
	bool _r_kw; //Read except keyword
	bool _w_kw; //Write with keyword
	char* _kw_r; //keyword associated with read operation
	char* _kw_w; //keyword associated with write operation
} ACL;
ACL _acl[10]; //Access control maxtrix with maximum 10 rules
unsigned int _size = 0;//Number of existed rules
char* _curFilename = NULL;

/**************************/
/*String related functions*/
//Extract filename from the path
char* getName(char* path)
{
	char* name;
	return name;
}





//seed@ubuntu:~/Downloads/hw5$ sudo grep sys_call_table /proc/kallsyms
//c1513160 R sys_call_table
static long* sys_call_table = (long*)SYS_CALL_TABLE_ADDR;

typedef asmlinkage long (* sys_open_func_ptr)(const char __user* filename, int flags, int mode);

sys_open_func_ptr sys_open_orig = NULL;


typedef asmlinkage long (* sys_read_func_ptr)(unsigned int fd, char __user* buf, size_t count);
typedef asmlinkage long (* sys_write_func_ptr)(unsigned int fd, char __user* buf, size_t count);

sys_read_func_ptr sys_read_orig = NULL;
sys_write_func_ptr sys_write_orig = NULL;


static struct rw_semaphore myrwsema; 

void initACL(char* buff)
{
	//buff is content of the hookme_rules.txt file
	//Initilize the  here
	//This function is called by sys_read, when the hookme_rules.txt file is opened
}

ACL* getRule(int uid, char* filename)
{
	ACL* acl = NULL;
	int i;
	for(i=0; i<_size; i++)
	{
		//Check filename
		if (strcmp(filename, _acl[i]._filename) == 0)
			//Check user id
			if (_acl[i]._uid == uid)
			{
				acl = &_acl[i];
				i = 11; //Found & break the loop
			}
	}
	return acl;
}

//don't forget the asmlinkage declaration. This is a particular calling convention
asmlinkage long my_sys_open(const char __user* filename, int flags, int mode)
{
	long ret = 0;

	//add in another reader to the semaphore
	down_read(&myrwsema);

	ret = sys_open_orig(filename, flags, mode);

	_curFilename = getname(filename); //this is needed because filename is in userspace
	if (strcmp(_curFilename, "/home/kien/Desktop/infosec/Assignment5-KienPham/hookme_rules.txt") == 0)
		printk(KERN_INFO "The file [%s] is being opened\n", _curFilename);

	//Get current user id
	int uid = current_uid();
	ACL* acl = getRule(uid, _curFilename);//Get the entry that corresponds to (uid, _curFilename) if it exists

	//uid and filename are in the ACL
	//Check permission
	if (acl != NULL)
	{
		switch(mode)
		{
			case 0://Read mode
				if (acl->_r == false)
				{
					printk(KERN_INFO "User %d is not allowed to open the file %s \n", uid, filename);
					ret = -1;//Deny access
				}
				break;
			default:
				break;
		}
	}

	//release the reader lock (or one of them) right before the return
	// to limit the possibility of unloading the module
	// when there is still code to be executed
	up_read(&myrwsema);
	return (ret);
}

asmlinkage long my_sys_read(unsigned int fd, char __user* buf, size_t count)
{
	long ret = 0;
	down_read(&myrwsema);

	if (strcmp(_curFilename, "/home/kien/Desktop/infosec/Assignment5-KienPham/hookme_rules.txt") == 0)
		printk(KERN_INFO "File content before calling read_sys: %s \n", buf);

	ret = sys_read_orig(fd, buf, count);

	if (strcmp(_curFilename, "/home/kien/Desktop/infosec/Assignment5-KienPham/hookme_rules.txt") == 0)
		printk(KERN_INFO "File content after calling read_sys: %s \n", buf);

	//Check whether user have permission to read the file
	int uid = current_uid();
	ACL *acl = getRule(uid, _curFilename);
	if (strcmp(_curFilename, "hookme_rules.txt"))
		initACL(buf);
	if (acl != NULL)
	{
		if (acl->_r == false && acl->_r_kw == false)
		{
			printk(KERN_INFO "User %d is not allowed to open the file %s \n", uid, _curFilename);
			ret = -1;//Deny access
		}
		else if (acl->_r_kw == true)
		{
			char* keyword = acl->_kw_r;
			//Modify buff based on keyword here

		}
	}

	up_read(&myrwsema);
	return (ret);
}

asmlinkage long my_sys_write(unsigned int fd, char __user* buf, size_t count)
{
	long ret = 0;
	down_read(&myrwsema);

	ret = sys_write_orig(fd, buf, count);
	int uid = current_uid();
	ACL *acl = getRule(uid, _curFilename);
	if (acl != NULL)
	{
	}
	if (strcmp(_curFilename, "/home/kien/Desktop/infosec/Assignment5-KienPham/hookme_rules.txt") == 0)
		printk(KERN_INFO "File content has been written \n");
	up_read(&myrwsema);
	return (ret);
}

int set_addr_rw(unsigned long addr)
{
	unsigned int level; 
	pte_t* pte = lookup_address(addr, &level);
	if (pte == NULL)
	{
		return (-1);
	}

	pte->pte |= _PAGE_RW;

	return (0);
}

int set_addr_ro(unsigned long addr)
{
	unsigned int level; 
	pte_t* pte = lookup_address(addr, &level);
	if (pte == NULL)
	{
		return (-1);
	}

	pte->pte = pte->pte & ~_PAGE_RW;

	return (0);
}

int init_module(void)
{
	//sys_close is exported, so we can use it to make sure we have the
	// right address for sys_call_table
	//printk(KERN_INFO "sys_close is at [%p] == [%p]?.\n", sys_call_table[__NR_close], &sys_close);
	if (sys_call_table[__NR_close] != (long)(&sys_close))
	{
		printk(KERN_INFO "Seems like we don't have the right addresses [0x%08lx] vs [%p]\n", sys_call_table[__NR_close], &sys_close);
		return (-1); 
	}

	//initialize the rw semahore
	init_rwsem(&myrwsema);

	//make sure the table is writable
	set_addr_rw( (unsigned long)sys_call_table);
	//GPF_DISABLE();

	printk(KERN_INFO "Saving sys_open @ [0x%08lx]\n", sys_call_table[__NR_open]);
	sys_open_orig = (sys_open_func_ptr)(sys_call_table[__NR_open]);
	sys_call_table[__NR_open] = (long)&my_sys_open;

	printk(KERN_INFO "Saving sys_read @ [0x%08lx]\n", sys_call_table[__NR_read]);
	sys_read_orig = (sys_read_func_ptr)(sys_call_table[__NR_read]);
	sys_call_table[__NR_read] = (long)&my_sys_read;

	printk(KERN_INFO "Saving sys_write @ [0x%08lx]\n", sys_call_table[__NR_write]);
	sys_write_orig = (sys_write_func_ptr)(sys_call_table[__NR_write]);
	sys_call_table[__NR_write] = (long)&my_sys_write;

	set_addr_ro( (unsigned long)sys_call_table);
	//GPF_ENABLE();

	return (0);
}

void cleanup_module(void)
{
	if (sys_open_orig != NULL)
	{
		set_addr_rw( (unsigned long)sys_call_table);
		printk(KERN_INFO "Restoring sys_open\n");
		sys_call_table[__NR_open] = (long)sys_open_orig; 
		set_addr_ro( (unsigned long)sys_call_table);
	}

	if (sys_read_orig != NULL)
	{
		set_addr_rw( (unsigned long)sys_call_table);
		printk(KERN_INFO "Restoring sys_read\n");
		sys_call_table[__NR_read] = (long)sys_read_orig; 
		set_addr_ro( (unsigned long)sys_call_table);
	}

	if (sys_write_orig != NULL)
	{
		set_addr_rw( (unsigned long)sys_call_table);
		printk(KERN_INFO "Restoring sys_write\n");
		sys_call_table[__NR_write] = (long)sys_write_orig;
		set_addr_ro( (unsigned long)sys_call_table);
	}


	//after the system call table has been restored - we will need to wait
	printk(KERN_INFO "Checking the semaphore as a write ...\n");
	down_write(&myrwsema);

	printk(KERN_INFO "Have the write lock - meaning all read locks have been released\n");
	printk(KERN_INFO " So it is now safe to remove the module\n");
}

MODULE_LICENSE("GPL");
//module_init(init_module);
//module_exit(cleanup_module);
