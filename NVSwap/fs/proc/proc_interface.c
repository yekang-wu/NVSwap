#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include<linux/module.h>
#include <asm/uaccess.h>
#include <linux/swap.h>
#include <linux/sched.h>
#include <linux/slab.h>

#define MODULE_VERS "1.0"
#define MODULE_NAME "hybrid_interface"

static struct proc_dir_entry *hybrid_file;

struct Hybrid_mesg {
    unsigned int mode;
    pid_t pid;
    unsigned int ratio;
    pid_t pid_2;
    unsigned int ratio_2;
    pid_t pid_3;
    unsigned int ratio_3;
    pid_t pid_4;
    unsigned int ratio_4;
	pid_t pid_5;
    unsigned int ratio_5;
	pid_t pid_6;
    unsigned int ratio_6;
	pid_t pid_7;
    unsigned int ratio_7;
};

struct Hybrid_mesg hybrid_mesg;

static int hybrid_interface_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Control Message:\nMode:%u\n\
<1>\tPID1:%d\tNVM_Proportion1:%u%%\tNVM_SUM1:%lu\tSSD_SUM1:%lu\n\
<2>\tPID2:%d\tNVM_Proportion2:%u%%\tNVM_SUM2:%lu\tSSD_SUM2:%lu\n\
<3>\tPID3:%d\tNVM_Proportion3:%u%%\tNVM_SUM3:%lu\tSSD_SUM3:%lu\n\
<4>\tPID4:%d\tNVM_Proportion4:%u%%\tNVM_SUM4:%lu\tSSD_SUM4:%lu\n\
<5>\tPID5:%d\tNVM_Proportion5:%u%%\tNVM_SUM5:%lu\tSSD_SUM5:%lu\n\
<6>\tPID6:%d\tNVM_Proportion6:%u%%\tNVM_SUM6:%lu\tSSD_SUM6:%lu\n\
<7>\tPID7:%d\tNVM_Proportion7:%u%%\tNVM_SUM7:%lu\tSSD_SUM7:%lu\n",
	           hybrid_mode,
	           hybrid_task_pid,
	           hybrid_task_ratio,
	           hybrid_mem_total,
	           hybrid_ssd_total,
	           hybrid_task_pid_2,
	           hybrid_task_ratio_2,
			   hybrid_mem_total_2,
	           hybrid_ssd_total_2,
	           hybrid_task_pid_3,
	           hybrid_task_ratio_3,
			   hybrid_mem_total_3,
	           hybrid_ssd_total_3,
	           hybrid_task_pid_4,
			   hybrid_task_ratio_4,
			   hybrid_mem_total_4,
	           hybrid_ssd_total_4,
	           hybrid_task_pid_5,
	           hybrid_task_ratio_5,
			   hybrid_mem_total_5,
	           hybrid_ssd_total_5,
			   hybrid_task_pid_6,
	           hybrid_task_ratio_6,
			   hybrid_mem_total_6,
	           hybrid_ssd_total_6,
	           hybrid_task_pid_7,
	           hybrid_task_ratio_7,
			   hybrid_mem_total_7,
	           hybrid_ssd_total_7);

    return 0;
}

static int hybrid_interface_open(struct inode *inode, struct file *file)
{
    return single_open(file, hybrid_interface_show, NULL);
}

static ssize_t hybrid_interface_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char *token[8],*stringp;
    char *tmp_space = kzalloc((count+1), GFP_KERNEL);
    int index;

    for(index=0;index<8;index++){
        token[index]=NULL;
    }
    
    if(!tmp_space)
        return -ENOMEM;
    if(copy_from_user(tmp_space, buf, count))
    {
        kfree(tmp_space);
        return -EFAULT;
    }

    stringp = tmp_space;
    index = 0;
    while (stringp != NULL) {
        token[index] = strsep(&stringp, "#");
        token[index] = strsep(&token[index], "\n");
        index++;
        if(index>7){
            break;
        }
    }
    
    if(simple_strtoull(token[0], NULL, 10)==1){
        hybrid_mesg.mode = 1;
        hybrid_mesg.pid = simple_strtoull(token[1], NULL, 10);
        hybrid_mesg.ratio = simple_strtol(token[2], NULL, 10);
        hybrid_mode = hybrid_mesg.mode;
        hybrid_task_pid = (pid_t)hybrid_mesg.pid;
        hybrid_task_ratio = hybrid_mesg.ratio;
        hybrid_mem_total = 0;
        hybrid_ssd_total = 0;
    } else if(simple_strtoull(token[0], NULL, 10)==2){
        hybrid_mesg.mode = 2;
        hybrid_mesg.pid_2 = simple_strtoull(token[1], NULL, 10);
        hybrid_mesg.ratio_2 = simple_strtol(token[2], NULL, 10);
        hybrid_mode = hybrid_mesg.mode;
        hybrid_task_pid_2 = (pid_t)hybrid_mesg.pid_2;
        hybrid_task_ratio_2 = hybrid_mesg.ratio_2;
        hybrid_mem_total_2 = 0;
        hybrid_ssd_total_2 = 0;
    } else if(simple_strtoull(token[0], NULL, 10)==3){
        hybrid_mesg.mode = 3;
        hybrid_mesg.pid_3 = simple_strtoull(token[1], NULL, 10);
        hybrid_mesg.ratio_3 = simple_strtol(token[2], NULL, 10);
        hybrid_mode = hybrid_mesg.mode;
        hybrid_task_pid_3 = (pid_t)hybrid_mesg.pid_3;
        hybrid_task_ratio_3 = hybrid_mesg.ratio_3;
        hybrid_mem_total_3 = 0;
        hybrid_ssd_total_3 = 0;
    } else if(simple_strtoull(token[0], NULL, 10)==4){
        hybrid_mesg.mode = 4;
        hybrid_mesg.pid_4 = simple_strtoull(token[1], NULL, 10);
        hybrid_mesg.ratio_4 = simple_strtol(token[2], NULL, 10);
        hybrid_mode = hybrid_mesg.mode;
        hybrid_task_pid_4 = (pid_t)hybrid_mesg.pid_4;
        hybrid_task_ratio_4 = hybrid_mesg.ratio_4;
        hybrid_mem_total_4 = 0;
        hybrid_ssd_total_4 = 0;
    } else if(simple_strtoull(token[0], NULL, 10)==5){
        hybrid_mesg.mode = 5;
        hybrid_mesg.pid_5 = simple_strtoull(token[1], NULL, 10);
        hybrid_mesg.ratio_5 = simple_strtol(token[2], NULL, 10);
        hybrid_mode = hybrid_mesg.mode;
        hybrid_task_pid_5 = (pid_t)hybrid_mesg.pid_5;
        hybrid_task_ratio_5 = hybrid_mesg.ratio_5;
        hybrid_mem_total_5 = 0;
        hybrid_ssd_total_5 = 0;
    } else if(simple_strtoull(token[0], NULL, 10)==6){
        hybrid_mesg.mode = 6;
        hybrid_mesg.pid_6 = simple_strtoull(token[1], NULL, 10);
        hybrid_mesg.ratio_6 = simple_strtol(token[2], NULL, 10);
        hybrid_mode = hybrid_mesg.mode;
        hybrid_task_pid_6 = (pid_t)hybrid_mesg.pid_6;
        hybrid_task_ratio_6 = hybrid_mesg.ratio_6;
        hybrid_mem_total_6 = 0;
        hybrid_ssd_total_6 = 0;
    } else if(simple_strtoull(token[0], NULL, 10)==7){
        hybrid_mesg.mode = 7;
        hybrid_mesg.pid_7 = simple_strtoull(token[1], NULL, 10);
        hybrid_mesg.ratio_7 = simple_strtol(token[2], NULL, 10);
        hybrid_mode = hybrid_mesg.mode;
        hybrid_task_pid_7 = (pid_t)hybrid_mesg.pid_7;
        hybrid_task_ratio_7 = hybrid_mesg.ratio_7;
        hybrid_mem_total_7 = 0;
        hybrid_ssd_total_7 = 0;
    }
	
    kfree(tmp_space);

    return count;
}

static const struct file_operations hybrid_interface_fops =
{
    .open		= hybrid_interface_open,
    .read		= seq_read,
    .llseek		= seq_lseek,
    .release		= single_release,
    .write		= hybrid_interface_write,
};

static int __init hybrid_interface_init(void)
{
    hybrid_file = proc_create(MODULE_NAME, 0, NULL, &hybrid_interface_fops);
    hybrid_mesg.mode = 0;
    hybrid_mesg.pid = -1;
    hybrid_mesg.ratio = 0;
    hybrid_mesg.pid_2 = -1;
    hybrid_mesg.ratio_2 = 0;
    hybrid_mesg.pid_3 = -1;
    hybrid_mesg.ratio_3 = 0;
    hybrid_mesg.pid_4 = -1;
    hybrid_mesg.ratio_4 = 0;
	hybrid_mesg.pid_5 = -1;
    hybrid_mesg.ratio_5 = 0;
    hybrid_mesg.pid_6 = -1;
    hybrid_mesg.ratio_6 = 0;
    hybrid_mesg.pid_7 = -1;
    hybrid_mesg.ratio_7 = 0;

    hybrid_mem_total = 0;
    hybrid_ssd_total = 0;
	hybrid_mem_total_2 = 0;
    hybrid_ssd_total_2 = 0;
	hybrid_mem_total_3 = 0;
    hybrid_ssd_total_3 = 0;
	hybrid_mem_total_4 = 0;
    hybrid_ssd_total_4 = 0;
	hybrid_mem_total_5 = 0;
    hybrid_ssd_total_5 = 0;
	hybrid_mem_total_6 = 0;
    hybrid_ssd_total_6 = 0;
	hybrid_mem_total_7 = 0;
    hybrid_ssd_total_7 = 0;

    return 0;
}

static void __exit hybrid_interface_exit(void)
{
    remove_proc_entry(MODULE_NAME, NULL);

    printk(KERN_INFO "%s %s removed\n",
           MODULE_NAME, MODULE_VERS);
}

module_init(hybrid_interface_init);
module_exit(hybrid_interface_exit);

MODULE_AUTHOR("Yekang Wu");
MODULE_DESCRIPTION("Hybrid_Interface Module");
MODULE_LICENSE("GPL");
