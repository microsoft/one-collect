#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/perf_event.h>
#include <asm/perf_regs.h>
#include <sys/syscall.h>
#include <sys/mman.h>

static long perf_event_open(
    struct perf_event_attr *pe, 
    pid_t pid,
    int cpu, 
    int group_fd, 
    unsigned long flags)
{
   return syscall(
       SYS_perf_event_open, 
       pe, 
       pid, 
       cpu,
       group_fd, 
       flags);
}

void capture(int pid)
{
    struct perf_event_attr pe = {0};
    struct perf_event_mmap_page *page;
    struct perf_event_header *header;
    int fd;
    __u64 pageSize = sysconf(_SC_PAGE_SIZE);

    pe.type = PERF_TYPE_SOFTWARE;
    pe.size = PERF_ATTR_SIZE_VER4;
    pe.config = PERF_COUNT_SW_CPU_CLOCK;
    pe.sample_freq = 1000;
    pe.sample_type = PERF_SAMPLE_REGS_USER |
                     PERF_SAMPLE_STACK_USER;
    pe.sample_regs_user = (1 << PERF_REG_X86_IP) |
                          (1 << PERF_REG_X86_SP) |
                          (1 << PERF_REG_X86_BP);
    pe.sample_stack_user = 4096;
    pe.precise_ip = 3;
    pe.exclude_idle = 1;
    pe.exclude_hv = 1;

    printf("Capturing %d...\n", pid);

    fd = perf_event_open(&pe, pid, -1, -1, 0);

    if (fd == -1) {
        printf("Error: %d\n", errno);
        exit(1);
    }

    page = mmap(
        NULL, pageSize * 9, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0);

    if (page == MAP_FAILED) {
        printf("Error: %d\n", errno);
        exit(1);
    }

    printf("Waiting for a sample...\n");
    while (page->data_head == 0) {
        usleep(15);
    }

    header = ((void *)page) + page->data_offset;

    if (header->type == PERF_RECORD_SAMPLE) {
        __u64 *data = (__u64 *)(header + 1);
        __u64 abi = *data++;

        if (abi != 2) {
            printf("Error: Odd ABI\n");
            exit(1);
        }

        __u64 rbp = *data++;
        __u64 rsp = *data++;
        __u64 rip = *data++;
        __u64 size = *data++;

        if (rbp == 0) {
            printf("Error: RBP is corrupt (bad sample), try again\n");
            exit(1);
        }

        printf("RBP=0x%llx, RSP=0x%llx, RIP=0x%llx\n",
            rbp, rsp, rip);

        FILE *fp = fopen("stack.data", "w");

        if (fp == NULL) {
            printf("Error: Unable to open/create stack.data\n");
            exit(1);
        }

        fwrite(data, 1, size, fp);
        fclose(fp);
    } else {
        printf("Error: Type was %d\n", header->type);
        exit(1);
    }
}

void __attribute__ ((noinline)) frame1(void *a)
{
    int i, sum = 0;
    int pid = fork();

    if (pid != 0) {
        capture(pid);
        return;
    }

    for (i = 0; i < 1e9; ++i) {
        sum += i;
    }

    exit(0);
}

void __attribute__ ((noinline)) frame2(void *a)
{
    char stuff[128] = {0};
    memset(stuff, '2', sizeof(stuff));
    frame1(a);
}

void __attribute__ ((noinline)) frame3(void *a)
{
    char stuff[33] = {0};
    memset(stuff, '3', sizeof(stuff));
    frame2(a);
}

int dump_range()
{
    FILE *fp;
    char buf[1024];
    char name[1024];

    ssize_t len = readlink("/proc/self/exe", name, sizeof(name)-1);
    name[len] = 0;

    fp = fopen("/proc/self/maps", "r");

    if (fp == NULL) {
        printf("Oops, cannot get maps");
        return -1;
    }

    printf("Use Map:\n");
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, name)) {
            printf("%s", buf);
        }
    }

    fclose(fp);

    return 0;
}

int main()
{
    int a = 0;
    char z = 'z';
    frame3(&a);
    return dump_range();
}
