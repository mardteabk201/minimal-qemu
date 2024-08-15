#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <linux/errno.h>

#define RAM_SIZE 128000000
#define VCPU_ID 0
#define DPRINTF(fmt, ...) \
    do { fprintf(stderr, fmt, ## __VA_ARGS__); } while (0)
// accel/kvm/kvm-all.c KVMState
struct KVMState {
	int fd;
	int vmfd;
};

// include/sysemu/kvm_int.h KVMSlot
typedef struct KVMSlot {
	uint64_t start_addr;
	uint64_t memory_size;
	void *ram;
	int slot;
	int flags;
} KVMSlot;

// include/qom/cpu.h CPUState
// target/i386/cpu.h X86CPU
typedef struct CPUState {
	int kvm_fd;
	struct kvm_run *kvm_run;
} X86CPU;

struct KVMState *kvm_state;
// target/i386/kvm.c kvm_put_sregs
static void kvm_put_sregs(X86CPU *cpu)
{
	struct kvm_sregs sregs;

	ioctl(cpu->kvm_fd, KVM_GET_SREGS, &sregs);
	sregs.cs.base = 0x1000;
	ioctl(cpu->kvm_fd, KVM_SET_SREGS, &sregs);
}

// target/i386/kvm.c kvm_getput_regs
static void kvm_getput_regs(X86CPU *cpu, int set)
{
	if (set) {
		struct kvm_regs regs;
		regs.rflags = 0x2;

		ioctl(cpu->kvm_fd, KVM_SET_REGS, &regs);
	}
}

// target/i386/kvm.c kvm_arch_put_registers
static void kvm_arch_put_registers(struct CPUState *cpu)
{
	kvm_put_sregs(cpu);
	kvm_getput_regs(cpu, 1);
}

// accel/kvm/kvm-all.c kvm_init_vcpu
static void kvm_init_vcpu(struct CPUState *cpu)
{
	long mmap_size;
	cpu->kvm_fd = ioctl(kvm_state->vmfd, KVM_CREATE_VCPU, VCPU_ID);
	mmap_size = ioctl(kvm_state->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	cpu->kvm_run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
	                    cpu->kvm_fd, 0);
}

// accel/kvm/kvm-all.c kvm_cpu_exec
int kvm_cpu_exec(struct CPUState *cpu)
{
	struct kvm_run *run = cpu->kvm_run;
	kvm_arch_put_registers(cpu);

	for (;;) {
		sleep(1);
		ioctl(cpu->kvm_fd, KVM_RUN, 0);

		switch (run->exit_reason) {
		case KVM_EXIT_IO:
			printf("out port: %d, data: %d\n",
			        run->io.port,
			        * (int *)((char *) run + run->io.data_offset));
			break;

		case KVM_EXIT_MMIO:
			DPRINTF("handle_mmio\n");
			break;

		case KVM_EXIT_IRQ_WINDOW_OPEN:
			DPRINTF("irq_window_open\n");
			break;

		case KVM_EXIT_SHUTDOWN:
			DPRINTF("shutdown\n");
			break;

		case KVM_EXIT_UNKNOWN:
			fprintf(stderr, "KVM: unknown exit, hardware reason  %" PRIx64 "\n",
			        (uint64_t) run->hw.hardware_exit_reason);
			break;

		case KVM_EXIT_INTERNAL_ERROR:
			DPRINTF("internal_error\n");
			break;

		case KVM_EXIT_SYSTEM_EVENT:
			DPRINTF("system_event\n");
			break;

		default:
			DPRINTF("kvm_arch_handle_exit, reason: %d\n", run->exit_reason);
			break;
		}
	}
}

// accel/kvm/kvm-all.c kvm_destroy_vcpu
static void kvm_destroy_vcpu(struct CPUState *cpu)
{
	long mmap_size;
	mmap_size = ioctl(kvm_state->fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	munmap(cpu->kvm_run, mmap_size);
	close(cpu->kvm_fd);
}

// accel/kvm/kvm-all.c kvm_set_user_memory_region
static void kvm_set_user_memory_region(KVMSlot *slot)
{
	struct kvm_userspace_memory_region mem;
	mem.flags = slot->flags;
	mem.slot = slot->slot;
	mem.guest_phys_addr =  slot->start_addr;
	mem.memory_size = slot->memory_size;
	mem.userspace_addr = (unsigned long) slot->ram;
	ioctl(kvm_state->vmfd, KVM_SET_USER_MEMORY_REGION, &mem);
}

/********************************************************************/
/*cpus*/
/********************************************************************/
// cpus.c qemu_kvm_cpu_thread_fn
static void *qemu_kvm_cpu_thread_fn(void *arg)
{
	struct CPUState *cpu = arg;

	kvm_init_vcpu(cpu);
	kvm_cpu_exec(cpu);
	kvm_destroy_vcpu(cpu);

	return NULL;
}

// cpus.c qemu_kvm_start_vcpu
void qemu_kvm_start_vcpu(struct CPUState *vcpu)
{
	pthread_t vcpu_thread;
	pthread_create(&(vcpu_thread), NULL, qemu_kvm_cpu_thread_fn, vcpu);
	pthread_join(vcpu_thread, NULL);
}

// hw/i386/pc_piix.c   DEFINE_I440FX_MACHINE -> pc_init1 ->
// hw/i386/pc.c        pc_cpus_init -> pc_new_cpu ->
// target/i386/cpu.c   x86_cpu_realizefn ->
// cpus.c              qemu_init_vcpu
void qemu_init_vcpu(struct CPUState *cpu)
{
	qemu_kvm_start_vcpu(cpu);
}

/********************************************************************/
/*main*/
/********************************************************************/
// hw/core/loader.c rom_add_file
static void rom_add_file(uint64_t ram_start, uint64_t ram_size, char *file)
{
	int fd = open(file, O_RDONLY);
	int datasize = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	read(fd, (void *)ram_start, datasize);
}

static void mem_init(struct KVMSlot *slot, char *file)
{
	slot->ram = mmap(NULL, slot->memory_size, PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
	                 -1, 0);
	//set vm's mem region
	kvm_set_user_memory_region(slot);

	//load binary to vm's ram
	rom_add_file((uint64_t) slot->ram, slot->memory_size, file);
}

int main(int argc, char **argv)
{
	kvm_state = malloc(sizeof(struct KVMState));
	struct CPUState *vcpu = malloc(sizeof(struct CPUState));
	struct KVMSlot *slot = malloc(sizeof(struct KVMSlot));
	slot->memory_size = RAM_SIZE;
	slot->start_addr = 0;
	slot->slot = 0;

	kvm_state->fd = open("/dev/kvm", O_RDWR);
	kvm_state->vmfd = ioctl(kvm_state->fd, KVM_CREATE_VM, 0);

	mem_init(slot, argv[1]);
	qemu_init_vcpu(vcpu);
}
