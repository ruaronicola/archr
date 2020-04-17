#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::string;
using std::endl;

static std::ofstream TraceFile;
static ADDRINT img_low, img_high;
static bool after_ld = false;
static int last_syscall_num;
static bool last_read_empty = false;

/* syscalls ============================================================ */
# ifdef __amd64__
static const string SYSCALLS[] = {"FS::read", "FS::write", "FS::open", "FS::close", "FS::stat", "FS::fstat", "FS::lstat", "FS::poll", "FS::lseek", "KERNEL::mmap", "MM::mprotect", "MM::munmap", "MM::brk", "KERNEL::rt_sigaction", "KERNEL::rt_sigprocmask", "KERNEL::rt_sigreturn", "FS::ioctl", "FS::pread64", "FS::pwrite64", "FS::readv", "FS::writev", "FS::access", "FS::pipe", "FS::select", "KERNEL::sched_yield", "MM::mremap", "MM::msync", "MM::mincore", "MM::madvise", "IPC::shmget", "IPC::shmat", "IPC::shmctl", "FS::dup", "FS::dup2", "KERNEL::pause", "KERNEL::nanosleep", "KERNEL::getitimer", "KERNEL::alarm", "KERNEL::setitimer", "KERNEL::getpid", "FS::sendfile", "NET::socket", "NET::connect", "NET::accept", "NET::sendto", "NET::recvfrom", "NET::sendmsg", "NET::recvmsg", "NET::shutdown", "NET::bind", "NET::listen", "NET::getsockname", "NET::getpeername", "NET::socketpair", "NET::setsockopt", "NET::getsockopt", "KERNEL::clone", "KERNEL::fork", "KERNEL::vfork", "FS::execve", "KERNEL::exit", "KERNEL::wait4", "KERNEL::kill", "KERNEL::uname", "IPC::semget", "IPC::semop", "IPC::semctl", "IPC::shmdt", "IPC::msgget", "IPC::msgsnd", "IPC::msgrcv", "IPC::msgctl", "FS::fcntl", "FS::flock", "FS::fsync", "FS::fdatasync", "FS::truncate", "FS::ftruncate", "FS::getdents", "FS::getcwd", "FS::chdir", "FS::fchdir", "FS::rename", "FS::mkdir", "FS::rmdir", "FS::creat", "FS::link", "FS::unlink", "FS::symlink", "FS::readlink", "FS::chmod", "FS::fchmod", "FS::chown", "FS::fchown", "FS::lchown", "KERNEL::umask", "KERNEL::gettimeofday", "KERNEL::getrlimit", "KERNEL::getrusage", "KERNEL::sysinfo", "KERNEL::times", "KERNEL::ptrace", "KERNEL::getuid", "KERNEL::syslog", "KERNEL::getgid", "KERNEL::setuid", "KERNEL::setgid", "KERNEL::geteuid", "KERNEL::getegid", "KERNEL::setpgid", "KERNEL::getppid", "KERNEL::getpgrp", "KERNEL::setsid", "KERNEL::setreuid", "KERNEL::setregid", "KERNEL::getgroups", "KERNEL::setgroups", "KERNEL::setresuid", "KERNEL::getresuid", "KERNEL::setresgid", "KERNEL::getresgid", "KERNEL::getpgid", "KERNEL::setfsuid", "KERNEL::setfsgid", "KERNEL::getsid", "KERNEL::capget", "KERNEL::capset", "KERNEL::rt_sigpending", "KERNEL::rt_sigtimedwait", "KERNEL::rt_sigqueueinfo", "KERNEL::rt_sigsuspend", "KERNEL::sigaltstack", "FS::utime", "FS::mknod", "FS::uselib", "KERNEL::personality", "FS::ustat", "FS::statfs", "FS::fstatfs", "FS::sysfs", "KERNEL::getpriority", "KERNEL::setpriority", "KERNEL::sched_setparam", "KERNEL::sched_getparam", "KERNEL::sched_setscheduler", "KERNEL::sched_getscheduler", "KERNEL::sched_get_priority_max", "KERNEL::sched_get_priority_min", "KERNEL::sched_rr_get_interval", "MM::mlock", "MM::munlock", "MM::mlockall", "MM::munlockall", "FS::vhangup", "KERNEL::modify_ldt", "FS::pivot_root", "KERNEL::_sysctl", "KERNEL::prctl", "KERNEL::arch_prctl", "KERNEL::adjtimex", "KERNEL::setrlimit", "FS::chroot", "FS::sync", "KERNEL::acct", "KERNEL::settimeofday", "FS::mount", "FS::umount2", "MM::swapon", "MM::swapoff", "KERNEL::reboot", "KERNEL::sethostname", "KERNEL::setdomainname", "KERNEL::iopl", "KERNEL::ioperm", "NOT_IMPLEMENTED", "KERNEL::init_module", "KERNEL::delete_module", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "FS::quotactl", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "KERNEL::gettid", "MM::readahead", "FS::setxattr", "FS::lsetxattr", "FS::fsetxattr", "FS::getxattr", "FS::lgetxattr", "FS::fgetxattr", "FS::listxattr", "FS::llistxattr", "FS::flistxattr", "FS::removexattr", "FS::lremovexattr", "FS::fremovexattr", "KERNEL::tkill", "KERNEL::time", "KERNEL::futex", "KERNEL::sched_setaffinity", "KERNEL::sched_getaffinity", "KERNEL::set_thread_area", "FS::io_setup", "FS::io_destroy", "FS::io_getevents", "FS::io_submit", "FS::io_cancel", "KERNEL::get_thread_area", "FS::lookup_dcookie", "FS::epoll_create", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "MM::remap_file_pages", "FS::getdents64", "KERNEL::set_tid_address", "KERNEL::restart_syscall", "IPC::semtimedop", "MM::fadvise64", "KERNEL::timer_create", "KERNEL::timer_settime", "KERNEL::timer_gettime", "KERNEL::timer_getoverrun", "KERNEL::timer_delete", "KERNEL::clock_settime", "KERNEL::clock_gettime", "KERNEL::clock_getres", "KERNEL::clock_nanosleep", "KERNEL::exit_group", "FS::epoll_wait", "FS::epoll_ctl", "KERNEL::tgkill", "FS::utimes", "NOT_IMPLEMENTED", "MM::mbind", "MM::set_mempolicy", "MM::get_mempolicy", "IPC::mq_open", "IPC::mq_unlink", "IPC::mq_timedsend", "IPC::mq_timedreceive", "IPC::mq_notify", "IPC::mq_getsetattr", "KERNEL::kexec_load", "KERNEL::waitid", "SECURITY::add_key", "SECURITY::request_key", "SECURITY::keyctl", "FS::ioprio_set", "FS::ioprio_get", "FS::inotify_init", "FS::inotify_add_watch", "FS::inotify_rm_watch", "MM::migrate_pages", "FS::openat", "FS::mkdirat", "FS::mknodat", "FS::fchownat", "FS::futimesat", "FS::newfstatat", "FS::unlinkat", "FS::renameat", "FS::linkat", "FS::symlinkat", "FS::readlinkat", "FS::fchmodat", "FS::faccessat", "FS::pselect6", "FS::ppoll", "KERNEL::unshare", "KERNEL::set_robust_list", "KERNEL::get_robust_list", "FS::splice", "FS::tee", "FS::sync_file_range", "FS::vmsplice", "MM::move_pages", "FS::utimensat", "FS::epoll_pwait", "FS::signalfd", "FS::timerfd_create", "FS::eventfd", "FS::fallocate", "FS::timerfd_settime", "FS::timerfd_gettime", "NET::accept4", "FS::signalfd4", "FS::eventfd2", "FS::epoll_create1", "FS::dup3", "FS::pipe2", "FS::inotify_init1", "FS::preadv", "FS::pwritev", "KERNEL::rt_tgsigqueueinfo", "KERNEL::perf_event_open", "NET::recvmmsg", "FS::fanotify_init", "FS::fanotify_mark", "KERNEL::prlimit64", "FS::name_to_handle_at", "FS::open_by_handle_at", "KERNEL::clock_adjtime", "FS::syncfs", "NET::sendmmsg", "KERNEL::setns", "KERNEL::getcpu", "MM::process_vm_readv", "MM::process_vm_writev", "KERNEL::kcmp", "KERNEL::finit_module", "KERNEL::sched_setattr", "KERNEL::sched_getattr", "FS::renameat2", "KERNEL::seccomp", "KERNEL::getrandom", "MM::memfd_create", "KERNEL::kexec_file_load", "KERNEL::bpf", "FS::execveat", "FS::userfaultfd", "KERNEL::membarrier", "MM::mlock2", "FS::copy_file_range", "FS::preadv2", "FS::pwritev2", "MM::pkey_mprotect", "MM::pkey_alloc", "MM::pkey_free", "FS::statx", "FS::io_pgetevents", "KERNEL::rseq"};
# define SYSCALL_READ 0
# else
static const string SYSCALLS[] = {"KERNEL::restart_syscall", "KERNEL::exit", "KERNEL::fork", "FS::read", "FS::write", "FS::open", "FS::close", "KERNEL::waitpid", "FS::creat", "FS::link", "FS::unlink", "KERNEL::execve", "FS::chdir", "KERNEL::time", "FS::mknod", "FS::chmod", "KERNEL::lchown16", "NOT_IMPLEMENTED", "FS::stat", "FS::lseek", "KERNEL::getpid", "FS::mount", "FS::oldumount", "KERNEL::setuid16", "KERNEL::getuid16", "KERNEL::stime", "KERNEL::ptrace", "KERNEL::alarm", "FS::fstat", "KERNEL::pause", "FS::utime", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "FS::access", "KERNEL::nice", "FS::ftime", "FS::sync", "KERNEL::kill", "FS::rename", "FS::mkdir", "FS::rmdir", "FS::dup", "FS::pipe", "KERNEL::times", "NOT_IMPLEMENTED", "MM::brk", "KERNEL::setgid16", "KERNEL::getgid16", "KERNEL::signal", "KERNEL::geteuid16", "KERNEL::getegid16", "KERNEL::acct", "FS::umount", "NOT_IMPLEMENTED", "FS::ioctl", "FS::fcntl", "NOT_IMPLEMENTED", "KERNEL::setpgid", "NOT_IMPLEMENTED", "KERNEL::olduname", "KERNEL::umask", "FS::chroot", "FS::ustat", "FS::dup2", "KERNEL::getppid", "KERNEL::getpgrp", "KERNEL::setsid", "KERNEL::sigaction", "KERNEL::sgetmask", "KERNEL::ssetmask", "KERNEL::setreuid16", "KERNEL::setregid16", "KERNEL::sigsuspend", "KERNEL::sigpending", "KERNEL::sethostname", "KERNEL::setrlimit", "KERNEL::old_getrlimit", "KERNEL::getrusage", "KERNEL::gettimeofday", "KERNEL::settimeofday", "KERNEL::getgroups16", "KERNEL::setgroups16", "FS::old_select", "FS::symlink", "FS::lstat", "FS::readlink", "FS::uselib", "MM::swapon", "KERNEL::reboot", "FS::old_readdir", "MM::old_mmap", "MM::munmap", "FS::truncate", "FS::ftruncate", "FS::fchmod", "KERNEL::fchown16", "KERNEL::getpriority", "KERNEL::setpriority", "NOT_IMPLEMENTED", "FS::statfs", "FS::fstatfs", "FS::ioperm", "NET::socketcall", "KERNEL::syslog", "KERNEL::setitimer", "KERNEL::getitimer", "FS::newstat", "FS::newlstat", "FS::newfstat", "KERNEL::uname", "FS::iopl", "FS::vhangup", "NOT_IMPLEMENTED", "KERNEL::vm86old", "KERNEL::wait4", "MM::swapoff", "KERNEL::sysinfo", "IPC::ipc", "FS::fsync", "KERNEL::sigreturn", "KERNEL::clone", "KERNEL::setdomainname", "KERNEL::newuname", "KERNEL::modify_ldt", "KERNEL::adjtimex", "MM::mprotect", "KERNEL::sigprocmask", "NOT_IMPLEMENTED", "KERNEL::init_module", "KERNEL::delete_module", "NOT_IMPLEMENTED", "FS::quotactl", "KERNEL::getpgid", "FS::fchdir", "FS::bdflush", "FS::sysfs", "KERNEL::personality", "NOT_IMPLEMENTED", "KERNEL::setfsuid16", "KERNEL::setfsgid16", "FS::llseek", "FS::getdents", "FS::select", "FS::flock", "MM::msync", "FS::readv", "FS::writev", "KERNEL::getsid", "FS::fdatasync", "KERNEL::sysctl", "MM::mlock", "MM::munlock", "MM::mlockall", "MM::munlockall", "KERNEL::sched_setparam", "KERNEL::sched_getparam", "KERNEL::sched_setscheduler", "KERNEL::sched_getscheduler", "KERNEL::sched_yield", "KERNEL::sched_get_priority_max", "KERNEL::sched_get_priority_min", "KERNEL::sched_rr_get_interval", "KERNEL::nanosleep", "MM::mremap", "KERNEL::setresuid16", "KERNEL::getresuid16", "KERNEL::vm86", "NOT_IMPLEMENTED", "FS::poll", "FS::nfsservctl", "KERNEL::setresgid16", "KERNEL::getresgid16", "KERNEL::prctl", "KERNEL::rt_sigreturn", "KERNEL::rt_sigaction", "KERNEL::rt_sigprocmask", "KERNEL::rt_sigpending", "KERNEL::rt_sigtimedwait", "KERNEL::rt_sigqueueinfo", "KERNEL::rt_sigsuspend", "FS::pread64", "FS::pwrite64", "KERNEL::chown16", "FS::getcwd", "KERNEL::capget", "KERNEL::capset", "KERNEL::sigaltstack", "FS::sendfile", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "KERNEL::vfork", "KERNEL::getrlimit", "MM::mmap_pgoff", "FS::truncate64", "FS::ftruncate64", "FS::stat64", "FS::lstat64", "FS::fstat64", "FS::lchown", "KERNEL::getuid", "KERNEL::getgid", "KERNEL::geteuid", "KERNEL::getegid", "KERNEL::setreuid", "KERNEL::setregid", "KERNEL::getgroups", "KERNEL::setgroups", "FS::fchown", "KERNEL::setresuid", "KERNEL::getresuid", "KERNEL::setresgid", "KERNEL::getresgid", "FS::chown", "KERNEL::setuid", "KERNEL::setgid", "KERNEL::setfsuid", "KERNEL::setfsgid", "FS::pivot_root", "MM::mincore", "MM::madvise", "FS::getdents64", "FS::fcntl64", "NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "KERNEL::gettid", "MM::readahead", "FS::setxattr", "FS::lsetxattr", "FS::fsetxattr", "FS::getxattr", "FS::lgetxattr", "FS::fgetxattr", "FS::listxattr", "FS::llistxattr", "FS::flistxattr", "FS::removexattr", "FS::lremovexattr", "FS::fremovexattr", "KERNEL::tkill", "FS::sendfile64", "KERNEL::futex", "KERNEL::sched_setaffinity", "KERNEL::sched_getaffinity", "KERNEL::set_thread_area", "KERNEL::get_thread_area", "FS::io_setup", "FS::io_destroy", "FS::io_getevents", "FS::io_submit", "FS::io_cancel", "MM::fadvise64", "NOT_IMPLEMENTED", "KERNEL::exit_group", "FS::lookup_dcookie", "FS::epoll_create", "FS::epoll_ctl", "FS::epoll_wait", "MM::remap_file_pages", "KERNEL::set_tid_address", "KERNEL::timer_create", "KERNEL::timer_settime", "KERNEL::timer_gettime", "KERNEL::timer_getoverrun", "KERNEL::timer_delete", "KERNEL::clock_settime", "KERNEL::clock_gettime", "KERNEL::clock_getres", "KERNEL::clock_nanosleep", "FS::statfs64", "FS::fstatfs64", "KERNEL::tgkill", "FS::utimes", "MM::fadvise64_64", "NOT_IMPLEMENTED", "MM::mbind", "MM::get_mempolicy", "MM::set_mempolicy", "IPC::mq_open", "IPC::mq_unlink", "IPC::mq_timedsend", "IPC::mq_timedreceive", "IPC::mq_notify", "IPC::mq_getsetattr", "KERNEL::kexec_load", "KERNEL::waitid", "NOT_IMPLEMENTED", "SECURITY::add_key", "SECURITY::request_key", "SECURITY::keyctl", "FS::ioprio_set", "FS::ioprio_get", "FS::inotify_init", "FS::inotify_add_watch", "FS::inotify_rm_watch", "MM::migrate_pages", "FS::openat", "FS::mkdirat", "FS::mknodat", "FS::fchownat", "FS::futimesat", "FS::fstatat64", "FS::unlinkat", "FS::renameat", "FS::linkat", "FS::symlinkat", "FS::readlinkat", "FS::fchmodat", "FS::faccessat", "FS::pselect6", "FS::ppoll", "KERNEL::unshare", "KERNEL::set_robust_list", "KERNEL::get_robust_list", "FS::splice", "FS::sync_file_range", "FS::tee", "FS::vmsplice", "MM::move_pages", "KERNEL::getcpu", "FS::epoll_pwait", "FS::utimensat", "FS::signalfd", "FS::timerfd_create", "FS::eventfd", "FS::fallocate", "FS::timerfd_settime", "FS::timerfd_gettime", "FS::signalfd4", "FS::eventfd2", "FS::epoll_create1", "FS::dup3", "FS::pipe2", "FS::inotify_init1", "FS::preadv", "FS::pwritev", "KERNEL::rt_tgsigqueueinfo", "KERNEL::perf_event_open", "NET::recvmmsg"};
# define SYSCALL_READ 3
# endif

/* cmd line options ==================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "trace.out", "Specify trace filename");
KNOB<bool> KnobTraceBBL(KNOB_MODE_WRITEONCE, "pintool",
    "bbl", "0", "Trace BBL addresses");
KNOB<bool> KnobTraceCalls(KNOB_MODE_WRITEONCE, "pintool",
    "calls", "0", "Trace Calls");
KNOB<bool> KnobTraceSyscalls(KNOB_MODE_WRITEONCE, "pintool",
    "sys", "0", "Trace System Calls");
KNOB<bool> KnobBranchesOnly(KNOB_MODE_WRITEONCE, "pintool",
    "branches", "0", "Trace branches only");
KNOB<bool> KnobMainObjOnly(KNOB_MODE_WRITEONCE, "pintool",
    "main", "0", "Trace BBL addresses only in the main object");

INT32 Usage() {
    cerr << "This tool produces a dynamic basic block trace." << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* syscalls instrumentation ============================================ */
VOID syscall_entry(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *vptr) {
    last_syscall_num = PIN_GetSyscallNumber(ctxt, std);
}

VOID dosyscall(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *vptr) {
	if(!KnobMainObjOnly.Value() || after_ld){
		TraceFile << "SYSCALL " << SYSCALLS[PIN_GetSyscallNumber(ctxt, std)] << endl;
	}
}

/* call instrumentation ================================================ */
VOID  do_call(ADDRINT target)
{
    TraceFile << "CALL " << target << endl;
}

VOID  do_call_indirect(ADDRINT target, BOOL taken)
{
    if( !taken ) return;
    do_call( target );
}

/* patch to exit on double empty read ================================== */
VOID exit_on_double_empty_read(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *vptr) {
    if(last_syscall_num == SYSCALL_READ) {
        if (PIN_GetSyscallReturn(ctxt, std) == 0) {
            if (last_read_empty){
                exit(1);
            }
            last_read_empty = true;
        } else {
            last_read_empty = false;
        }
    }
}

/* trace instrumentation =============================================== */
VOID dotrace(ADDRINT addr) {
	TraceFile << addr << endl;
	after_ld = true;
}

/* main binary only instrumentation ==================================== */
VOID instrument_img(IMG img, VOID *vptr) {
	if (IMG_IsMainExecutable(img)) {
		img_low = IMG_LowAddress(img);
		img_high = IMG_HighAddress(img);
	}
}


/* trace bbl instrumentation =========================================== */
VOID instrument_trace_bbl(TRACE trace, VOID *vptr) {
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    	// bbl tracing
    	ADDRINT addr = BBL_Address(bbl);
    	if ((!KnobBranchesOnly.Value() || BBL_HasFallThrough(bbl)) && (!KnobMainObjOnly.Value() || (img_low < addr && addr < img_high))) {
	        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR) dotrace,
	                       IARG_ADDRINT, addr, IARG_END);
	    }
    }
}

/* trace call instrumentation ========================================== */
VOID instrument_trace_calls(TRACE trace, VOID *vptr) {
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    	ADDRINT addr = BBL_Address(bbl);
        INS tail = BBL_InsTail(bbl);
        // call tracing
        if( INS_IsCall(tail) && (!KnobMainObjOnly.Value() || (img_low < addr && addr < img_high))) {
            if( INS_IsDirectControlFlow(tail) ) {
                const ADDRINT target = INS_DirectControlFlowTargetAddress(tail);
                if( !KnobMainObjOnly.Value() || (img_low < target && target < img_high) ) {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call),
                                             IARG_PTR, target, IARG_END);
                }
            }
            else {
                if( !KnobMainObjOnly.Value() || (img_low < addr && addr < img_high) ) {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
                }
            }
        }
    }
}


int  main(int argc, char *argv[]) {

    if( PIN_Init(argc,argv) ) {
        return Usage();
    }
    TraceFile.open(KnobOutputFile.Value().c_str());


	IMG_AddInstrumentFunction(instrument_img, NULL);

    if (KnobTraceBBL.Value()){
	    TRACE_AddInstrumentFunction(instrument_trace_bbl, NULL);
	}

	if (KnobTraceCalls.Value()){
	    TRACE_AddInstrumentFunction(instrument_trace_calls, NULL);
	}

    PIN_AddSyscallEntryFunction(syscall_entry, NULL);
    PIN_AddSyscallExitFunction(exit_on_double_empty_read, NULL);

    if (KnobTraceSyscalls.Value()){
    	PIN_AddSyscallEntryFunction(dosyscall, NULL);
    }
    PIN_StartProgram();

    return 0; // never returns
}
