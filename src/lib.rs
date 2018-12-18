//! An abstraction over the windows tlhelp32 api.
//! It offers a generic [`Snapshot`] struct which acts as an iterator to easily iterate over the
//! returned entries.

#![cfg(windows)]
#![warn(missing_docs, missing_copy_implementations, missing_debug_implementations)]

#![doc(html_root_url = "https://docs.rs/tlhelp32/1.0.1")]

use widestring::U16CString;
use winapi::shared::minwindef::{BOOL, HMODULE, LPCVOID};
use winapi::um::{
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    tlhelp32::*,
    winnt::HANDLE,
};

use std::{
    fmt,
    io::{Error, Result},
    iter::{FusedIterator, Iterator},
    mem,
};

type Tl32helpFunc<T> = unsafe extern "system" fn(HANDLE, *mut T) -> BOOL;

macro_rules! to_u16cstring {
    ($ident:expr) => {
        U16CString::from_vec_with_nul(Box::new($ident) as Box<[u16]>).unwrap_or_default()
    };
}

/// Copies memory allocated to another process at the specified address into a supplied slice.
/// The number of bytes to copy is the length of the supplied slice.
pub fn read_process_memory(
    process_id: u32,
    base_address: LPCVOID,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut num_bytes_read = 0;
    if unsafe {
        Toolhelp32ReadProcessMemory(
            process_id,
            base_address,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            &mut num_bytes_read,
        )
    } == 0
    {
        Err(Error::last_os_error())
    } else {
        Ok(num_bytes_read)
    }
}

/// A trait for the different [`Snapshot`] types. You shouldn't need to work with this directly.
pub trait TagTl32: private::Sealed {
    /// The raw windows counterpart of the implementing struct
    type Raw: Copy;
    /// The corresponding Snapshot flags
    const FLAGS: u32;
    /// The `*32First` windows function
    const ITER_FIRST: Tl32helpFunc<Self::Raw>;
    /// The `*32Next` windows function
    const ITER_NEXT: Tl32helpFunc<Self::Raw>;

    /// Creates a new instance of this raw representation and initializes its `dwSize` field.
    fn init_raw() -> Self::Raw;

    /// Creates a new instance of `Self` from its windows counterpart.
    fn from_raw(raw: Self::Raw) -> Self;
}

mod private {
    pub trait Sealed {}
    impl Sealed for super::ProcessEntry {}
    impl Sealed for super::HeapList {}
    impl Sealed for super::ModuleEntry {}
    impl Sealed for super::ThreadEntry {}
}

/// A process entry taken from a [`Snapshot`].
/// For more information on the fields meanings visit the [`microsoft docs`](https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/ns-tlhelp32-tagprocessentry32)
#[allow(missing_docs)]
#[derive(Clone)]
pub struct ProcessEntry {
    pub process_id: u32,
    pub cnt_threads: u32,
    pub parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub sz_exe_file: U16CString,
}

impl TagTl32 for ProcessEntry {
    type Raw = PROCESSENTRY32W;
    const FLAGS: u32 = TH32CS_SNAPPROCESS;
    const ITER_FIRST: Tl32helpFunc<Self::Raw> = Process32FirstW;
    const ITER_NEXT: Tl32helpFunc<Self::Raw> = Process32NextW;

    #[inline]
    fn init_raw() -> Self::Raw {
        Self::Raw {
            dwSize: mem::size_of::<Self::Raw>() as u32,
            ..unsafe { mem::uninitialized() }
        }
    }

    #[inline]
    fn from_raw(raw: Self::Raw) -> Self {
        ProcessEntry {
            process_id: raw.th32ProcessID,
            cnt_threads: raw.cntThreads,
            parent_process_id: raw.th32ParentProcessID,
            pc_pri_class_base: raw.pcPriClassBase,
            sz_exe_file: to_u16cstring!(raw.szExeFile),
        }
    }
}

impl fmt::Debug for ProcessEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ProcessEntry")
            .field("process_id", &self.process_id)
            .field("cnt_threads", &self.cnt_threads)
            .field("parent_process_id", &self.parent_process_id)
            .field("pc_pri_class_base", &self.pc_pri_class_base)
            .field(
                "sz_exe_file",
                &self.sz_exe_file.to_string().unwrap_or_default(),
            )
            .finish()
    }
}

/// A module entry taken from a [`Snapshot`].
/// For more information on the fields meanings visit the [`microsoft docs`](https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/ns-tlhelp32-tagmoduleentry32)
#[allow(missing_docs)]
#[derive(Clone)]
pub struct ModuleEntry {
    pub process_id: u32,
    pub base_addr: *mut u8,
    pub base_size: u32,
    pub h_module: HMODULE,
    pub sz_module: U16CString,
    pub sz_exe_path: U16CString,
}

impl TagTl32 for ModuleEntry {
    type Raw = MODULEENTRY32W;
    const FLAGS: u32 = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    const ITER_FIRST: Tl32helpFunc<Self::Raw> = Module32FirstW;
    const ITER_NEXT: Tl32helpFunc<Self::Raw> = Module32NextW;

    #[inline]
    fn init_raw() -> Self::Raw {
        Self::Raw {
            dwSize: mem::size_of::<Self::Raw>() as u32,
            ..unsafe { mem::uninitialized() }
        }
    }

    #[inline]
    fn from_raw(raw: Self::Raw) -> Self {
        ModuleEntry {
            process_id: raw.th32ProcessID,
            base_addr: raw.modBaseAddr,
            base_size: raw.modBaseSize,
            h_module: raw.hModule,
            sz_module: to_u16cstring!(raw.szModule),
            sz_exe_path: to_u16cstring!(raw.szExePath),
        }
    }
}

impl fmt::Debug for ModuleEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ProcessEntry")
            .field("process_id", &self.process_id)
            .field("base_addr", &self.base_addr)
            .field("base_size", &self.base_size)
            .field("h_module", &self.h_module)
            .field("sz_module", &self.sz_module.to_string().unwrap_or_default())
            .field(
                "sz_exe_file",
                &self.sz_exe_path.to_string().unwrap_or_default(),
            )
            .finish()
    }
}

/// A heap list taken from a [`Snapshot`]. This struct is an iterator over the heap entries of its heap.
/// For more information on the fields meanings visit the [`microsoft docs`](https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/ns-tlhelp32-tagheaplist32)
#[allow(missing_docs, missing_copy_implementations)]
pub struct HeapList {
    pub process_id: u32,
    pub heap_id: usize,
    pub flags: u32,
    current: Option<HEAPENTRY32>,
}

impl TagTl32 for HeapList {
    type Raw = HEAPLIST32;
    const FLAGS: u32 = TH32CS_SNAPHEAPLIST;
    const ITER_FIRST: Tl32helpFunc<Self::Raw> = Heap32ListFirst;
    const ITER_NEXT: Tl32helpFunc<Self::Raw> = Heap32ListNext;

    #[inline]
    fn init_raw() -> Self::Raw {
        Self::Raw {
            dwSize: mem::size_of::<Self::Raw>(),
            ..unsafe { mem::uninitialized() }
        }
    }

    #[inline]
    fn from_raw(raw: Self::Raw) -> Self {
        let mut entry = HEAPENTRY32 {
            dwSize: mem::size_of::<HEAPENTRY32>(),
            ..unsafe { mem::uninitialized() }
        };
        let current = if unsafe { Heap32First(&mut entry, raw.th32ProcessID, raw.th32HeapID) == 0 }
        {
            None
        } else {
            Some(entry)
        };
        HeapList {
            process_id: raw.th32ProcessID,
            heap_id: raw.th32HeapID,
            flags: raw.dwFlags,
            current,
        }
    }
}

impl Iterator for HeapList {
    type Item = HeapEntry;
    fn next(&mut self) -> Option<Self::Item> {
        let val = HeapEntry::from_raw(self.current?);
        if unsafe { Heap32Next(self.current.as_mut().unwrap()) == 0 } {
            self.current = None
        }
        Some(val)
    }
}

impl fmt::Debug for HeapList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeapList")
            .field("process_id", &self.process_id)
            .field("heap_id", &self.heap_id)
            .field("flags", &self.flags)
            .field("exhausted", &self.current.is_none())
            .finish()
    }
}

/// A heap entry taken from a [`HeapList`].
/// For more information on the fields meanings visit the [`microsoft docs`](https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/ns-tlhelp32-tagheapentry32)
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub struct HeapEntry {
    pub handle: HANDLE,
    pub address: usize,
    pub block_size: usize,
    pub flags: u32,
    pub process_id: u32,
    pub heap_id: usize,
}

impl HeapEntry {
    fn from_raw(raw: HEAPENTRY32) -> Self {
        HeapEntry {
            handle: raw.hHandle,
            address: raw.dwAddress,
            block_size: raw.dwBlockSize,
            flags: raw.dwFlags,
            process_id: raw.th32ProcessID,
            heap_id: raw.th32HeapID,
        }
    }
}

/// A thread entry taken from a [`Snapshot`].
/// For more information on the fields meanings visit the [`microsoft docs`](https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/ns-tlhelp32-tagthreadentry32)
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub struct ThreadEntry {
    pub thread_id: u32,
    pub owner_process_id: u32,
    pub base_pri: i32,
}

impl TagTl32 for ThreadEntry {
    type Raw = THREADENTRY32;
    const FLAGS: u32 = TH32CS_SNAPTHREAD;
    const ITER_FIRST: Tl32helpFunc<Self::Raw> = Thread32First;
    const ITER_NEXT: Tl32helpFunc<Self::Raw> = Thread32Next;

    #[inline]
    fn init_raw() -> Self::Raw {
        Self::Raw {
            dwSize: mem::size_of::<Self::Raw>() as u32,
            ..unsafe { mem::uninitialized() }
        }
    }

    #[inline]
    fn from_raw(raw: Self::Raw) -> Self {
        ThreadEntry {
            thread_id: raw.th32ThreadID,
            owner_process_id: raw.th32OwnerProcessID,
            base_pri: raw.tpBasePri,
        }
    }
}

/// An iterator for the Toolhelp32Snapshot Windows API.
/// You create them by calling the appropriate `new_*` methods.
#[derive(Debug)]
pub struct Snapshot<T: TagTl32> {
    snapshot: HANDLE,
    current: Option<T::Raw>,
}

impl<T: TagTl32> Snapshot<T> {
    #[inline]
    fn new(pid: u32) -> Result<Self> {
        unsafe { Self::from_handle(CreateToolhelp32Snapshot(T::FLAGS, pid)) }
    }

    /// Creates a snapshot from a given handle. Avoid using this unless you have a specific reason to.
    /// # Safety
    /// This function does not check whether the generic type and the flags belong together.
    /// If used incorrectly this will produce an iterator that returns [`None`] from the very beginning.
    pub unsafe fn from_handle(snapshot: HANDLE) -> Result<Self> {
        match snapshot {
            INVALID_HANDLE_VALUE => Err(Error::last_os_error()),
            snapshot => {
                let mut entry = T::init_raw();
                let current = if T::ITER_FIRST(snapshot, &mut entry) == 0 {
                    None
                } else {
                    Some(entry)
                };
                Ok(Snapshot { snapshot, current })
            }
        }
    }

    /// Retrieves the windows snapshot handle
    pub fn handle(&self) -> HANDLE {
        self.snapshot
    }
}

impl Snapshot<ProcessEntry> {
    /// Creates a new [`ProcessEntry`] [`Snapshot`]. This is equal to creating a snapshot with the `TH32CS_SNAPPROCESS` flag.
    /// # Errors
    /// This function fails and returns the appropriate os error if it is unable to create a [`Snapshot`]
    ///
    /// # Usage
    ///
    /// ```rust,no_run
    /// for entry in tlhelp32::Snapshot::new_process()? {
    ///     println!("{:?}", entry);
    /// }
    /// ```
    pub fn new_process() -> Result<Self> {
        Self::new(0)
    }
}

impl Snapshot<HeapList> {
    /// Creates a new [`HeapList`] [`Snapshot`]. This is equal to creating a snapshot with the `TH32CS_SNAPHEAPLIST` flag.
    /// # Errors
    /// This function fails and returns the appropriate os error if it is unable to create a [`Snapshot`]
    /// # Usage
    ///
    /// ```rust,no_run
    /// for heap_list in tlhelp32::Snapshot::new_heap_list(pid)? {
    ///     for heap_entry in heap_list {
    ///         println!("{:?}", heap_entry);
    ///     }
    /// }
    /// ```
    pub fn new_heap_list(pid: u32) -> Result<Self> {
        Self::new(pid)
    }
}

impl Snapshot<ModuleEntry> {
    /// Creates a new [`ModuleEntry`] [`Snapshot`]. This is equal to creating a snapshot with the `TH32CS_SNAPMODULE` and `TH32CS_SNAPMODULE32` flags.
    /// # Errors
    /// This function fails and returns the appropriate os error if it is unable to create a [`Snapshot`]
    ///
    /// # Usage
    ///
    /// ```rust,no_run
    /// for mod_entry in tlhelp32::Snapshot::new_module(entry.process_id)? {
    ///     println!("{:?}", mod_entry);
    /// }
    /// ```
    pub fn new_module(pid: u32) -> Result<Self> {
        Self::new(pid)
    }
}

impl Snapshot<ThreadEntry> {
    /// Creates a new [`ThreadEntry`] [`Snapshot`]. This is equal to creating a snapshot with the `TH32CS_SNAPTHREAD` flag.
    /// # Errors
    /// This function fails and returns the appropriate os error if it is unable to create a [`Snapshot`]
    ///
    /// # Usage
    ///
    /// ```rust,no_run
    /// for thread_entry in tlhelp32::Snapshot::new_thread()? {
    ///     println!("{:?}", mod_entry);
    /// }
    /// ```
    pub fn new_thread() -> Result<Self> {
        Self::new(0)
    }
}

impl<T: TagTl32> Iterator for Snapshot<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        let val = T::from_raw(self.current?);
        if unsafe { T::ITER_NEXT(self.snapshot, self.current.as_mut().unwrap()) == 0 } {
            self.current = None
        }
        Some(val)
    }
}

impl<T: TagTl32> FusedIterator for Snapshot<T> {}

impl<T: TagTl32> Drop for Snapshot<T> {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.snapshot) };
    }
}

unsafe impl Send for ModuleEntry {}
unsafe impl Sync for ModuleEntry {}
unsafe impl Send for HeapList {}
unsafe impl Send for HeapEntry {}
unsafe impl Sync for HeapEntry {}
