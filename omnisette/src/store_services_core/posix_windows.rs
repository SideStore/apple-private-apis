pub use libc::{chmod, close, free, fstat, malloc, mkdir, open, read, strncpy, write};

use windows_sys::Win32::{
    Foundation::FILETIME,
    Storage::FileSystem::{
        SetEndOfFile,
        SetFilePointerEx
    },
    System::SystemInformation::GetSystemTimeAsFileTime
};

// took from cosmopolitan libc

pub unsafe extern "C" fn umask(mask: usize) -> usize {
    println!("Windows specific implementation called!");
    mask
}

pub unsafe extern "C" fn ftruncate(handle: i64, length: u64) -> usize {
    println!("Windows specific implementation called!");
    let mut tell = -1;
    let mut ok: bool = SetFilePointerEx(handle as isize, 0, &mut tell, 1) != 0;
    if ok {
        ok = SetFilePointerEx(handle as isize, length as i64, std::ptr::null_mut(), 0) != 0 &&
            SetEndOfFile(handle as isize) != 0;
        assert!(SetFilePointerEx(handle as isize, tell, std::ptr::null_mut(), 0) != 0);
    }

    if ok {
        0
    } else {
        255
    }
}

#[repr(C)]
pub struct PosixTimeval {
    tv_sec: u64,
    tv_usec: u64 /* microseconds */
}

#[repr(C)]
pub struct PosixTimezone {
    tz_minuteswest: u32,
    tz_dsttime: u32 /* microseconds */
}

static MODERNITYSECONDS: u64 = 11644473600;
static HECTONANOSECONDS: u64 = 10000000;

pub unsafe extern "C" fn gettimeofday(timeval: *mut PosixTimeval, timezone: *mut PosixTimezone) -> isize {
    println!("Windows specific implementation called!");
    let mut filetime = FILETIME {
        dwHighDateTime: 0,
        dwLowDateTime: 0,
    };
    GetSystemTimeAsFileTime(&mut filetime);
    let filetime: u64 = std::mem::transmute(filetime);
    if !timeval.is_null() {
        *timeval = PosixTimeval {
            tv_sec: filetime / HECTONANOSECONDS - MODERNITYSECONDS,
            tv_usec: filetime % HECTONANOSECONDS / 10
        };
    }
    if !timezone.is_null() {
        *timezone = PosixTimezone {
            tz_minuteswest: 0,
            tz_dsttime: 0
        }
    }
    0
}

pub unsafe extern "C" fn lstat() {
    println!("Windows specific implementation called!");
    println!("not implemented");
}
