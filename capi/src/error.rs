// SPDX-License-Identifier: Apache-2.0

use libc::c_char;
use std::ffi::CString;
use std::io;

#[repr(C)]
pub enum ErrorKind {
    Unknown,
    InvalidArgument,
    IoError,
}

#[repr(C)]
pub struct Error {
    kind: ErrorKind,
    message: *const c_char,
}

#[no_mangle]
pub unsafe extern "C" fn pgp_error_free(err_ptr: *mut Error) {
    drop(Box::from_raw(err_ptr))
}

pub fn set_error(err_ptr: *mut *mut Error, kind: ErrorKind, message: &str) {
    if !err_ptr.is_null() {
        unsafe {
            *err_ptr = Box::into_raw(Box::new(Error {
                kind,
                message: CString::new(message).unwrap().into_raw(),
            }));
        }
    }
}

pub fn set_error_from(err_ptr: *mut *mut Error, err: anyhow::Error) {
    if !err_ptr.is_null() {
        let kind = if err.is::<io::Error>() {
            ErrorKind::IoError
        } else {
            ErrorKind::Unknown
        };

        unsafe {
            *err_ptr = Box::into_raw(Box::new(Error {
                kind,
                message: CString::from_vec_unchecked(err.to_string().into()).into_raw(),
            }));
        }
    }
}
