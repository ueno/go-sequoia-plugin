// SPDX-License-Identifier: Apache-2.0

use libc::{c_char, size_t};
use openpgp::cert::prelude::*;
use openpgp::parse::{stream::*, PacketParser, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{LiteralWriter, Message, Signer};
use openpgp::KeyHandle;
use sequoia_cert_store::{Store as _, StoreUpdate as _};
use sequoia_keystore;
use sequoia_openpgp as openpgp;
use std::ffi::{CStr, OsStr};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::Arc;

use crate::{set_error_from, Error};

pub struct Mechanism<'a> {
    keystore: sequoia_keystore::Keystore,
    certstore: Arc<sequoia_cert_store::CertStore<'a>>,
}

impl<'a> Mechanism<'a> {
    fn from_directory(dir: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let home_dir = if dir.as_ref() == Path::new("") {
            let data_dir = dirs::data_dir()
                .ok_or_else(|| anyhow::anyhow!("unable to determine XDG data directory"))?;
            data_dir.join("sequoia")
        } else {
            dir.as_ref().to_path_buf()
        };

        let context = sequoia_keystore::Context::configure()
            .home(&home_dir)
            .build()?;
        let keystore = sequoia_keystore::Keystore::connect(&context)?;

        let certstore = sequoia_cert_store::CertStore::open(home_dir.join("certs"))?;
        Ok(Self {
            keystore,
            certstore: Arc::new(certstore),
        })
    }

    fn ephemeral(keyring: &[u8]) -> Result<Self, anyhow::Error> {
        let ppr = PacketParser::from_bytes(keyring)?;
        let certs: Vec<openpgp::Cert> =
            CertParser::from(ppr).collect::<openpgp::Result<Vec<_>>>()?;
        let context = sequoia_keystore::Context::configure().ephemeral().build()?;
        let certstore = Arc::new(sequoia_cert_store::CertStore::empty());
        for cert in certs {
            certstore.update(Arc::new(sequoia_cert_store::LazyCert::from(cert)))?
        }
        Ok(Self {
            keystore: sequoia_keystore::Keystore::connect(&context)?,
            certstore,
        })
    }

    fn sign(
        &mut self,
        key_handle: &str,
        password: Option<&str>,
        data: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let key_handle: KeyHandle = key_handle.parse()?;
        let mut keys = self.keystore.find_key(key_handle)?;

        if keys.len() == 0 {
            return Err(anyhow::anyhow!("No matching key"));
        }
        if let Some(password) = password {
            keys[0].unlock(password.into())?;
        }

        let mut sink = vec![];
        {
            let message = Message::new(&mut sink);
            let message = Signer::new(message, &mut keys[0]).build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(data)?;
            message.finalize()?;
        }

        Ok(sink)
    }

    fn verify(&mut self, signature: &[u8]) -> Result<VerificationResult, anyhow::Error> {
        let p = &StandardPolicy::new();
        let h = Helper {
            certstore: self.certstore.clone(),
            signer: Default::default(),
        };
        let mut v = VerifierBuilder::from_bytes(signature)?.with_policy(p, None, h)?;
        let mut content = Vec::new();
        v.read_to_end(&mut content)?;

        assert!(v.message_processed());

        match &v.helper_ref().signer {
            Some(signer) => Ok(VerificationResult {
                content,
                signer: signer.clone(),
            }),
            None => Err(anyhow::anyhow!("No valid signature")),
        }
    }
}

struct Helper<'a> {
    certstore: Arc<sequoia_cert_store::CertStore<'a>>,
    signer: Option<openpgp::Cert>,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        let mut certs = Vec::new();
        for id in ids {
            let matches = self.certstore.lookup_by_cert(id)?;
            for lc in matches {
                certs.push(lc.to_cert()?.clone());
            }
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for (_, layer) in structure.into_iter().enumerate() {
            match layer {
                MessageLayer::SignatureGroup { ref results } => {
                    let result = results.iter().find(|r| r.is_ok());
                    if let Some(result) = result {
                        self.signer = Some(result.as_ref().unwrap().ka.cert().cert().to_owned());
                        return Ok(());
                    }
                }
                _ => return Err(anyhow::anyhow!("Unexpected message structure")),
            }
        }
        Err(anyhow::anyhow!("No valid signature"))
    }
}

pub struct Signature {
    data: Vec<u8>,
}

pub struct VerificationResult {
    content: Vec<u8>,
    signer: openpgp::Cert,
}

#[no_mangle]
pub unsafe extern "C" fn pgp_mechanism_new_from_directory<'a>(
    dir_ptr: *const c_char,
    err_ptr: *mut *mut Error,
) -> *mut Mechanism<'a> {
    let c_dir = CStr::from_ptr(dir_ptr);
    let os_dir = OsStr::from_bytes(c_dir.to_bytes());
    match Mechanism::from_directory(os_dir) {
        Ok(mechanism) => Box::into_raw(Box::new(mechanism)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pgp_mechanism_new_ephemeral<'a>(
    keyring_ptr: *const u8,
    keyring_len: size_t,
    err_ptr: *mut *mut Error,
) -> *mut Mechanism<'a> {
    let keyring = slice::from_raw_parts(keyring_ptr, keyring_len);
    match Mechanism::ephemeral(keyring) {
        Ok(mechanism) => Box::into_raw(Box::new(mechanism)),
        Err(e) => {
            set_error_from(err_ptr, e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pgp_mechanism_free(mechanism_ptr: *mut Mechanism) {
    drop(Box::from_raw(mechanism_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn pgp_signature_free(signature_ptr: *mut Signature) {
    drop(Box::from_raw(signature_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn pgp_signature_get_data(
    signature_ptr: *const Signature,
    data_len: *mut size_t,
) -> *const u8 {
    *data_len = (*signature_ptr).data.len();
    (*signature_ptr).data.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn pgp_verification_result_free(result_ptr: *mut VerificationResult) {
    drop(Box::from_raw(result_ptr))
}

#[no_mangle]
pub unsafe extern "C" fn pgp_verification_result_get_content(
    result_ptr: *const VerificationResult,
    data_len: *mut size_t,
) -> *const u8 {
    *data_len = (*result_ptr).content.len();
    (*result_ptr).content.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn pgp_verification_result_get_signer(
    result_ptr: *const VerificationResult,
) -> *const c_char {
    let fingerprint = (*result_ptr).signer.fingerprint();
    match CStr::from_bytes_with_nul(fingerprint.to_hex().as_bytes()) {
        Ok(c_fingerprint) => c_fingerprint.as_ptr(),
        Err(_) => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pgp_sign(
    mechanism_ptr: *mut Mechanism,
    key_handle_ptr: *const c_char,
    password_ptr: *const c_char,
    data_ptr: *const u8,
    data_len: size_t,
    err_ptr: *mut *mut Error,
) -> *mut Signature {
    assert!(!mechanism_ptr.is_null());
    assert!(!key_handle_ptr.is_null());
    assert!(!data_ptr.is_null());

    let key_handle = match CStr::from_ptr(key_handle_ptr).to_str() {
        Ok(key_handle) => key_handle,
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return ptr::null_mut();
        }
    };

    let password = if password_ptr.is_null() {
        None
    } else {
        match CStr::from_ptr(password_ptr).to_str() {
            Ok(key_handle) => Some(key_handle),
            Err(e) => {
                set_error_from(err_ptr, e.into());
                return ptr::null_mut();
            }
        }
    };

    let data = slice::from_raw_parts(data_ptr, data_len);
    match (&mut *mechanism_ptr).sign(key_handle, password, &data) {
        Ok(signature) => return Box::into_raw(Box::new(Signature { data: signature })),
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pgp_verify(
    mechanism_ptr: *mut Mechanism,
    signature_ptr: *const u8,
    signature_len: size_t,
    err_ptr: *mut *mut Error,
) -> *mut VerificationResult {
    assert!(!mechanism_ptr.is_null());
    assert!(!signature_ptr.is_null());

    let signature = slice::from_raw_parts(signature_ptr, signature_len);
    match (&mut *mechanism_ptr).verify(&signature) {
        Ok(result) => return Box::into_raw(Box::new(result)),
        Err(e) => {
            set_error_from(err_ptr, e.into());
            return ptr::null_mut();
        }
    }
}
