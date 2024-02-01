// SPDX-License-Identifier: LGPL-2.0-or-later

use libc::{c_int, size_t};
use openpgp::cert::prelude::*;
use openpgp::parse::{stream::*, PacketParser, Parse};
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;
use std::slice;

struct Helper<'a> {
    certs: &'a [openpgp::Cert],
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        let mut certs = Vec::new();
        for id in ids {
            if let Some(cert) = self.certs.iter().find(|cert| cert.key_handle() == *id) {
                certs.push(cert.clone());
            }
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let mut good = false;
        for (i, layer) in structure.into_iter().enumerate() {
            match (i, layer) {
                (0, MessageLayer::SignatureGroup { results }) => match results.into_iter().next() {
                    Some(Ok(_)) => good = true,
                    Some(Err(e)) => return Err(openpgp::Error::from(e).into()),
                    None => return Err(anyhow::anyhow!("No signature")),
                },
                _ => return Err(anyhow::anyhow!("Unexpected message structure")),
            }
        }

        if good {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Signature verification failed"))
        }
    }
}

fn verify_detatched(keyring: &[u8], signature: &[u8], data: &[u8]) -> Result<(), anyhow::Error> {
    let ppr = PacketParser::from_bytes(keyring)?;
    let certs: Vec<openpgp::Cert> = CertParser::from(ppr).collect::<openpgp::Result<Vec<_>>>()?;
    let p = &StandardPolicy::new();
    let h = Helper {
        certs: certs.as_ref(),
    };
    let mut v = DetachedVerifierBuilder::from_bytes(signature)?.with_policy(p, None, h)?;
    v.verify_bytes(data)
}

#[no_mangle]
pub unsafe extern "C" fn pgp_verify_detached(
    keyring_ptr: *const u8,
    keyring_len: size_t,
    signature_ptr: *const u8,
    signature_len: size_t,
    data_ptr: *const u8,
    data_len: size_t,
) -> c_int {
    assert!(!keyring_ptr.is_null());
    assert!(!signature_ptr.is_null());
    assert!(!data_ptr.is_null());

    let keyring = slice::from_raw_parts(keyring_ptr, keyring_len);
    let signature = slice::from_raw_parts(signature_ptr, signature_len);
    let data = slice::from_raw_parts(data_ptr, data_len);

    match verify_detatched(keyring, signature, data) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
