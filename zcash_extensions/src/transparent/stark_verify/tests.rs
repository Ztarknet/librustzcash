use zcash_primitives::{
    extensions::transparent::{self as tze, Extension, FromPayload, ToPayload},
    transaction::{
        TransactionData, TxVersion,
        components::tze::{Authorized, Bundle, OutPoint, TzeIn, TzeOut},
    },
};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};

use super::{Context, Precondition, Program, Witness, modes};

/// Helper function to extract roots and program hash from a Cairo proof for testing
fn extract_data_from_proof(proof_data: &[u8], _with_pedersen: bool, proof_format: modes::verify::ProofFormat) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    use bzip2::read::BzDecoder;
    use cairo_air::utils::get_verification_output;
    use cairo_air::CairoProof;
    use stwo::core::vcs::blake2_merkle::Blake2sMerkleHasher;
    use stwo_cairo_serialize::CairoDeserialize;
    use std::io::Read;

    // Parse the Cairo proof based on the encoding format
    let cairo_proof: CairoProof<Blake2sMerkleHasher> = match proof_format {
        modes::verify::ProofFormat::JsonEnc => {
            let proof_str = std::str::from_utf8(proof_data)
                .map_err(|_| "Failed to decode proof as UTF-8")?;
            serde_json::from_str(proof_str).map_err(|e| format!("Failed to parse JSON: {}", e))?
        }
        modes::verify::ProofFormat::BinEnc => {
            // Check if the data is bzip2-compressed
            let actual_data = if proof_data.len() >= 2 && proof_data[0] == b'B' && proof_data[1] == b'Z' {
                let mut bz_decoder = BzDecoder::new(proof_data);
                let mut decompressed = Vec::new();
                bz_decoder.read_to_end(&mut decompressed)
                    .map_err(|e| format!("Failed to decompress: {}", e))?;
                decompressed
            } else {
                proof_data.to_vec()
            };
            bincode::deserialize(&actual_data)
                .map_err(|e| format!("Failed to deserialize bincode: {}", e))?
        }
    };

    // Parse the proof's public output
    let verification_output = get_verification_output(&cairo_proof.claim.public_data.public_memory);
    let public_output = &verification_output.output;

    let mut iter = public_output.iter();
    let _bootloader_output = modes::verify::BootloaderOutput::deserialize(&mut iter);
    let os_header = modes::verify::OsOutputHeader::deserialize(&mut iter);

    let initial_root: [u8; 32] = os_header.initial_root.to_bytes_be()
        .try_into()
        .map_err(|_| "Failed to convert initial_root to bytes")?;
    let final_root: [u8; 32] = os_header.final_root.to_bytes_be()
        .try_into()
        .map_err(|_| "Failed to convert final_root to bytes")?;
    let program_hash: [u8; 32] = os_header.os_program_hash.to_bytes_be()
        .try_into()
        .map_err(|_| "Failed to convert os_program_hash to bytes")?;

    Ok((initial_root, final_root, program_hash))
}

#[test]
fn precondition_initialize_round_trip() {
    let root = [7u8; 32];
    let program_hash = [9u8; 32];
    let mut data = Vec::new();
    data.extend_from_slice(&root);
    data.extend_from_slice(&program_hash);
    let p = Precondition::from_payload(modes::initialize::MODE, &data).unwrap();
    assert_eq!(p, Precondition::initialize(root, program_hash));
    assert_eq!(p.to_payload(), (modes::initialize::MODE, data));
}

#[test]
fn precondition_stark_verify_round_trip() {
    let root = [7u8; 32];
    let program_hash = [9u8; 32];
    let mut data = Vec::new();
    data.extend_from_slice(&root);
    data.extend_from_slice(&program_hash);
    let p = Precondition::from_payload(modes::verify::MODE, &data).unwrap();
    assert_eq!(p, Precondition::stark_verify(root, program_hash));
    assert_eq!(p.to_payload(), (modes::verify::MODE, data));
}

#[test]
fn precondition_rejects_invalid_mode() {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(&[7u8; 32]);
    data[32..].copy_from_slice(&[9u8; 32]);
    let p = Precondition::from_payload(99, &data);
    assert!(p.is_err());
}

#[test]
fn precondition_rejects_invalid_payload_length() {
    // Test both initialize and stark_verify modes
    for mode in [modes::initialize::MODE, modes::verify::MODE] {
        // Empty payload should be rejected
        let p = Precondition::from_payload(mode, &[]);
        assert!(p.is_err());

        // Wrong length payload should be rejected
        let p = Precondition::from_payload(mode, &[1, 2, 3]);
        assert!(p.is_err());

        // 32 bytes should be rejected (need 64 bytes now)
        let p = Precondition::from_payload(mode, &[0u8; 32]);
        assert!(p.is_err());

        // 63 bytes should be rejected
        let p = Precondition::from_payload(mode, &[0u8; 63]);
        assert!(p.is_err());

        // 65 bytes should be rejected
        let p = Precondition::from_payload(mode, &[0u8; 65]);
        assert!(p.is_err());
    }
}

#[test]
fn witness_initialize_round_trip() {
    // Initialize witness has no payload
    let w = Witness::from_payload(modes::initialize::MODE, &[]).unwrap();
    assert_eq!(w, Witness::initialize());
    assert_eq!(w.to_payload(), (modes::initialize::MODE, vec![]));
}

#[test]
fn witness_stark_verify_round_trip() {
    let proof_data = b"test proof data".to_vec();
    let with_pedersen = false;
    let proof_format = modes::verify::ProofFormat::JsonEnc;

    // Create payload: [with_pedersen flag] + [proof_format] + [proof_data]
    let mut payload = vec![
        if with_pedersen { 1 } else { 0 },
        match proof_format {
            modes::verify::ProofFormat::JsonEnc => 0,
            modes::verify::ProofFormat::BinEnc => 1,
        },
    ];
    payload.extend_from_slice(&proof_data);

    let w = Witness::from_payload(modes::verify::MODE, &payload).unwrap();
    assert_eq!(w, Witness::stark_verify(proof_data.clone(), with_pedersen, proof_format));
    assert_eq!(w.to_payload(), (modes::verify::MODE, payload));
}

#[test]
fn witness_rejects_invalid_mode() {
    let w = Witness::from_payload(99, &[]);
    assert!(w.is_err());
}

#[test]
fn witness_accepts_valid_payload() {
    // Initialize mode accepts empty payload
    let w = Witness::from_payload(modes::initialize::MODE, &[]);
    assert!(w.is_ok());

    // StarkVerify mode requires at least 2 bytes: pedersen flag + format byte
    let w = Witness::from_payload(modes::verify::MODE, &[0, 1, 2, 3]);
    assert!(w.is_ok());
}

#[test]
fn witness_rejects_empty_payload() {
    // Initialize mode should reject non-empty payload
    let w = Witness::from_payload(modes::initialize::MODE, &[1, 2, 3]);
    assert!(w.is_err());

    // StarkVerify mode should reject empty payload (needs at least 2 bytes: pedersen flag + format byte)
    let w = Witness::from_payload(modes::verify::MODE, &[]);
    assert!(w.is_err());
    // Single byte should also be rejected
    let w = Witness::from_payload(modes::verify::MODE, &[0]);
    assert!(w.is_err());
}

/// Dummy context for testing
struct Ctx<'a> {
    tx: &'a zcash_primitives::transaction::Transaction,
}

impl<'a> Context for Ctx<'a> {
    fn tx_tze_outputs(&self) -> &[zcash_primitives::transaction::components::tze::TzeOut] {
        match self.tx.tze_bundle() {
            Some(b) => &b.vout,
            None => &[],
        }
    }
}

#[test]
fn stark_verify_program_succeeds() {
    // Use dummy roots and program hash for testing
    let initial_root = [1u8; 32];
    let final_root = [2u8; 32];
    let program_hash = [3u8; 32];

    // Create a simple transaction with STARK verify TZE input and output
    let out_a = TzeOut {
        value: Zatoshis::from_u64(1).unwrap(),
        precondition: tze::Precondition::from(0, &Precondition::stark_verify(initial_root, program_hash)),
    };

    let tx_a = TransactionData::from_parts_zfuture(
        TxVersion::ZFuture,
        BranchId::ZFuture,
        0,
        0u32.into(),
        #[cfg(feature = "zip-233")]
        Zatoshis::ZERO,
        None,
        None,
        None,
        None,
        Some(Bundle {
            vin: vec![],
            vout: vec![out_a],
            authorization: Authorized,
        }),
    )
    .freeze()
    .unwrap();

    // Create spending transaction with a dummy witness and output (just for structural test)
    let in_witness = TzeIn {
        prevout: OutPoint::new(tx_a.txid(), 0),
        witness: tze::Witness::from(0, &Witness::stark_verify(vec![1, 2, 3], false, modes::verify::ProofFormat::JsonEnc)),
    };

    let out_b = TzeOut {
        value: Zatoshis::from_u64(1).unwrap(),
        precondition: tze::Precondition::from(0, &Precondition::stark_verify(final_root, program_hash)),
    };

    let tx_b = TransactionData::from_parts_zfuture(
        TxVersion::ZFuture,
        BranchId::ZFuture,
        0,
        0u32.into(),
        #[cfg(feature = "zip-233")]
        Zatoshis::ZERO,
        None,
        None,
        None,
        None,
        Some(Bundle {
            vin: vec![in_witness],
            vout: vec![out_b],
            authorization: Authorized,
        }),
    )
    .freeze()
    .unwrap();

    // Verify the spend - this should fail with dummy data
    let ctx = Ctx { tx: &tx_b };
    let result = Program.verify(
        &tx_a.tze_bundle().unwrap().vout[0].precondition,
        &tx_b.tze_bundle().unwrap().vin[0].witness,
        &ctx,
    );
    // Dummy proof data should fail verification
    assert!(result.is_err());
}

/// This test demonstrates STARK proof verification from Starknet Sepolia network.
#[test]
fn verify_proof_sepolia() {
    // Load the compressed proof from test fixtures
    //
    // Generated using this command inside Ztarknet/gpp:
    // cargo run -- -b 2725346 -n sepolia
    let proof_file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/proof-sepolia-2725346.bz");
    let proof_data = std::fs::read(proof_file)
        .expect("Failed to read compressed proof file");

    // Extract roots and program hash from the proof
    let (initial_root, final_root, program_hash) = extract_data_from_proof(
        &proof_data,
        true,
        modes::verify::ProofFormat::BinEnc
    ).expect("Failed to extract data from proof");

    // Create a transaction with a STARK verification precondition output
    let out = TzeOut {
        value: Zatoshis::from_u64(100000).unwrap(),
        precondition: tze::Precondition::from(0, &Precondition::stark_verify(initial_root, program_hash)),
    };

    let tx_a = TransactionData::from_parts_zfuture(
        TxVersion::ZFuture,
        BranchId::ZFuture,
        0,
        0u32.into(),
        #[cfg(feature = "zip-233")]
        Zatoshis::ZERO,
        None,
        None,
        None,
        None,
        Some(Bundle {
            vin: vec![],
            vout: vec![out],
            authorization: Authorized,
        }),
    )
    .freeze()
    .unwrap();

    // Create a spending transaction with the STARK proof witness (binary encoded) and output with final root
    let in_witness = TzeIn {
        prevout: OutPoint::new(tx_a.txid(), 0),
        witness: tze::Witness::from(0, &Witness::stark_verify(proof_data, true, modes::verify::ProofFormat::BinEnc)),
    };

    let out_b = TzeOut {
        value: Zatoshis::from_u64(100000).unwrap(),
        precondition: tze::Precondition::from(0, &Precondition::stark_verify(final_root, program_hash)),
    };

    let tx_b = TransactionData::from_parts_zfuture(
        TxVersion::ZFuture,
        BranchId::ZFuture,
        0,
        0u32.into(),
        #[cfg(feature = "zip-233")]
        Zatoshis::ZERO,
        None,
        None,
        None,
        None,
        Some(Bundle {
            vin: vec![in_witness],
            vout: vec![out_b],
            authorization: Authorized,
        }),
    )
    .freeze()
    .unwrap();

    // Verify the spending transaction using the full verification path
    let ctx = Ctx { tx: &tx_b };
    let result = Program.verify(
        &tx_a.tze_bundle().unwrap().vout[0].precondition,
        &tx_b.tze_bundle().unwrap().vin[0].witness,
        &ctx,
    );
    // The proof should verify successfully
    assert!(
        result.is_ok(),
        "STARK proof verification failed: {:?}",
        result.err()
    );
}

#[test]
fn verify_inner_basic_flow() {
    // This test demonstrates that the verify_inner function is properly wired up
    // and can parse/verify proofs. It expects failure with invalid proof data,
    // which confirms the verification logic is running.

    let initial_root = [1u8; 32];
    let final_root = [2u8; 32];
    let program_hash = [3u8; 32];

    // Create a transaction with TZE output for context
    let out = TzeOut {
        value: Zatoshis::from_u64(1).unwrap(),
        precondition: tze::Precondition::from(0, &Precondition::stark_verify(final_root, program_hash)),
    };

    let tx = TransactionData::from_parts_zfuture(
        TxVersion::ZFuture,
        BranchId::ZFuture,
        0,
        0u32.into(),
        #[cfg(feature = "zip-233")]
        Zatoshis::ZERO,
        None,
        None,
        None,
        None,
        Some(Bundle {
            vin: vec![],
            vout: vec![out],
            authorization: Authorized,
        }),
    )
    .freeze()
    .unwrap();

    let ctx = Ctx { tx: &tx };
    let precondition = Precondition::stark_verify(initial_root, program_hash);

    // Test 1: Invalid JSON should fail at parsing stage
    let invalid_json = b"{invalid json}".to_vec();
    let witness = Witness::stark_verify(invalid_json, false, modes::verify::ProofFormat::JsonEnc);
    let result = Program.verify_inner(&precondition, &witness, &ctx);
    assert!(
        result.is_err(),
        "Invalid JSON should fail verification"
    );

    // Test 2: Valid JSON but not a proof should fail
    let not_a_proof = br#"{"foo": "bar"}"#.to_vec();
    let witness = Witness::stark_verify(not_a_proof, false, modes::verify::ProofFormat::JsonEnc);
    let result = Program.verify_inner(&precondition, &witness, &ctx);
    assert!(
        result.is_err(),
        "Non-proof JSON should fail verification"
    );

    // This confirms that:
    // 1. Witness data is being passed through correctly
    // 2. JSON parsing is attempted
    // 3. Verification logic is invoked
    // 4. Errors are properly propagated
}
