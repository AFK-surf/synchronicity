//! Provider contract smoke tests. Each test is enabled by its bucket/container
//! environment variable, so local `cargo test` stays hermetic while CI can run
//! the same semantic path against MinIO, fake-gcs-server, and Azurite.

use std::{collections::HashMap, sync::Arc, time::Duration};

use synch_store::{
    backend::{CasBackend, Cloud},
    cloud::{CloudConfig, CloudService, CloudStore, CloudUploadPolicy},
    Donor, Store, StoreError,
};

fn configured(service: CloudService) -> Option<HashMap<String, String>> {
    let mut options = HashMap::new();
    let copy = |options: &mut HashMap<String, String>, env_name: &str, key: &str| {
        if let Ok(value) = std::env::var(env_name) {
            options.insert(key.to_string(), value);
        }
    };
    match service {
        CloudService::S3 => {
            options.insert("bucket".into(), std::env::var("SYNCH_TEST_S3_BUCKET").ok()?);
            copy(&mut options, "SYNCH_TEST_S3_ENDPOINT", "endpoint");
            copy(&mut options, "SYNCH_TEST_S3_REGION", "region");
            copy(&mut options, "SYNCH_TEST_S3_ACCESS_KEY_ID", "access_key_id");
            copy(
                &mut options,
                "SYNCH_TEST_S3_SECRET_ACCESS_KEY",
                "secret_access_key",
            );
            copy(&mut options, "SYNCH_TEST_S3_SESSION_TOKEN", "session_token");
        }
        CloudService::Gcs => {
            options.insert(
                "bucket".into(),
                std::env::var("SYNCH_TEST_GCS_BUCKET").ok()?,
            );
            copy(&mut options, "SYNCH_TEST_GCS_ENDPOINT", "endpoint");
            if options.contains_key("endpoint") {
                options.insert("skip_signature".into(), "true".into());
                options.insert("disable_vm_metadata".into(), "true".into());
            }
            copy(
                &mut options,
                "SYNCH_TEST_GCS_CREDENTIAL_PATH",
                "credential_path",
            );
        }
        CloudService::Azblob => {
            options.insert(
                "container".into(),
                std::env::var("SYNCH_TEST_AZBLOB_CONTAINER").ok()?,
            );
            copy(&mut options, "SYNCH_TEST_AZBLOB_ENDPOINT", "endpoint");
            copy(
                &mut options,
                "SYNCH_TEST_AZBLOB_ACCOUNT_NAME",
                "account_name",
            );
            copy(&mut options, "SYNCH_TEST_AZBLOB_ACCOUNT_KEY", "account_key");
        }
        CloudService::Memory => return None,
    }
    options.insert(
        "root".into(),
        format!(
            "/synch-contract/{}/{}-{}/",
            service.as_str(),
            std::process::id(),
            synch_core::now_ns()
        ),
    );
    Some(options)
}

async fn provider_contract(service: CloudService) {
    // Shipped binaries do this before constructing any TLS client. This test
    // binary has no application `main`, so reproduce that process contract.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let Some(options) = configured(service) else {
        eprintln!(
            "{} provider contract skipped: test namespace is not configured",
            service.as_str()
        );
        return;
    };
    let data = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(data.path()).unwrap());
    let objects = CloudStore::open(&CloudConfig {
        service,
        options,
        scratch_dir: scratch.path().to_path_buf(),
        io_timeout: Duration::from_secs(30),
        upload_policy: CloudUploadPolicy::OwnPinned,
        cache_bytes: None,
    })
    .unwrap();
    let backend = Cloud::new(store, objects.clone(), CloudUploadPolicy::OwnPinned, None);
    let payload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
    let ingested = backend
        .ingest_bytes(payload.clone(), synch_core::now_ns())
        .await
        .unwrap();
    assert_eq!(
        backend.read_range(ingested.root, 71, 90_000).await.unwrap(),
        payload[71..90_071]
    );
    let target = data.path().join("materialized");
    backend
        .materialize(ingested.root, ingested.size, target.clone())
        .await
        .unwrap();
    assert_eq!(std::fs::read(target).unwrap(), payload);
    backend.delete(ingested.root).await.unwrap();
    assert!(matches!(
        objects.read_range(&ingested.root, 0..1).await,
        Err(StoreError::CloudNotFound { .. })
    ));

    let provider_dir = tempfile::tempdir().unwrap();
    let provider = Store::open(provider_dir.path()).unwrap();
    let partial_root = provider.ingest_bytes(&payload, 1).unwrap();
    let all = synch_core::ChunkRanges::single(0, synch_core::group_count(payload.len() as u64));
    let (encoded, served) = provider.encode_slice(&partial_root, &all).unwrap();
    let written = backend
        .write_slice(
            partial_root,
            payload.len() as u64,
            served,
            encoded,
            synch_core::now_ns(),
        )
        .await
        .unwrap();
    assert_eq!(written.durability, synch_store::backend::Durability::Staged);
    backend
        .finalize(partial_root, payload.len() as u64)
        .await
        .unwrap();

    let old: Vec<u8> = (0..200_000)
        .map(|index| ((index * 17 + 3) % 251) as u8)
        .collect();
    let mut new = old.clone();
    new[64 * 1024..80 * 1024].fill(0xa5);
    let donor = backend
        .ingest_bytes(old, synch_core::now_ns())
        .await
        .unwrap();
    let target_root = provider.ingest_bytes(&new, 2).unwrap();
    let target_all = synch_core::ChunkRanges::single(0, synch_core::group_count(new.len() as u64));
    let (proof, proof_served) = provider
        .encode_proof(&target_root, &target_all, 0, synch_core::MAX_PROOF_NODES)
        .unwrap();
    let proven = backend
        .write_proof(
            target_root,
            new.len() as u64,
            proof_served,
            0,
            proof,
            synch_core::now_ns(),
        )
        .await
        .unwrap();
    let promoted = backend
        .promote(Donor(donor.root), proven, synch_core::now_ns())
        .await
        .unwrap();
    assert!(!promoted.is_empty());
    let missing = target_all.difference(&promoted);
    let (encoded, served) = provider.encode_slice(&target_root, &missing).unwrap();
    backend
        .write_slice(
            target_root,
            new.len() as u64,
            served,
            encoded,
            synch_core::now_ns(),
        )
        .await
        .unwrap();
    backend
        .finalize(target_root, new.len() as u64)
        .await
        .unwrap();
    assert_eq!(
        backend
            .read_range(target_root, 0, new.len() as u64)
            .await
            .unwrap(),
        new
    );
    for root in [partial_root, donor.root, target_root] {
        backend.delete(root).await.unwrap();
    }
}

#[tokio::test]
async fn minio_s3_passes_the_cloud_backend_contract() {
    provider_contract(CloudService::S3).await;
}

#[tokio::test]
async fn fake_gcs_server_passes_the_cloud_backend_contract() {
    provider_contract(CloudService::Gcs).await;
}

#[tokio::test]
async fn azurite_passes_the_cloud_backend_contract() {
    provider_contract(CloudService::Azblob).await;
}
