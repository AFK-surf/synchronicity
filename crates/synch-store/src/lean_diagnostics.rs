//! Mechanical host diagnostic conversions shared by native CAS adapters.
//! Domain-specific messages and recovery decisions stay with their callers.

use synch_verified::{cas::CellType, host};

use crate::StoreError;

pub(crate) fn column_type(index: u64, column: String, actual: CellType) -> StoreError {
    let kind = match actual {
        CellType::Null => rusqlite::types::Type::Null,
        CellType::Integer => rusqlite::types::Type::Integer,
        CellType::Real => rusqlite::types::Type::Real,
        CellType::Text => rusqlite::types::Type::Text,
        CellType::Blob => rusqlite::types::Type::Blob,
    };
    match usize::try_from(index) {
        Ok(index) => rusqlite::Error::InvalidColumnType(index, column, kind).into(),
        Err(_) => StoreError::invalid("native column index exceeds address space"),
    }
}

pub(crate) fn io_failure(error: StoreError) -> host::FileFailure<StoreError> {
    let kind = match &error {
        StoreError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            host::FileFailureKind::Missing
        }
        StoreError::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            host::FileFailureKind::ShortRead
        }
        _ => host::FileFailureKind::Other,
    };
    host::FileFailure { error, kind }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn column_diagnostics_preserve_all_sqlite_types_and_names() {
        use rusqlite::types::Type;
        for (actual, expected) in [
            (CellType::Null, Type::Null),
            (CellType::Integer, Type::Integer),
            (CellType::Real, Type::Real),
            (CellType::Text, Type::Text),
            (CellType::Blob, Type::Blob),
        ] {
            match column_type(17, "blobs.inline".into(), actual) {
                StoreError::Sqlite(rusqlite::Error::InvalidColumnType(index, column, kind)) => {
                    assert_eq!(index, 17);
                    assert_eq!(column, "blobs.inline");
                    assert_eq!(kind, expected);
                }
                other => panic!("unexpected diagnostic: {other:?}"),
            }
        }
    }

    #[test]
    fn column_indices_are_checked_against_the_host_address_space() {
        for index in [0, usize::MAX as u64, u64::MAX] {
            let error = column_type(index, "column".into(), CellType::Blob);
            match usize::try_from(index) {
                Ok(expected) => assert!(matches!(
                    error,
                    StoreError::Sqlite(rusqlite::Error::InvalidColumnType(actual, _, _))
                        if actual == expected
                )),
                Err(_) => assert!(matches!(
                    error,
                    StoreError::Invalid(message)
                        if message == "native column index exceeds address space"
                )),
            }
        }
    }

    #[derive(Debug)]
    struct Marker(u8);

    impl std::fmt::Display for Marker {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("original file failure")
        }
    }

    impl std::error::Error for Marker {}

    #[test]
    fn file_failures_classify_io_kinds_without_replacing_the_original_source() {
        use host::FileFailureKind;
        for (kind, expected) in [
            (ErrorKind::NotFound, FileFailureKind::Missing),
            (ErrorKind::UnexpectedEof, FileFailureKind::ShortRead),
            (ErrorKind::PermissionDenied, FileFailureKind::Other),
            (ErrorKind::InvalidInput, FileFailureKind::Other),
            (ErrorKind::Other, FileFailureKind::Other),
        ] {
            let error = Error::new(kind, Marker(71));
            let original =
                error.get_ref().unwrap().downcast_ref::<Marker>().unwrap() as *const Marker;
            let failure = io_failure(error.into());
            assert_eq!(failure.kind, expected);
            match failure.error {
                StoreError::Io(error) => {
                    assert_eq!(error.kind(), kind);
                    assert_eq!(
                        error.get_ref().unwrap().downcast_ref::<Marker>().unwrap().0,
                        71
                    );
                    assert_eq!(
                        error.get_ref().unwrap().downcast_ref::<Marker>().unwrap() as *const Marker,
                        original
                    );
                }
                other => panic!("unexpected diagnostic: {other:?}"),
            }
        }
    }

    #[test]
    fn file_failures_preserve_raw_os_codes_and_non_io_errors() {
        let error = Error::from_raw_os_error(2);
        let kind = error.kind();
        match io_failure(error.into()).error {
            StoreError::Io(error) => {
                assert_eq!(error.raw_os_error(), Some(2));
                assert_eq!(error.kind(), kind);
            }
            other => panic!("unexpected diagnostic: {other:?}"),
        }

        let message = String::from("not found is not an I/O classification");
        let original = message.as_ptr();
        let failure = io_failure(StoreError::Invalid(message));
        assert_eq!(failure.kind, host::FileFailureKind::Other);
        match failure.error {
            StoreError::Invalid(message) => assert_eq!(message.as_ptr(), original),
            other => panic!("unexpected diagnostic: {other:?}"),
        }
    }
}
