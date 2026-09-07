//! Private synchronous transport for raw storage/resource and crypto effects.
pub(crate) use crate::generated::{decode, dispatch, Command, Frame};
use crate::host::{
    ByteStorage, Cell, Clock, ConflictValue, Exclusion, Fields, FileFailure, FileFailureKind,
    FileIO, Join, Order, Resources, Row, Scan, Selection, SourceValue, Storage, SyncStatus,
};
use crate::native::{self, Handle};

#[derive(Debug)]
pub enum OperationError<E> {
    Host(E),
    MalformedMetadata(u64),
    Protocol,
}

impl<E: std::fmt::Display> std::fmt::Display for OperationError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(error) => error.fmt(f),
            Self::MalformedMetadata(_) => f.write_str("malformed Lean operation metadata"),
            Self::Protocol => f.write_str("invalid Lean host-effect protocol"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for OperationError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Host(error) => Some(error),
            _ => None,
        }
    }
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);
impl<'a> Reader<'a> {
    fn conflict_expression(
        &mut self,
        depth: usize,
        budget: &mut usize,
    ) -> Result<ConflictValue, ()> {
        if depth > 32 || *budget == 0 {
            return Err(());
        }
        *budget -= 1;
        Ok(match self.byte()? {
            0 => ConflictValue::Current(self.string()?),
            1 => ConflictValue::Excluded(self.string()?),
            tag @ (2 | 3) => {
                let left = self.conflict_expression(depth + 1, budget)?;
                let right = self.conflict_expression(depth + 1, budget)?;
                let pair = Box::new((left, right));
                if tag == 2 {
                    ConflictValue::Coalesce(pair)
                } else {
                    ConflictValue::Maximum(pair)
                }
            }
            _ => return Err(()),
        })
    }
    /// Conflict assignments share one expression budget across the whole
    /// list, bounding both nesting and total node count of hostile packets.
    pub(crate) fn assignments(&mut self) -> Result<Vec<(String, ConflictValue)>, ()> {
        let count = self.count()?;
        let mut budget = 4096;
        if count > budget || count > self.0.len() {
            return Err(());
        }
        let mut assignments = Vec::new();
        for _ in 0..count {
            assignments.push((self.string()?, self.conflict_expression(0, &mut budget)?));
        }
        Ok(assignments)
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], ()> {
        if count > self.0.len() {
            return Err(());
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    pub(crate) fn byte(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn word(&mut self) -> Result<u64, ()> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| ())?,
        ))
    }
    fn count(&mut self) -> Result<usize, ()> {
        usize::try_from(self.word()?).map_err(|_| ())
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, ()> {
        Ok(self.byte_slice()?.to_vec())
    }
    pub(crate) fn byte_slice(&mut self) -> Result<&'a [u8], ()> {
        let count = self.count()?;
        self.take(count)
    }
    pub(crate) fn string(&mut self) -> Result<String, ()> {
        String::from_utf8(self.bytes()?).map_err(|_| ())
    }
    pub(crate) fn boolean(&mut self) -> Result<bool, ()> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(()),
        }
    }
    pub(crate) fn list<T>(
        &mut self,
        read: impl Fn(&mut Self) -> Result<T, ()>,
    ) -> Result<Vec<T>, ()> {
        let count = self.count()?;
        if count > self.0.len() {
            return Err(());
        }
        (0..count).map(|_| read(self)).collect()
    }
    pub(crate) fn option<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T, ()>,
    ) -> Result<Option<T>, ()> {
        match self.byte()? {
            0 => Ok(None),
            1 => read(self).map(Some),
            _ => Err(()),
        }
    }
    pub(crate) fn cell(&mut self) -> Result<Cell, ()> {
        Ok(match self.byte()? {
            0 => Cell::Null,
            1 => Cell::Integer(self.word()? as i64),
            2 => Cell::Text(self.string()?),
            3 => Cell::Blob(self.bytes()?),
            4 => Cell::Real(self.word()?),
            5 => Cell::RawText(self.bytes()?),
            _ => return Err(()),
        })
    }
    pub(crate) fn fields(&mut self) -> Result<Fields, ()> {
        self.list(|r| Ok((r.string()?, r.cell()?)))
    }
    pub(crate) fn selection(&mut self) -> Result<Selection, ()> {
        Ok(Selection {
            relation: self.string()?,
            equals: self.fields()?,
            like_any: self.list(|r| Ok((r.string()?, r.string()?)))?,
            not_equals: self.fields()?,
        })
    }
    pub(crate) fn order(&mut self) -> Result<Order, ()> {
        Ok(Order {
            column: self.string()?,
            descending: self.boolean()?,
        })
    }
    pub(crate) fn join(&mut self) -> Result<Join, ()> {
        Ok(Join {
            relation: self.string()?,
            keys: self.list(|r| Ok((r.string()?, r.string()?)))?,
        })
    }
    pub(crate) fn exclusion(&mut self) -> Result<Exclusion, ()> {
        Ok(Exclusion {
            relation: self.string()?,
            equals: self.fields()?,
            keys: self.list(|r| Ok((r.string()?, r.string()?)))?,
        })
    }
    pub(crate) fn source_value(&mut self) -> Result<SourceValue, ()> {
        Ok(match self.byte()? {
            0 => SourceValue::Literal(self.cell()?),
            1 => SourceValue::Column(self.string()?),
            _ => return Err(()),
        })
    }
    pub(crate) fn end(&self) -> Result<(), ()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn word(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    word(out, value.len() as u64);
    out.extend_from_slice(value);
}
fn cell(out: &mut Vec<u8>, value: &Cell) {
    match value {
        Cell::Null => out.push(0),
        Cell::Integer(value) => {
            out.push(1);
            word(out, *value as u64);
        }
        Cell::Text(value) => {
            out.push(2);
            bytes(out, value.as_bytes());
        }
        Cell::Blob(value) => {
            out.push(3);
            bytes(out, value);
        }
        Cell::Real(bits) => {
            out.push(4);
            word(out, *bits);
        }
        Cell::RawText(value) => {
            out.push(5);
            bytes(out, value);
        }
    }
}
fn rows(out: &mut Vec<u8>, values: Vec<Row>) {
    word(out, values.len() as u64);
    for row in values {
        word(out, row.len() as u64);
        for value in row {
            cell(out, &value);
        }
    }
}

pub(crate) fn reply<E, A>(
    tag: u8,
    value: Result<A, E>,
    errors: &mut Vec<Option<E>>,
    encode: impl FnOnce(&mut Vec<u8>, A),
) -> Vec<u8> {
    match value {
        Ok(value) => {
            let mut out = vec![1, tag];
            encode(&mut out, value);
            out
        }
        Err(error) => {
            errors.push(Some(error));
            let mut out = vec![1, 0];
            word(&mut out, 1);
            word(&mut out, errors.len() as u64);
            out
        }
    }
}

pub(crate) fn scan_reply<E>(
    tag: u8,
    scan: Result<Scan<E>, E>,
    errors: &mut Vec<Option<E>>,
) -> Vec<u8> {
    match scan {
        Err(error) => reply(tag, Err::<(), _>(error), errors, |_, ()| {}),
        Ok(scan) => {
            let mut out = vec![1, tag];
            rows(&mut out, scan.rows);
            if let Some(error) = scan.failure {
                errors.push(Some(error));
                out.push(1);
                word(&mut out, 1);
                word(&mut out, errors.len() as u64);
            } else {
                out.push(0);
            }
            out
        }
    }
}

pub(crate) fn file_reply<E, A>(
    tag: u8,
    value: Result<A, FileFailure<E>>,
    errors: &mut Vec<Option<E>>,
    encode: impl FnOnce(&mut Vec<u8>, A),
) -> Vec<u8> {
    match value {
        Ok(value) => reply(tag, Ok(value), errors, encode),
        Err(FileFailure { error, kind }) => {
            let mut out = reply(tag, Err::<A, _>(error), errors, encode);
            out.push(match kind {
                FileFailureKind::Missing => 0,
                FileFailureKind::ShortRead => 1,
                FileFailureKind::Other => 2,
            });
            out
        }
    }
}

/// How a successful reply value is written after its tag. Scans are the one
/// exception: a trailing failure registers its own error token.
pub(crate) trait EncodeReply {
    fn encode(out: &mut Vec<u8>, value: Self);
}
impl EncodeReply for () {
    fn encode(_: &mut Vec<u8>, (): Self) {}
}
impl EncodeReply for u64 {
    fn encode(out: &mut Vec<u8>, value: Self) {
        word(out, value);
    }
}
impl EncodeReply for i64 {
    fn encode(out: &mut Vec<u8>, value: Self) {
        word(out, value as u64);
    }
}
impl EncodeReply for bool {
    fn encode(out: &mut Vec<u8>, value: Self) {
        out.push(u8::from(value));
    }
}
impl EncodeReply for Vec<u8> {
    fn encode(out: &mut Vec<u8>, value: Self) {
        bytes(out, &value);
    }
}
impl EncodeReply for Option<u64> {
    fn encode(out: &mut Vec<u8>, value: Self) {
        match value {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                word(out, value);
            }
        }
    }
}
impl EncodeReply for Option<i64> {
    fn encode(out: &mut Vec<u8>, value: Self) {
        match value {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                word(out, value as u64);
            }
        }
    }
}
impl EncodeReply for Option<Vec<u8>> {
    fn encode(out: &mut Vec<u8>, value: Self) {
        match value {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                bytes(out, &value);
            }
        }
    }
}
impl EncodeReply for Vec<Row> {
    fn encode(out: &mut Vec<u8>, value: Self) {
        rows(out, value);
    }
}
impl EncodeReply for SyncStatus {
    fn encode(out: &mut Vec<u8>, value: Self) {
        out.push(match value {
            SyncStatus::Synced => 0,
            SyncStatus::Unsupported => 1,
        });
    }
}

/// How a command argument is written into the packet that starts a run.
pub(crate) trait Encode {
    fn encode(&self, out: &mut Vec<u8>);
}
impl Encode for u64 {
    fn encode(&self, out: &mut Vec<u8>) {
        word(out, *self);
    }
}
impl Encode for i64 {
    fn encode(&self, out: &mut Vec<u8>) {
        word(out, *self as u64);
    }
}
impl Encode for bool {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
}
impl Encode for Vec<u8> {
    fn encode(&self, out: &mut Vec<u8>) {
        bytes(out, self);
    }
}
impl Encode for String {
    fn encode(&self, out: &mut Vec<u8>) {
        bytes(out, self.as_bytes());
    }
}
impl<T: Encode> Encode for Option<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(value) => {
                out.push(1);
                value.encode(out);
            }
        }
    }
}
impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
        self.1.encode(out);
    }
}
impl Encode for Vec<(u64, u64)> {
    fn encode(&self, out: &mut Vec<u8>) {
        word(out, self.len() as u64);
        for pair in self {
            pair.encode(out);
        }
    }
}
macro_rules! encode_list {
    ($($item:ty),+ $(,)?) => {
        $(impl Encode for Vec<$item> {
            fn encode(&self, out: &mut Vec<u8>) {
                word(out, self.len() as u64);
                for item in self {
                    item.encode(out);
                }
            }
        })+
    };
}
encode_list!(Vec<u8>, String, (Vec<u8>, Vec<u8>));

/// How a terminal value is read back once a run has finished.
pub(crate) trait Decode: Sized {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()>;
}
impl Decode for () {
    fn decode(_: &mut Reader<'_>) -> Result<Self, ()> {
        Ok(())
    }
}
impl Decode for u64 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        r.word()
    }
}
impl Decode for i64 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        Ok(r.word()? as i64)
    }
}
impl Decode for bool {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        r.boolean()
    }
}
impl Decode for Vec<u8> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        r.bytes()
    }
}
impl Decode for String {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        r.string()
    }
}
impl<T: Decode> Decode for Option<T> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        Ok(match r.byte()? {
            0 => None,
            1 => Some(Decode::decode(r)?),
            _ => return Err(()),
        })
    }
}
impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        Ok((Decode::decode(r)?, Decode::decode(r)?))
    }
}
impl Decode for Vec<(u64, u64)> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        r.list(Decode::decode)
    }
}
/// A finished command: its value, or the domain error that ended it.
impl<A: Decode, E: Decode> Decode for Result<A, E> {
    fn decode(r: &mut Reader<'_>) -> Result<Self, ()> {
        Ok(match r.byte()? {
            0 => Ok(Decode::decode(r)?),
            1 => Err(Decode::decode(r)?),
            _ => return Err(()),
        })
    }
}

/// Decode a whole terminal, refusing trailing bytes.
pub(crate) fn terminal<T: Decode>(bytes: &[u8]) -> Result<T, ()> {
    let mut reader = Reader(bytes);
    let value = Decode::decode(&mut reader)?;
    reader.end()?;
    Ok(value)
}

// Byte-only commands do not need a pretend relational store or a second
// layer of host errors: only the raw byte read and the digest primitive are
// served, each only when the caller supplied it.
fn dispatch_readonly<S: ByteStorage>(
    storage: Option<&mut S>,
    capabilities: &mut Capabilities<'_, S::Error>,
    frame: Frame<'_>,
    errors: &mut Vec<Option<S::Error>>,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    match frame {
        Frame::ReadBytes(space, key) => {
            let storage = storage.ok_or(OperationError::Protocol)?;
            Ok(reply(
                22,
                storage.read_bytes(&space, key),
                errors,
                EncodeReply::encode,
            ))
        }
        Frame::Blake3(bytes) => {
            let digest = capabilities
                .digest
                .as_deref_mut()
                .ok_or(OperationError::Protocol)?;
            Ok(reply(53, digest.blake3(bytes), errors, EncodeReply::encode))
        }
        Frame::PutBytes(space, key, bytes) => {
            let writes = capabilities
                .writes
                .as_deref_mut()
                .ok_or(OperationError::Protocol)?;
            Ok(reply(
                54,
                writes.put_bytes(&space, key, bytes),
                errors,
                EncodeReply::encode,
            ))
        }
        Frame::IsRedacted(hash, path) => {
            let redaction = capabilities
                .redaction
                .as_deref_mut()
                .ok_or(OperationError::Protocol)?;
            Ok(reply(
                70,
                redaction.is_redacted(hash, path),
                errors,
                EncodeReply::encode,
            ))
        }
        Frame::ApplyChange(key, kind, new) => {
            let apply = capabilities
                .apply
                .as_deref_mut()
                .ok_or(OperationError::Protocol)?;
            Ok(reply(
                71,
                apply.apply_change(key, kind, new),
                errors,
                EncodeReply::encode,
            ))
        }
        _ => Err(OperationError::Protocol),
    }
}

/// A byte store that is never there: the type a digest-only run names for
/// the storage it does not supply. A byte read is refused before this is
/// ever asked, so the impossible method is unreachable by construction, and
/// the type is uninhabited on purpose.
#[allow(dead_code)]
enum NoBytes<E> {
    Never(std::convert::Infallible, std::marker::PhantomData<E>),
}

impl<E> ByteStorage for NoBytes<E> {
    type Error = E;
    fn read_bytes(&mut self, _: &str, _: &[u8]) -> Result<Option<Vec<u8>>, E> {
        match *self {
            NoBytes::Never(never, _) => match never {},
        }
    }
}

/// The raw services an operation may direct besides relational storage. A
/// request for a service the caller did not supply is a protocol failure:
/// the Lean effect row of each operation says which services it can reach.
pub(crate) struct Capabilities<'a, E> {
    pub(crate) resources: Option<&'a mut dyn Resources<Error = E>>,
    pub(crate) crypto: Option<&'a mut dyn crate::host::Crypto<Error = E>>,
    pub(crate) files: Option<&'a mut dyn FileIO<Error = E>>,
    pub(crate) clock: Option<&'a mut dyn Clock<Error = E>>,
    pub(crate) output: Option<&'a mut dyn crate::host::Output<Error = OperationError<E>>>,
    pub(crate) construct: Option<&'a mut dyn crate::host::Construct<Error = E>>,
    pub(crate) temporary: Option<&'a mut dyn crate::host::TemporaryFiles<Error = E>>,
    pub(crate) leases: Option<&'a mut dyn crate::host::Lease<Error = E>>,
    pub(crate) source: Option<&'a mut dyn crate::host::SourceIO<Error = E>>,
    pub(crate) digest: Option<&'a mut dyn crate::host::Digest<Error = E>>,
    pub(crate) writes: Option<&'a mut dyn crate::host::ByteWrites<Error = E>>,
    pub(crate) bao: Option<&'a mut dyn crate::host::Bao<Error = E>>,
    pub(crate) sweep: Option<&'a mut dyn crate::host::Sweep<Error = E>>,
    pub(crate) memo: Option<&'a mut dyn crate::host::Memo<Error = E>>,
    pub(crate) redaction: Option<&'a mut dyn crate::host::Redaction<Error = E>>,
    pub(crate) apply: Option<&'a mut dyn crate::host::Apply<Error = E>>,
}

impl<E> Default for Capabilities<'_, E> {
    fn default() -> Self {
        Self {
            resources: None,
            crypto: None,
            files: None,
            clock: None,
            output: None,
            construct: None,
            temporary: None,
            leases: None,
            source: None,
            digest: None,
            writes: None,
            bao: None,
            sweep: None,
            memo: None,
            redaction: None,
            apply: None,
        }
    }
}

/// A protocol failure delivered into the program, so its own cleanup runs.
fn protocol_failure() -> Vec<u8> {
    let mut out = vec![1, 0];
    word(&mut out, 3);
    word(&mut out, 0);
    out
}

/// Append a host encoding to the output sink and reply with the count it
/// added, shaped by `wrap`. A sink that cannot grow is a protocol failure
/// delivered into the program, so its own cleanup still runs.
fn sink_reply<E, A: EncodeReply>(
    tag: u8,
    encoded: Vec<u8>,
    output: &mut dyn crate::host::Output<Error = OperationError<E>>,
    errors: &mut Vec<Option<E>>,
    wrap: impl FnOnce(u64) -> Option<A>,
) -> Vec<u8> {
    let count = encoded.len() as u64;
    match output.append(&encoded) {
        Ok(()) => match wrap(count) {
            Some(value) => reply(tag, Ok::<A, E>(value), errors, EncodeReply::encode),
            None => {
                let mut out = vec![1, 0];
                word(&mut out, 3);
                word(&mut out, 0);
                out
            }
        },
        Err(OperationError::Host(error)) => {
            reply(tag, Err::<A, _>(error), errors, EncodeReply::encode)
        }
        Err(_) => {
            let mut out = vec![1, 0];
            word(&mut out, 3);
            word(&mut out, 0);
            out
        }
    }
}

fn execute<E>(
    mut state: Handle,
    mut host: impl FnMut(
        Frame<'_>,
        &mut Capabilities<'_, E>,
        &mut Vec<Option<E>>,
    ) -> Result<Vec<u8>, OperationError<E>>,
    inputs: &[&[u8]],
    mut capabilities: Capabilities<'_, E>,
) -> Result<Vec<u8>, OperationError<E>> {
    let mut errors = Vec::new();
    loop {
        let packet = state.packet();
        let frame = decode(packet.as_bytes()).map_err(|()| OperationError::Protocol)?;
        let response = match frame {
            // The transferred bytes go from the file straight into the tail of
            // the output sink; they are never a reply payload. A sink that
            // cannot grow is a protocol failure delivered as a file failure,
            // so the program's close-before-return continuation still runs.
            Frame::Transfer(handle, offset, count) => {
                let files = capabilities
                    .files
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                let output = capabilities
                    .output
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                match output.grow(count) {
                    Ok(buffer) => match files.read_into(handle, offset, buffer) {
                        Ok(()) => vec![1, 52],
                        Err(failure) => {
                            output.shrink(count);
                            file_reply(52, Err::<(), _>(failure), &mut errors, |_, ()| {})
                        }
                    },
                    Err(OperationError::Host(error)) => file_reply(
                        52,
                        Err::<(), _>(FileFailure {
                            error,
                            kind: FileFailureKind::Other,
                        }),
                        &mut errors,
                        |_, ()| {},
                    ),
                    Err(_) => {
                        let mut out = vec![1, 0];
                        word(&mut out, 3);
                        word(&mut out, 0);
                        out.push(2);
                        out
                    }
                }
            }
            // A Bao encoding lands in the output sink the way a transfer does:
            // the host encodes exactly the groups the program named, and the
            // program learns only the byte count it appended.
            Frame::EncodeSlice(root, size, inline, spans) => {
                let bao = capabilities
                    .bao
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                let output = capabilities
                    .output
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                match bao.encode_slice(root, size, inline, &spans) {
                    Ok(encoded) => sink_reply(55, encoded, output, &mut errors, Some),
                    Err(error) => reply(55, Err::<u64, _>(error), &mut errors, EncodeReply::encode),
                }
            }
            Frame::EncodeProof(root, size, spans, level, budget) => {
                let bao = capabilities
                    .bao
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                let output = capabilities
                    .output
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                match bao.encode_proof(root, size, &spans, level, budget) {
                    Ok(Some(encoded)) => {
                        sink_reply(56, encoded, output, &mut errors, |count| Some(Some(count)))
                    }
                    Ok(None) => reply(
                        56,
                        Ok::<Option<u64>, _>(None),
                        &mut errors,
                        EncodeReply::encode,
                    ),
                    Err(error) => reply(
                        56,
                        Err::<Option<u64>, _>(error),
                        &mut errors,
                        EncodeReply::encode,
                    ),
                }
            }
            // Received encodings are decoded out of the run's byte inputs
            // straight into the object's files or inline buffer; the program
            // names the input by handle and never holds the encoding.
            Frame::DecodeInline(root, size, inline, spans, input) => {
                let bao = capabilities
                    .bao
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                match usize::try_from(input)
                    .ok()
                    .and_then(|input| inputs.get(input))
                {
                    Some(encoded) => reply(
                        57,
                        bao.decode_inline(root, size, inline, &spans, encoded),
                        &mut errors,
                        EncodeReply::encode,
                    ),
                    None => protocol_failure(),
                }
            }
            Frame::DecodeSlice(root, size, spans, input) => {
                let bao = capabilities
                    .bao
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                match usize::try_from(input)
                    .ok()
                    .and_then(|input| inputs.get(input))
                {
                    Some(encoded) => reply(
                        58,
                        bao.decode_slice(root, size, &spans, encoded),
                        &mut errors,
                        EncodeReply::encode,
                    ),
                    None => protocol_failure(),
                }
            }
            Frame::WriteProof(root, size, spans, level, input) => {
                let bao = capabilities
                    .bao
                    .as_deref_mut()
                    .ok_or(OperationError::Protocol)?;
                match usize::try_from(input)
                    .ok()
                    .and_then(|input| inputs.get(input))
                {
                    Some(encoded) => reply(
                        61,
                        bao.write_proof(root, size, &spans, level, encoded),
                        &mut errors,
                        |out, (wrote, proven)| {
                            out.push(u8::from(wrote));
                            word(out, proven.len() as u64);
                            for (start, groups, cv, whole) in proven {
                                word(out, start);
                                word(out, groups);
                                bytes(out, &cv);
                                out.push(u8::from(whole));
                            }
                        },
                    ),
                    None => protocol_failure(),
                }
            }
            Frame::Append(bytes) => match capabilities.output.as_deref_mut() {
                Some(output) => match output.append(bytes) {
                    Ok(()) => vec![1, 37],
                    Err(OperationError::Host(error)) => {
                        reply(37, Err::<(), _>(error), &mut errors, |_, ()| {})
                    }
                    // An allocation/capacity failure is not an invented backing
                    // store error. Deliver protocol failure into Lean so its
                    // resource cleanup executes before the operation terminates.
                    Err(_) => {
                        let mut out = vec![1, 0];
                        word(&mut out, 3);
                        word(&mut out, 0);
                        out
                    }
                },
                None => return Err(OperationError::Protocol),
            },
            Frame::ReadInput(handle, offset, count) => {
                let selected = usize::try_from(handle)
                    .ok()
                    .and_then(|handle| inputs.get(handle))
                    .and_then(|input| {
                        let start = usize::try_from(offset).ok()?;
                        let count = usize::try_from(count).ok()?;
                        input.get(start..start.checked_add(count)?)
                    });
                match selected {
                    Some(input) => {
                        let mut out = vec![1, 23];
                        bytes(&mut out, input);
                        out
                    }
                    None => {
                        let mut out = vec![1, 0];
                        word(&mut out, 3);
                        word(&mut out, 0);
                        out
                    }
                }
            }
            Frame::Done(result) => return Ok(result.to_vec()),
            Frame::Failure(code, token) => {
                return Err(match (code, token) {
                    (1, token) if token > 0 => errors
                        .get_mut((token - 1) as usize)
                        .and_then(Option::take)
                        .map(OperationError::Host)
                        .unwrap_or(OperationError::Protocol),
                    (2, detail) => OperationError::MalformedMetadata(detail),
                    _ => OperationError::Protocol,
                })
            }
            frame => host(frame, &mut capabilities, &mut errors)?,
        };
        // No request borrows packet data past this point. Release the packet
        // before constructing the next continuation to limit peak retention.
        drop(packet);
        state.resume(&response);
    }
}

/// Start a Lean command; the fresh continuation is owned here until the run
/// ends.
fn start(command: &Command) -> Handle {
    let mut packet = Vec::new();
    command.encode(&mut packet);
    native::start(&packet)
}

/// Run one command over the relational host and whatever raw services it may
/// direct, without exposing continuations to the caller. Borrowed input
/// buffers live until the run returns.
pub(crate) fn run<S: Storage>(
    storage: &mut S,
    capabilities: Capabilities<'_, S::Error>,
    inputs: &[&[u8]],
    command: &Command,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    let state = start(command);
    execute(
        state,
        |frame, capabilities, errors| dispatch(storage, capabilities, frame, errors),
        inputs,
        capabilities,
    )
}

/// Same ownership contract as `run`, narrowed to byte-reading capabilities.
pub(crate) fn run_readonly<S: ByteStorage>(
    storage: &mut S,
    inputs: &[&[u8]],
    command: &Command,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    let state = start(command);
    execute(
        state,
        |frame, capabilities, errors| {
            dispatch_readonly(Some(&mut *storage), capabilities, frame, errors)
        },
        inputs,
        Capabilities::default(),
    )
}

/// Same ownership contract as `run`, narrowed to byte reads, content-addressed
/// byte writes and the digest primitive: what a trie write needs and nothing
/// relational.
pub(crate) fn run_bytes<S: ByteStorage>(
    storage: &mut S,
    writes: &mut dyn crate::host::ByteWrites<Error = S::Error>,
    digest: &mut dyn crate::host::Digest<Error = S::Error>,
    inputs: &[&[u8]],
    command: &Command,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    let state = start(command);
    let capabilities = Capabilities {
        digest: Some(digest),
        writes: Some(writes),
        ..Capabilities::default()
    };
    execute(
        state,
        |frame, capabilities, errors| {
            dispatch_readonly(Some(&mut *storage), capabilities, frame, errors)
        },
        inputs,
        capabilities,
    )
}

/// Same ownership contract as `run`, narrowed to byte reads and the walk
/// services the caller supplies (the refusals, the digest, the materializer):
/// what a structural walk over the trie needs and nothing relational.
pub(crate) fn run_walk<S: ByteStorage>(
    storage: &mut S,
    capabilities: Capabilities<'_, S::Error>,
    inputs: &[&[u8]],
    command: &Command,
) -> Result<Vec<u8>, OperationError<S::Error>> {
    let state = start(command);
    execute(
        state,
        |frame, capabilities, errors| {
            dispatch_readonly(Some(&mut *storage), capabilities, frame, errors)
        },
        inputs,
        capabilities,
    )
}

/// Same ownership contract as `run`, narrowed to the digest primitive: no
/// storage of any kind is reachable, so a byte read is a protocol failure.
pub(crate) fn run_digest<D: crate::host::Digest>(
    digest: &mut D,
    inputs: &[&[u8]],
    command: &Command,
) -> Result<Vec<u8>, OperationError<D::Error>> {
    let state = start(command);
    let capabilities = Capabilities {
        digest: Some(digest),
        ..Capabilities::default()
    };
    execute(
        state,
        |frame, capabilities, errors| {
            dispatch_readonly::<NoBytes<D::Error>>(None, capabilities, frame, errors)
        },
        inputs,
        capabilities,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::IngestInput;

    #[derive(Default)]
    struct ByteHost {
        reads: usize,
        failure: Option<Box<u8>>,
        value: Option<Vec<u8>>,
    }

    impl ByteStorage for ByteHost {
        type Error = Box<u8>;

        fn read_bytes(&mut self, _: &str, _: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            self.reads += 1;
            match self.failure.take() {
                Some(error) => Err(error),
                None => Ok(self.value.clone()),
            }
        }
    }

    #[test]
    fn byte_only_dispatch_rejects_relational_capabilities_without_host_calls() {
        let mut host = ByteHost::default();
        let mut errors = Vec::new();
        let selection = || Selection {
            relation: "table".into(),
            equals: vec![],
            like_any: vec![],
            not_equals: vec![],
        };
        for frame in [
            Frame::Begin,
            Frame::Commit(1),
            Frame::Rollback(1),
            Frame::ReadRows(1, "table".into(), vec![], vec![], vec![], vec![]),
            Frame::Upsert(1, "table".into(), vec![], vec![], vec![]),
            Frame::DeleteRows(1, "table".into(), vec![], vec![], vec![]),
            Frame::ExistsRows(1, "table".into(), vec![]),
            Frame::ScanRows(1, "table".into(), vec![], vec![], vec![], vec![]),
            Frame::Write(1, "table".into(), vec![], vec![], vec![]),
            Frame::Snapshot(selection(), vec![]),
            Frame::Update(1, selection(), vec![]),
            Frame::CopyRows(1, "table".into(), selection(), vec![], vec![]),
            Frame::Delete(1, selection()),
        ] {
            assert!(matches!(
                dispatch_readonly(
                    Some(&mut host),
                    &mut Capabilities::default(),
                    frame,
                    &mut errors
                ),
                Err(OperationError::Protocol)
            ));
        }
        assert_eq!(host.reads, 0);
        assert!(errors.is_empty());
    }

    #[test]
    fn byte_only_native_runner_rejects_transactional_programs() {
        let mut host = ByteHost::default();
        // This deliberately supplies only byte capabilities to a program whose
        // first effect is begin.
        let command = Command::Acquire {
            root: vec![9; 32],
            holder: "holder".into(),
            now: 0,
            possession: true,
        };
        let result = run_readonly(&mut host, &[], &command);
        assert!(matches!(result, Err(OperationError::Protocol)));
        assert_eq!(host.reads, 0);
    }

    #[test]
    fn byte_only_native_lookup_returns_the_original_error_allocation() {
        let original = Box::new(71);
        let address = &*original as *const u8;
        let mut host = ByteHost {
            failure: Some(original),
            ..ByteHost::default()
        };
        match crate::trie::get(&mut host, &[1; 32], &[]) {
            Err(crate::trie::LookupError::Host(error)) => {
                assert_eq!(&*error as *const u8, address);
                assert_eq!(*error, 71);
            }
            other => panic!("expected the original backing error, got {other:?}"),
        }
        assert_eq!(host.reads, 1);
        assert!(host.failure.is_none());
    }

    #[test]
    fn byte_only_dispatch_distinguishes_absence_from_empty_bytes() {
        let mut host = ByteHost::default();
        let mut errors = Vec::new();
        let key = [1; 32];
        let frame = || Frame::ReadBytes("trie_nodes".into(), &key);
        let mut none = Capabilities::default();
        assert_eq!(
            dispatch_readonly(Some(&mut host), &mut none, frame(), &mut errors).unwrap(),
            vec![1, 22, 0]
        );
        host.value = Some(vec![]);
        assert_eq!(
            dispatch_readonly(Some(&mut host), &mut none, frame(), &mut errors).unwrap(),
            vec![1, 22, 1, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(host.reads, 2);
        assert!(errors.is_empty());
    }

    #[test]
    fn native_ingestion_constructor_owns_input_admission_and_failure_continuation() {
        let commands = [
            (0, Some(IngestInput::Bytes(0))),
            (1, Some(IngestInput::File)),
            (255, None),
        ];
        for (kind, input) in commands {
            // Each command starts one fresh owned continuation. An undecodable
            // packet is the third case: a protocol failure before any effect.
            let mut state = match input {
                Some(input) => start(&Command::Ingest {
                    input,
                    now: i64::MIN,
                    cache: false,
                    allow_unsupported: false,
                }),
                None => native::start(&[255]),
            };
            match (kind, decode(state.packet().as_bytes()).unwrap()) {
                (0, Frame::Open(space, key)) => {
                    assert_eq!(space, "input");
                    assert!(key.is_empty());
                }
                (1, Frame::Stat(space, key)) => {
                    assert_eq!(space, "input");
                    assert!(key.is_empty());
                }
                (255, Frame::Failure(3, 0)) => continue,
                _ => panic!("unexpected ingestion start"),
            }
            let mut failed = vec![1, 0];
            word(&mut failed, 1);
            word(&mut failed, 77);
            if kind == 0 {
                failed.push(2);
            } // Generic FileIO error classification.
            state.resume(&failed);
            assert!(matches!(
                decode(state.packet().as_bytes()),
                Ok(Frame::Failure(1, 77))
            ));
        }
    }

    #[test]
    fn ingestion_frames_are_exact_and_borrow_payloads() {
        let mut packet = vec![1, 39];
        bytes(&mut packet, &[41, 42]);
        match decode(&packet).unwrap() {
            Frame::Hash(payload) => {
                assert_eq!(payload, [41, 42]);
                assert_eq!(payload.as_ptr(), packet[10..].as_ptr());
            }
            _ => panic!("unexpected frame"),
        }
        for end in 0..packet.len() {
            assert!(decode(&packet[..end]).is_err());
        }
        packet.push(0);
        assert!(decode(&packet).is_err());
        let mut build = vec![1, 38];
        for value in [1, 2, 3, u64::MAX] {
            word(&mut build, value);
        }
        assert!(matches!(
            decode(&build),
            Ok(Frame::Build(1, 2, 3, u64::MAX))
        ));
        for end in 0..build.len() {
            assert!(decode(&build[..end]).is_err());
        }
        build.push(0);
        assert!(decode(&build).is_err());
        for tag in [43, 45, 48] {
            let mut packet = vec![1, tag];
            word(&mut packet, 7);
            assert!(decode(&packet).is_ok());
            packet.push(0);
            assert!(decode(&packet).is_err());
        }
    }

    #[test]
    fn hash_frames_reject_hostile_lengths_and_stale_tags() {
        let mut packet = vec![1, 39];
        word(&mut packet, u64::MAX);
        assert!(decode(&packet).is_err());
        // The retired per-chunk primitive tag is no longer a request.
        let mut parent = vec![1, 40, 1];
        bytes(&mut parent, &[0; 32]);
        bytes(&mut parent, &[0; 32]);
        assert!(decode(&parent).is_err());
    }

    #[test]
    fn expression_decoder_bounds_recursion_and_total_nodes() {
        let mut deep = vec![2; 34];
        deep.push(0);
        bytes(&mut deep, b"size");
        assert!(Reader(&deep).conflict_expression(0, &mut 4096).is_err());
        let leaf = [0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(Reader(&leaf).conflict_expression(0, &mut 0).is_err());
        assert!(Reader(&[4]).conflict_expression(0, &mut 4096).is_err());
        let mut pair = vec![3];
        pair.extend_from_slice(&leaf);
        pair.extend_from_slice(&leaf);
        assert!(Reader(&pair).conflict_expression(0, &mut 2).is_err());
        assert!(matches!(
            Reader(&pair).conflict_expression(0, &mut 3),
            Ok(crate::host::ConflictValue::Maximum(_))
        ));
        let mut packet = vec![1, 41];
        word(&mut packet, 1);
        bytes(&mut packet, b"blobs");
        word(&mut packet, 0);
        word(&mut packet, 0);
        word(&mut packet, u64::MAX);
        assert!(decode(&packet).is_err());
    }

    #[test]
    fn ingestion_failures_preserve_opaque_errors_in_generic_replies() {
        for tag in 38..=52 {
            let mut errors = Vec::new();
            let response = reply(tag, Err::<(), _>("original"), &mut errors, |_, ()| {});
            assert_eq!(errors, vec![Some("original")]);
            let mut expected = vec![1, 0];
            word(&mut expected, 1);
            word(&mut expected, 1);
            assert_eq!(response, expected);
        }
    }

    #[test]
    fn source_frames_preserve_unsigned_coordinates_and_borrow_frozen_bytes() {
        let mut read = vec![1, 50];
        for value in [7, u64::MAX, 65536] {
            word(&mut read, value);
        }
        assert!(matches!(
            decode(&read),
            Ok(Frame::ReadSome(7, u64::MAX, 65536))
        ));
        let mut frozen = vec![1, 51];
        bytes(&mut frozen, &[41, 42]);
        match decode(&frozen).unwrap() {
            Frame::Freeze(bytes) => assert_eq!(bytes.as_ptr(), frozen[10..].as_ptr()),
            _ => panic!("unexpected frame"),
        }
        for packet in [&read, &frozen] {
            for end in 0..packet.len() {
                assert!(decode(&packet[..end]).is_err());
            }
            let mut trailing = packet.clone();
            trailing.push(0);
            assert!(decode(&trailing).is_err());
        }
    }
    use crate::cas::acquire;

    #[test]
    fn terminal_frame_borrows_payload_and_rejects_nonexact_lengths() {
        let mut packet = vec![1, 0];
        word(&mut packet, 3);
        packet.extend_from_slice(&[3, 5, 7]);
        match decode(&packet).unwrap() {
            Frame::Done(payload) => {
                assert_eq!(payload, [3, 5, 7]);
                assert_eq!(payload.as_ptr(), packet[10..].as_ptr());
            }
            _ => panic!("expected terminal frame"),
        }
        for length in 0..packet.len() {
            assert!(decode(&packet[..length]).is_err());
        }
        packet.push(0);
        assert!(decode(&packet).is_err());
    }

    #[test]
    fn output_request_borrows_bounded_bytes_with_exact_framing() {
        let mut packet = vec![1, 37];
        bytes(&mut packet, &[9, 8, 7]);
        match decode(&packet).unwrap() {
            Frame::Append(payload) => {
                assert_eq!(payload, [9, 8, 7]);
                assert_eq!(payload.as_ptr(), packet[10..].as_ptr());
            }
            _ => panic!("expected output request"),
        }
        for length in 0..packet.len() {
            assert!(decode(&packet[..length]).is_err());
        }
        packet.push(0);
        assert!(decode(&packet).is_err());
    }

    struct OutputTestFiles(Vec<&'static str>);
    impl FileIO for OutputTestFiles {
        type Error = &'static str;
        fn open(&mut self, _: &str, _: &[u8]) -> Result<u64, FileFailure<Self::Error>> {
            self.0.push("open");
            Ok(9)
        }
        fn read_into(
            &mut self,
            handle: u64,
            offset: u64,
            buffer: &mut [u8],
        ) -> Result<(), FileFailure<Self::Error>> {
            assert_eq!((handle, offset, buffer.len()), (9, 0, 65540));
            self.0.push("transfer");
            buffer.fill(7);
            Ok(())
        }
        fn close(&mut self, handle: u64) -> Result<(), Self::Error> {
            assert_eq!(handle, 9);
            self.0.push("close");
            Ok(())
        }

        host_unexpected!(read_at);
    }
    impl Clock for OutputTestFiles {
        type Error = &'static str;

        host_unexpected!(now_ns);
    }
    struct FailingOutput {
        host: Option<bool>,
        bytes: Vec<u8>,
        grown: usize,
        shrunk: usize,
    }
    impl crate::host::Output for FailingOutput {
        type Error = OperationError<&'static str>;
        fn append(&mut self, _: &[u8]) -> Result<(), Self::Error> {
            panic!("a file read never appends a reply payload")
        }
        fn grow(&mut self, count: u64) -> Result<&mut [u8], Self::Error> {
            assert_eq!(count, 65540);
            self.grown += 1;
            match self.host {
                Some(true) => Err(OperationError::Host("sink")),
                Some(false) => Err(OperationError::Protocol),
                None => {
                    let start = self.bytes.len();
                    self.bytes.resize(start + count as usize, 0);
                    Ok(&mut self.bytes[start..])
                }
            }
        }
        fn shrink(&mut self, count: u64) {
            self.shrunk += 1;
            self.bytes.truncate(self.bytes.len() - count as usize);
        }
    }
    #[test]
    fn output_failures_resume_lean_and_close_before_termination() {
        for host in [Some(true), Some(false), None] {
            let mut storage = Script::default();
            let mut files = OutputTestFiles(vec![]);
            let mut clock = OutputTestFiles(vec![]);
            let mut output = FailingOutput {
                host,
                bytes: vec![],
                grown: 0,
                shrunk: 0,
            };
            let result = run(
                &mut storage,
                Capabilities {
                    files: Some(&mut files),
                    clock: Some(&mut clock),
                    output: Some(&mut output),
                    ..Capabilities::default()
                },
                &[],
                &Command::Read {
                    root: vec![7; 32],
                    range: None,
                },
            );
            match host {
                Some(true) => assert!(matches!(result, Err(OperationError::Host("sink")))),
                Some(false) => assert!(matches!(result, Err(OperationError::Protocol))),
                None => {
                    assert_eq!(result.unwrap(), [0, 4, 0, 1, 0, 0, 0, 0, 0]);
                    assert!(output.bytes.iter().all(|byte| *byte == 7));
                    assert_eq!(output.bytes.len(), 65540);
                }
            }
            assert_eq!(storage.calls, ["snapshot"]);
            assert_eq!(
                files.0,
                if host.is_some() {
                    vec!["open", "close"]
                } else {
                    vec!["open", "transfer", "close"]
                }
            );
            assert_eq!((output.grown, output.shrunk), (1, 0));
        }
    }

    struct ShortFile;
    impl FileIO for ShortFile {
        type Error = &'static str;
        fn open(&mut self, _: &str, _: &[u8]) -> Result<u64, FileFailure<Self::Error>> {
            Ok(9)
        }
        fn read_into(
            &mut self,
            _: u64,
            _: u64,
            buffer: &mut [u8],
        ) -> Result<(), FileFailure<Self::Error>> {
            buffer.fill(1);
            Err(FileFailure {
                error: "truncated",
                kind: FileFailureKind::ShortRead,
            })
        }
        fn close(&mut self, _: u64) -> Result<(), Self::Error> {
            Ok(())
        }

        host_unexpected!(read_at);
    }
    #[test]
    fn failed_transfer_takes_back_the_grown_tail() {
        let mut errors = Vec::new();
        let mut files = ShortFile;
        let mut sink = FailingOutput {
            host: None,
            bytes: vec![9, 9],
            grown: 0,
            shrunk: 0,
        };
        let response = {
            let files: &mut dyn FileIO<Error = &'static str> = &mut files;
            let output: &mut dyn crate::host::Output<Error = OperationError<&'static str>> =
                &mut sink;
            match output.grow(65540) {
                Ok(buffer) => match files.read_into(9, 0, buffer) {
                    Ok(()) => vec![1, 52],
                    Err(failure) => {
                        output.shrink(65540);
                        file_reply(52, Err::<(), _>(failure), &mut errors, |_, ()| {})
                    }
                },
                Err(_) => panic!("the sink grows"),
            }
        };
        assert_eq!(sink.bytes, [9, 9]);
        assert_eq!((sink.grown, sink.shrunk), (1, 1));
        assert_eq!(errors, [Some("truncated")]);
        let mut expected = vec![1, 0];
        word(&mut expected, 1);
        word(&mut expected, 1);
        expected.push(1);
        assert_eq!(response, expected);
    }

    fn selection_packet(out: &mut Vec<u8>) {
        bytes(out, b"raw_table");
        word(out, 1);
        bytes(out, b"id");
        cell(out, &Cell::Blob(vec![0, 255]));
        word(out, 1);
        bytes(out, b"name");
        bytes(out, b"prefix/%");
        word(out, 1);
        bytes(out, b"durable");
        cell(out, &Cell::Integer(0));
    }

    #[test]
    fn access_and_file_requests_have_exact_closed_framing() {
        let mut packets = Vec::new();
        let mut snapshot = vec![1, 29];
        selection_packet(&mut snapshot);
        word(&mut snapshot, 1);
        bytes(&mut snapshot, b"value");
        match decode(&snapshot).unwrap() {
            Frame::Snapshot(selection, columns) => {
                assert_eq!(selection.relation, "raw_table");
                assert_eq!(selection.equals, [("id".into(), Cell::Blob(vec![0, 255]))]);
                assert_eq!(selection.like_any, [("name".into(), "prefix/%".into())]);
                assert_eq!(selection.not_equals, [("durable".into(), Cell::Integer(0))]);
                assert_eq!(columns, ["value"]);
            }
            _ => panic!("unexpected snapshot frame"),
        }
        packets.push(snapshot);
        let mut update = vec![1, 30];
        word(&mut update, 9);
        selection_packet(&mut update);
        word(&mut update, 1);
        bytes(&mut update, b"value");
        cell(&mut update, &Cell::Integer(i64::MIN));
        assert!(matches!(decode(&update), Ok(Frame::Update(9, _, _))));
        packets.push(update);
        let mut copy = vec![1, 31];
        word(&mut copy, 9);
        bytes(&mut copy, b"destination");
        selection_packet(&mut copy);
        word(&mut copy, 2);
        bytes(&mut copy, b"literal");
        let source_tag = copy.len();
        copy.push(0);
        cell(&mut copy, &Cell::RawText(vec![255]));
        bytes(&mut copy, b"projected");
        copy.push(1);
        bytes(&mut copy, b"source_column");
        word(&mut copy, 1);
        bytes(&mut copy, b"literal");
        match decode(&copy).unwrap() {
            Frame::CopyRows(9, target, _, values, conflicts) => {
                assert_eq!(target, "destination");
                assert_eq!(
                    values,
                    [
                        (
                            "literal".into(),
                            SourceValue::Literal(Cell::RawText(vec![255]))
                        ),
                        (
                            "projected".into(),
                            SourceValue::Column("source_column".into())
                        ),
                    ]
                );
                assert_eq!(conflicts, ["literal"]);
            }
            _ => panic!("unexpected copy frame"),
        }
        let mut invalid = copy.clone();
        invalid[source_tag] = 2;
        assert!(decode(&invalid).is_err());
        packets.push(copy);
        let mut delete = vec![1, 32];
        word(&mut delete, 9);
        selection_packet(&mut delete);
        assert!(matches!(decode(&delete), Ok(Frame::Delete(9, _))));
        packets.push(delete);
        let mut open = vec![1, 33];
        bytes(&mut open, b"files");
        bytes(&mut open, &[0, 255]);
        assert!(matches!(decode(&open), Ok(Frame::Open(_, _))));
        packets.push(open);
        let mut read = vec![1, 34];
        for value in [42, u64::MAX, 0] {
            word(&mut read, value);
        }
        assert!(matches!(decode(&read), Ok(Frame::ReadAt(42, u64::MAX, 0))));
        packets.push(read);
        let mut close = vec![1, 35];
        word(&mut close, 42);
        assert!(matches!(decode(&close), Ok(Frame::Close(42))));
        packets.push(close);
        let mut transfer = vec![1, 52];
        for value in [42, u64::MAX, 65536] {
            word(&mut transfer, value);
        }
        assert!(matches!(
            decode(&transfer),
            Ok(Frame::Transfer(42, u64::MAX, 65536))
        ));
        packets.push(transfer);
        assert!(matches!(decode(&[1, 36]), Ok(Frame::NowNs)));
        packets.push(vec![1, 36]);
        for mut packet in packets {
            for length in 0..packet.len() {
                assert!(decode(&packet[..length]).is_err());
            }
            packet.push(0);
            assert!(decode(&packet).is_err());
        }
    }

    #[test]
    fn file_failures_keep_original_errors_and_classification_separate() {
        let mut errors = vec![Some("earlier")];
        for (kind, expected) in [
            (FileFailureKind::Missing, 0),
            (FileFailureKind::ShortRead, 1),
            (FileFailureKind::Other, 2),
        ] {
            let encoded = file_reply(
                33,
                Err::<u64, _>(FileFailure {
                    error: "original",
                    kind,
                }),
                &mut errors,
                word,
            );
            let mut reader = Reader(&encoded);
            assert_eq!(reader.byte(), Ok(1));
            assert_eq!(reader.byte(), Ok(0));
            assert_eq!(reader.word(), Ok(1));
            let token = reader.word().unwrap();
            assert_eq!(errors[(token - 1) as usize], Some("original"));
            assert_eq!(reader.byte(), Ok(expected));
            reader.end().unwrap();
        }
        assert_eq!(errors[0], Some("earlier"));
        let encoded = file_reply(33, Ok(42), &mut errors, word);
        let mut reader = Reader(&encoded);
        assert_eq!(reader.byte(), Ok(1));
        assert_eq!(reader.byte(), Ok(33));
        assert_eq!(reader.word(), Ok(42));
        reader.end().unwrap();
        assert_eq!(errors.len(), 4);
    }

    #[test]
    fn snapshot_scan_encodes_prefix_before_original_trailing_failure() {
        let mut errors = Vec::new();
        let packet = scan_reply(
            29,
            Ok(Scan {
                rows: vec![vec![Cell::Null]],
                failure: Some("step"),
            }),
            &mut errors,
        );
        let mut reader = Reader(&packet);
        assert_eq!(reader.byte(), Ok(1));
        assert_eq!(reader.byte(), Ok(29));
        assert_eq!(reader.word(), Ok(1));
        assert_eq!(reader.word(), Ok(1));
        assert_eq!(reader.cell(), Ok(Cell::Null));
        assert_eq!(reader.byte(), Ok(1));
        assert_eq!(reader.word(), Ok(1));
        assert_eq!(reader.word(), Ok(1));
        reader.end().unwrap();
        assert_eq!(errors, [Some("step")]);
    }

    #[test]
    fn cell_packets_preserve_real_bits_and_unvalidated_text() {
        for value in [
            Cell::Real(1.5f64.to_bits()),
            Cell::Real(u64::MAX),
            Cell::RawText(vec![255, 0, 254]),
        ] {
            let mut encoded = Vec::new();
            cell(&mut encoded, &value);
            let mut reader = Reader(&encoded);
            assert_eq!(reader.cell().unwrap(), value);
            reader.end().unwrap();
        }
    }

    #[test]
    fn ordered_and_guarded_packets_are_exact_and_fail_closed() {
        let mut read = vec![1, 19];
        word(&mut read, 7);
        bytes(&mut read, b"head_history");
        word(&mut read, 1);
        bytes(&mut read, b"seq");
        word(&mut read, 0); // equality fields
        word(&mut read, 1); // order terms
        bytes(&mut read, b"seq");
        read.push(1);
        let direction_offset = read.len() - 1;
        word(&mut read, 0); // joins
        match decode(&read).unwrap() {
            Frame::ReadRows(7, relation, columns, equals, order, joins) => {
                assert!(joins.is_empty());
                assert_eq!(relation, "head_history");
                assert_eq!(columns, ["seq"]);
                assert!(equals.is_empty());
                assert_eq!(
                    order,
                    [Order {
                        column: "seq".into(),
                        descending: true
                    }]
                );
            }
            _ => panic!("wrong request kind"),
        }
        let mut joined = read[..read.len() - 8].to_vec();
        word(&mut joined, 1);
        bytes(&mut joined, b"pins");
        word(&mut joined, 1);
        bytes(&mut joined, b"root");
        bytes(&mut joined, b"root");
        match decode(&joined).unwrap() {
            Frame::ReadRows(_, _, _, _, _, joins) => assert_eq!(
                joins,
                [Join {
                    relation: "pins".into(),
                    keys: vec![("root".into(), "root".into())],
                }]
            ),
            _ => panic!("wrong request kind"),
        }
        for length in 0..joined.len() {
            assert!(decode(&joined[..length]).is_err());
        }
        read[direction_offset] = 2;
        assert!(decode(&read).is_err());
        let mut delete = vec![1, 21];
        word(&mut delete, 7);
        bytes(&mut delete, b"head_history");
        word(&mut delete, 0);
        word(&mut delete, 1);
        bytes(&mut delete, b"heads");
        word(&mut delete, 1);
        bytes(&mut delete, b"seq");
        cell(&mut delete, &Cell::Integer(-1));
        word(&mut delete, 1);
        bytes(&mut delete, b"root");
        bytes(&mut delete, b"root");
        word(&mut delete, 1);
        bytes(&mut delete, b"seq");
        cell(&mut delete, &Cell::Integer(i64::MIN));
        match decode(&delete).unwrap() {
            Frame::DeleteRows(7, _, _, blockers, at_most) => {
                assert_eq!(at_most, vec![("seq".into(), Cell::Integer(i64::MIN))]);
                assert_eq!(
                    blockers,
                    [Exclusion {
                        relation: "heads".into(),
                        equals: vec![("seq".into(), Cell::Integer(-1))],
                        keys: vec![("root".into(), "root".into())],
                    }]
                );
            }
            _ => panic!("wrong request kind"),
        }
        for length in 0..delete.len() {
            assert!(decode(&delete[..length]).is_err());
        }
        delete.push(0);
        assert!(decode(&delete).is_err());
    }

    #[derive(Default)]
    struct Script {
        calls: Vec<&'static str>,
        fail_at: Option<usize>,
        rollback_fails: bool,
    }
    impl Script {
        fn step(&mut self, label: &'static str) -> Result<(), &'static str> {
            let index = self.calls.len();
            self.calls.push(label);
            if self.fail_at == Some(index) {
                Err("primary")
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Script {
        fn scan_rows(
            &mut self,
            tx: u64,
            relation: &str,
            columns: &[String],
            equals: &crate::host::Fields,
            order: &[crate::host::Order],
            joins: &[crate::host::Join],
        ) -> Result<crate::host::Scan<Self::Error>, Self::Error> {
            self.read_rows(tx, relation, columns, equals, order, joins)
                .map(|rows| crate::host::Scan {
                    rows,
                    failure: None,
                })
        }

        type Error = &'static str;
        fn begin(&mut self) -> Result<u64, Self::Error> {
            self.step("begin")?;
            Ok(42)
        }
        fn commit(&mut self, tx: u64) -> Result<(), Self::Error> {
            assert_eq!(tx, 42);
            self.step("commit")
        }
        fn rollback(&mut self, tx: u64) -> Result<(), Self::Error> {
            assert_eq!(tx, 42);
            self.step("rollback")?;
            if self.rollback_fails {
                Err("rollback")
            } else {
                Ok(())
            }
        }
        fn read_rows(
            &mut self,
            tx: u64,
            relation: &str,
            columns: &[String],
            equals: &Fields,
            _order: &[crate::host::Order],
            _joins: &[crate::host::Join],
        ) -> Result<Vec<Row>, Self::Error> {
            assert_eq!(tx, 42);
            assert_eq!(equals[0], ("root".into(), Cell::Blob(vec![9; 32])));
            match relation {
                "blobs" => {
                    self.step("durable")?;
                    assert_eq!(columns, &["durable"]);
                    Ok(vec![vec![Cell::Integer(-7)]])
                }
                "content_want" => {
                    self.step("want")?;
                    assert_eq!(columns, &["root"]);
                    Ok(vec![vec![Cell::Blob(vec![9; 32])]])
                }
                _ => panic!("unexpected relation"),
            }
        }
        fn upsert(
            &mut self,
            tx: u64,
            relation: &str,
            values: &Fields,
            conflicts: &[String],
            updates: &[String],
        ) -> Result<(), Self::Error> {
            assert_eq!(tx, 42);
            assert_eq!(relation, "pins");
            assert_eq!(conflicts, &["root", "holder"]);
            assert_eq!(updates, &["release_after"]);
            assert_eq!(values[2], ("created_at".into(), Cell::Integer(-11)));
            assert_eq!(values[3], ("release_after".into(), Cell::Null));
            self.step("upsert")
        }
        fn delete_rows(
            &mut self,
            tx: u64,
            relation: &str,
            equals: &Fields,
            _unless: &[crate::host::Exclusion],
            at_most: &Fields,
        ) -> Result<u64, Self::Error> {
            assert!(at_most.is_empty());
            assert_eq!(tx, 42);
            assert_eq!(relation, "content_want");
            assert_eq!(equals[1], ("holder".into(), Cell::Text("holder".into())));
            self.step("delete")?;
            Ok(1)
        }
        fn snapshot(
            &mut self,
            _: &Selection,
            _: &[String],
        ) -> Result<Scan<Self::Error>, Self::Error> {
            self.step("snapshot")?;
            Ok(Scan {
                rows: vec![vec![
                    Cell::Blob(vec![7; 32]),
                    Cell::Integer(65540),
                    Cell::Integer(1),
                    Cell::Null,
                    Cell::Null,
                    Cell::Integer(0),
                    Cell::Integer(1),
                ]],
                failure: None,
            })
        }

        host_unexpected!(
            exists_rows,
            delete_except,
            read_bytes,
            update,
            copy_rows,
            delete,
            write,
            snapshot_excluding
        );
    }

    #[test]
    fn acquisition_native_program_owns_complete_storage_trace() {
        let mut script = Script::default();
        assert!(acquire(&mut script, &[9; 32], "holder", -11, true).unwrap());
        assert_eq!(
            script.calls,
            ["begin", "durable", "want", "delete", "upsert", "commit"]
        );
    }

    #[test]
    fn each_native_effect_failure_stops_and_preserves_primary_error() {
        let normal = ["begin", "durable", "want", "delete", "upsert", "commit"];
        for index in 0..normal.len() {
            for rollback_fails in [false, true] {
                let mut script = Script {
                    fail_at: Some(index),
                    rollback_fails,
                    ..Script::default()
                };
                assert!(matches!(
                    acquire(&mut script, &[9; 32], "holder", -11, true),
                    Err(crate::cas::LifecycleError::Operation(OperationError::Host(
                        "primary"
                    )))
                ));
                let mut expected = normal[..=index].to_vec();
                if index > 0 {
                    expected.push("rollback");
                }
                assert_eq!(script.calls, expected);
            }
        }
    }

    fn state() -> Handle {
        start(&Command::Acquire {
            root: vec![9; 32],
            holder: "holder".into(),
            now: 0,
            possession: true,
        })
    }

    #[test]
    fn packet_owner_keeps_bytes_live_after_state_resume_and_drop() {
        let mut state = state();
        let first = state.packet();
        let mut begun = vec![1, 16];
        word(&mut begun, 42);
        state.resume(&begun);
        let second = state.packet();
        drop(state);
        assert_eq!(first.as_bytes(), [1, 16]);
        assert!(matches!(
            decode(second.as_bytes()),
            Ok(Frame::ReadRows(42, ..))
        ));
    }

    #[test]
    fn owned_resume_preserves_independent_packets_across_unwinding() {
        let mut state = state();
        let initial_packet = state.packet();
        let mut begun = vec![1, 16];
        word(&mut begun, 42);
        state.resume(&begun);
        let read_packet = state.packet();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            state.resume(&[1, 17]);
            assert!(matches!(
                decode(state.packet().as_bytes()),
                Ok(Frame::Rollback(42))
            ));
            panic!("injected unwind after ownership transfer");
        }));
        assert!(result.is_err());
        assert_eq!(initial_packet.as_bytes(), [1, 16]);
        assert!(matches!(
            decode(read_packet.as_bytes()),
            Ok(Frame::ReadRows(42, ..))
        ));
    }

    #[test]
    fn terminal_owned_resumes_cannot_reenter_or_invalidate_prior_packets() {
        let mut state = state();
        state.resume(&[1, 17]); // Failed begin: no transaction was acquired.
        let terminal_packet = state.packet();
        for _ in 0..64 {
            state.resume(&[1, 16]);
            assert!(matches!(
                decode(state.packet().as_bytes()),
                Ok(Frame::Failure(3, 0))
            ));
        }
        drop(state);
        assert!(matches!(
            decode(terminal_packet.as_bytes()),
            Ok(Frame::Failure(3, 0))
        ));
    }

    #[test]
    fn malformed_reply_runs_lean_rollback_and_polling_does_not_advance() {
        let mut state = state();
        assert_eq!(state.packet().as_bytes(), [1, 16]);
        assert_eq!(state.packet().as_bytes(), [1, 16]);
        let mut begun = vec![1, 16];
        word(&mut begun, 42);
        state.resume(&begun);
        assert!(matches!(
            decode(state.packet().as_bytes()),
            Ok(Frame::ReadRows(42, ..))
        ));
        state.resume(&[1, 17]); // Wrong success variant for the outstanding read.
        assert!(matches!(
            decode(state.packet().as_bytes()),
            Ok(Frame::Rollback(42))
        ));
        state.resume(&[1, 18]);
        assert!(matches!(
            decode(state.packet().as_bytes()),
            Ok(Frame::Failure(3, 0))
        ));
        state.resume(&begun); // A terminal operation cannot be restarted.
        assert!(matches!(
            decode(state.packet().as_bytes()),
            Ok(Frame::Failure(3, 0))
        ));
    }

    #[test]
    fn packet_decoder_rejects_truncation_trailing_data_and_hostile_lengths() {
        for packet in [
            &[][..],
            &[2, 16],
            &[1, 16, 0],
            &[1, 99],
            &[1, 0, 255, 255, 255, 255, 255, 255, 255, 255],
        ] {
            assert!(decode(packet).is_err());
        }
    }
}
