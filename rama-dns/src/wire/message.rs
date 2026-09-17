use core::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Range,
};

use rama_core::bytes::Bytes;

use super::{
    AddressRdataParseError, Name, NameParseError, RecordClass, RecordType, ResponseCode,
    ServiceBinding, ServiceBindingParseError, Txt, TxtParseError, parse_a_rdata, parse_aaaa_rdata,
};

/// Shortest encodable question: root name, QTYPE, and QCLASS.
const MIN_QUESTION_WIRE_LEN: usize = 5;
/// Shortest encodable resource record: root name, fixed fields, empty RDATA.
const MIN_RECORD_WIRE_LEN: usize = 11;
/// TYPE, CLASS, TTL, and RDLENGTH octets that follow a record's owner name.
const RECORD_FIELDS_WIRE_LEN: usize = 10;

const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_AUTHORITATIVE: u16 = 0x0400;
const FLAG_TRUNCATED: u16 = 0x0200;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const FLAG_AUTHENTIC_DATA: u16 = 0x0020;
const FLAG_CHECKING_DISABLED: u16 = 0x0010;
const OPCODE_SHIFT: u16 = 11;
const OPCODE_MASK: u16 = 0x000f;
const RESPONSE_CODE_MASK: u16 = 0x000f;

/// The fixed twelve-octet header of a DNS message.
///
/// RFC 1035 Section 4.1.1 defines the identifier, the flag word, and the four
/// section counts. The counts describe the message as sent; they are not a
/// promise that every counted record is present or well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageHeader {
    id: u16,
    flags: u16,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl MessageHeader {
    /// Wire length of a DNS message header in octets.
    pub const WIRE_LEN: usize = 12;

    /// Parse the fixed header at the start of a DNS message.
    ///
    /// Octets beyond the header are ignored, so this also inspects a message
    /// whose sections are unparsed, truncated, or not yet received.
    pub fn parse(message: &[u8]) -> Result<Self, MessageParseError> {
        let Some(header) = message.get(..Self::WIRE_LEN) else {
            return Err(MessageParseError::new(
                MessageParseErrorKind::TruncatedHeader { len: message.len() },
            ));
        };
        Ok(Self {
            id: u16::from_be_bytes([header[0], header[1]]),
            flags: u16::from_be_bytes([header[2], header[3]]),
            question_count: u16::from_be_bytes([header[4], header[5]]),
            answer_count: u16::from_be_bytes([header[6], header[7]]),
            authority_count: u16::from_be_bytes([header[8], header[9]]),
            additional_count: u16::from_be_bytes([header[10], header[11]]),
        })
    }

    /// Return the message identifier that pairs a response with its query.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Return the raw flag word, including the reserved Z bit.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Return whether the QR bit marks this message as a response.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    /// Return the four-bit OPCODE, where zero is a standard query.
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        ((self.flags >> OPCODE_SHIFT) & OPCODE_MASK) as u8
    }

    /// Return whether the answering server is authoritative for the name.
    #[must_use]
    pub const fn is_authoritative(&self) -> bool {
        self.flags & FLAG_AUTHORITATIVE != 0
    }

    /// Return whether the message was truncated by its transport.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.flags & FLAG_TRUNCATED != 0
    }

    /// Return whether the query asked the server to recurse.
    #[must_use]
    pub const fn is_recursion_desired(&self) -> bool {
        self.flags & FLAG_RECURSION_DESIRED != 0
    }

    /// Return whether the server offers recursion.
    #[must_use]
    pub const fn is_recursion_available(&self) -> bool {
        self.flags & FLAG_RECURSION_AVAILABLE != 0
    }

    /// Return the RFC 4035 authentic-data bit.
    #[must_use]
    pub const fn is_authentic_data(&self) -> bool {
        self.flags & FLAG_AUTHENTIC_DATA != 0
    }

    /// Return the RFC 4035 checking-disabled bit.
    #[must_use]
    pub const fn is_checking_disabled(&self) -> bool {
        self.flags & FLAG_CHECKING_DISABLED != 0
    }

    /// Return the response code held by the header's low four bits.
    ///
    /// EDNS(0) and TSIG extend this field with upper bits carried elsewhere in
    /// the message; those extensions are not read here.
    #[must_use]
    pub fn response_code(&self) -> ResponseCode {
        ResponseCode::from((self.flags & RESPONSE_CODE_MASK) as u8)
    }

    /// Return the declared question count (QDCOUNT).
    #[must_use]
    pub const fn question_count(&self) -> u16 {
        self.question_count
    }

    /// Return the declared answer count (ANCOUNT).
    #[must_use]
    pub const fn answer_count(&self) -> u16 {
        self.answer_count
    }

    /// Return the declared authority count (NSCOUNT).
    ///
    /// [`Message`] never parses that section; this reports what it skipped.
    #[must_use]
    pub const fn authority_count(&self) -> u16 {
        self.authority_count
    }

    /// Return the declared additional count (ARCOUNT).
    ///
    /// [`Message`] never parses that section; this reports what it skipped.
    #[must_use]
    pub const fn additional_count(&self) -> u16 {
        self.additional_count
    }
}

/// One entry of a DNS message's question section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    name: Name,
    record_type: RecordType,
    class: RecordClass,
}

impl Question {
    /// Return the queried name (QNAME), with compression already resolved.
    #[must_use]
    pub const fn name(&self) -> &Name {
        &self.name
    }

    /// Return the queried record type (QTYPE).
    #[must_use]
    pub const fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// Return the queried class (QCLASS).
    #[must_use]
    pub const fn class(&self) -> RecordClass {
        self.class
    }
}

/// One resource record of a DNS message's answer section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    name: Name,
    record_type: RecordType,
    class: RecordClass,
    ttl: u32,
    data: RecordData,
}

impl ResourceRecord {
    /// Return the record's owner name, with compression already resolved.
    #[must_use]
    pub const fn name(&self) -> &Name {
        &self.name
    }

    /// Return the record's type, which also labels opaque RDATA.
    #[must_use]
    pub const fn record_type(&self) -> RecordType {
        self.record_type
    }

    /// Return the record's class.
    #[must_use]
    pub const fn class(&self) -> RecordClass {
        self.class
    }

    /// Return the record's time to live, in seconds.
    ///
    /// The wire field is unsigned here. RFC 2181 Section 8 treats a TTL whose
    /// top bit is set as zero; that policy belongs with the cache.
    #[must_use]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Return the record's decoded RDATA.
    #[must_use]
    pub const fn data(&self) -> &RecordData {
        &self.data
    }
}

/// Decoded RDATA of an answer record.
///
/// Types whose RDATA Rama's wire vocabulary models are decoded; everything
/// else, including every class other than [`RecordClass::IN`], is retained as
/// [`RecordData::Opaque`] and labelled by [`ResourceRecord::record_type`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordData {
    /// An IPv4 host address from an [`RecordType::A`] record.
    A(Ipv4Addr),
    /// An IPv6 host address from an [`RecordType::AAAA`] record.
    Aaaa(Ipv6Addr),
    /// The canonical name of an alias.
    Cname(Name),
    /// An authoritative name server's name.
    Ns(Name),
    /// A pointer record's target name.
    Ptr(Name),
    /// One TXT record's character-strings.
    Txt(Txt),
    /// An [`RecordType::SVCB`] or [`RecordType::HTTPS`] service binding.
    ServiceBinding(ServiceBinding),
    /// Uninterpreted RDATA of a type or class this parser does not decode.
    Opaque(Bytes),
}

/// A parsed DNS message header, question section, and answer section.
///
/// Parsing deliberately stops after the answer section: the authority and
/// additional sections are never walked, so their records are not validated
/// and any EDNS(0) OPT record they carry is not read. Use
/// [`MessageHeader::authority_count`] and [`MessageHeader::additional_count`]
/// to see what was skipped.
///
/// The result stays close to the wire. Names keep their original case and
/// trailing root label, records keep their declared class and TTL, and no
/// section is capped or deduplicated. Normalisation and limits belong with
/// the caller.
///
/// [`Message::parse`] is lenient, because a message that goes wrong halfway
/// is still worth what precedes it. Only a message shorter than its fixed
/// header fails outright; a question or answer that cannot be decoded ends
/// the walk and everything before it is kept. [`Message::is_complete`] and
/// [`Message::incomplete_reason`] report whether the walk ended early and
/// why. A question that fails also ends it before the answer section, whose
/// start is then unknown.
///
/// [`Message::parse_strict`] instead rejects such a message, and its error
/// still hands back that same partial result through
/// [`MessageParseError::partial`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    header: MessageHeader,
    questions: Box<[Question]>,
    answers: Box<[ResourceRecord]>,
    incomplete: Option<Box<MessageParseError>>,
}

impl Message {
    /// Parse one borrowed DNS message, keeping what decodes.
    ///
    /// Only RDATA that outlives the call is copied. Use
    /// [`Message::parse_bytes`] when the caller already owns the message as
    /// [`Bytes`] and wants that RDATA to share its allocation.
    pub fn parse(message: &[u8]) -> Result<Self, MessageParseError> {
        Self::parse_with(message, |rdata| Bytes::copy_from_slice(&message[rdata]))
    }

    /// Parse one owned DNS message, keeping what decodes, without copying its
    /// RDATA.
    ///
    /// Retained RDATA keeps the whole message allocation alive, which is what
    /// a proportionately sized datagram buffer wants. Use [`Message::parse`]
    /// to copy out of an oversized or reused buffer.
    pub fn parse_bytes(message: &Bytes) -> Result<Self, MessageParseError> {
        Self::parse_with(message, |rdata| message.slice(rdata))
    }

    /// Parse one borrowed DNS message, rejecting an incomplete result.
    ///
    /// A question or answer that [`Message::parse`] would stop on is an error
    /// here. The error carries everything parsed before it through
    /// [`MessageParseError::partial`].
    pub fn parse_strict(message: &[u8]) -> Result<Self, MessageParseError> {
        Self::parse(message)?.into_complete()
    }

    /// Parse one owned DNS message, rejecting an incomplete result, without
    /// copying its RDATA.
    ///
    /// This is [`Message::parse_strict`] with the sharing behaviour of
    /// [`Message::parse_bytes`].
    pub fn parse_bytes_strict(message: &Bytes) -> Result<Self, MessageParseError> {
        Self::parse_bytes(message)?.into_complete()
    }

    fn parse_with(
        message: &[u8],
        retain_rdata: impl Fn(Range<usize>) -> Bytes,
    ) -> Result<Self, MessageParseError> {
        let header = MessageHeader::parse(message)?;
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        // Only the fixed header is required; a section that stops early
        // leaves its reason behind instead of discarding the records before
        // it.
        let incomplete =
            parse_sections(message, header, &retain_rdata, &mut questions, &mut answers)
                .err()
                .map(Box::new);

        Ok(Self {
            header,
            questions: questions.into_boxed_slice(),
            answers: answers.into_boxed_slice(),
            incomplete,
        })
    }

    fn into_complete(self) -> Result<Self, MessageParseError> {
        let Some(error) = self.incomplete.as_deref().cloned() else {
            return Ok(self);
        };
        Err(error.with_partial(self))
    }

    /// Return the message's header.
    #[must_use]
    pub const fn header(&self) -> &MessageHeader {
        &self.header
    }

    /// Return the message's questions, in wire order.
    ///
    /// This holds fewer entries than [`MessageHeader::question_count`] when
    /// the walk ended early.
    #[must_use]
    pub const fn questions(&self) -> &[Question] {
        &self.questions
    }

    /// Return the message's answer records, in wire order.
    ///
    /// This holds fewer entries than [`MessageHeader::answer_count`] when the
    /// walk ended early.
    #[must_use]
    pub const fn answers(&self) -> &[ResourceRecord] {
        &self.answers
    }

    /// Return whether every question and answer the header declared was
    /// parsed.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.incomplete.is_none()
    }

    /// Return what stopped the section walk, when it stopped early.
    ///
    /// This is the error [`Message::parse_strict`] reports for the same
    /// message, without a partial message of its own.
    #[must_use]
    pub fn incomplete_reason(&self) -> Option<&MessageParseError> {
        self.incomplete.as_deref()
    }
}

/// Walk the question and answer sections, appending what decodes.
///
/// The error reports where the walk stopped; the records before that point
/// stay in `questions` and `answers`.
fn parse_sections(
    message: &[u8],
    header: MessageHeader,
    retain_rdata: &impl Fn(Range<usize>) -> Bytes,
    questions: &mut Vec<Question>,
    answers: &mut Vec<ResourceRecord>,
) -> Result<(), MessageParseError> {
    let mut offset = MessageHeader::WIRE_LEN;
    questions.reserve_exact(bounded_capacity(
        header.question_count,
        message,
        offset,
        MIN_QUESTION_WIRE_LEN,
    ));
    for index in 0..usize::from(header.question_count) {
        let (name, name_len) = Name::from_message(message, offset).map_err(|error| {
            MessageParseError::new(MessageParseErrorKind::InvalidQuestionName { index, error })
        })?;
        offset += name_len;
        let Some(fields) = field(message, offset, 4) else {
            return Err(MessageParseError::new(
                MessageParseErrorKind::TruncatedQuestion { index },
            ));
        };
        questions.push(Question {
            name,
            record_type: RecordType::from(u16::from_be_bytes([fields[0], fields[1]])),
            class: RecordClass::from(u16::from_be_bytes([fields[2], fields[3]])),
        });
        offset += 4;
    }

    answers.reserve_exact(bounded_capacity(
        header.answer_count,
        message,
        offset,
        MIN_RECORD_WIRE_LEN,
    ));
    for index in 0..usize::from(header.answer_count) {
        let (name, name_len) = Name::from_message(message, offset).map_err(|error| {
            MessageParseError::new(MessageParseErrorKind::InvalidRecordName { index, error })
        })?;
        offset += name_len;
        let Some(fields) = field(message, offset, RECORD_FIELDS_WIRE_LEN) else {
            return Err(MessageParseError::new(
                MessageParseErrorKind::TruncatedRecord { index },
            ));
        };
        let record_type = RecordType::from(u16::from_be_bytes([fields[0], fields[1]]));
        let class = RecordClass::from(u16::from_be_bytes([fields[2], fields[3]]));
        let ttl = u32::from_be_bytes([fields[4], fields[5], fields[6], fields[7]]);
        let rdlength = usize::from(u16::from_be_bytes([fields[8], fields[9]]));
        offset += RECORD_FIELDS_WIRE_LEN;

        let Some(rdata) = field(message, offset, rdlength) else {
            return Err(MessageParseError::new(
                MessageParseErrorKind::TruncatedRdata {
                    index,
                    rdlength,
                    available: message.len() - offset,
                },
            ));
        };
        let data = parse_record_data(
            message,
            RecordDataRef {
                offset,
                rdata,
                record_type,
                class,
                index,
            },
            retain_rdata,
        )?;
        offset += rdlength;

        answers.push(ResourceRecord {
            name,
            record_type,
            class,
            ttl,
            data,
        });
    }

    Ok(())
}

/// Reserve only what the octets from `offset` onwards could hold, so a header
/// overstating its counts cannot make a short message allocate for thousands
/// of records.
pub(super) fn bounded_capacity(
    count: u16,
    message: &[u8],
    offset: usize,
    min_wire_len: usize,
) -> usize {
    usize::from(count).min(message.len().saturating_sub(offset) / min_wire_len)
}

/// Return `len` octets at `offset`, or `None` when the message ends first.
fn field(message: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    message.get(offset..)?.get(..len)
}

/// One answer record's RDATA, located within its message.
#[derive(Clone, Copy)]
struct RecordDataRef<'a> {
    offset: usize,
    rdata: &'a [u8],
    record_type: RecordType,
    class: RecordClass,
    index: usize,
}

fn parse_record_data(
    message: &[u8],
    record: RecordDataRef<'_>,
    retain_rdata: &impl Fn(Range<usize>) -> Bytes,
) -> Result<RecordData, MessageParseError> {
    let RecordDataRef {
        offset,
        rdata,
        record_type,
        class,
        index,
    } = record;
    let range = offset..offset + rdata.len();
    if class != RecordClass::IN {
        return Ok(RecordData::Opaque(retain_rdata(range)));
    }

    let address_error =
        |error| MessageParseError::new(MessageParseErrorKind::InvalidAddressRdata { index, error });
    let rdata_name = || parse_rdata_name(message, offset, rdata.len(), record_type, index);

    Ok(match record_type {
        RecordType::A => RecordData::A(parse_a_rdata(rdata).map_err(address_error)?),
        RecordType::AAAA => RecordData::Aaaa(parse_aaaa_rdata(rdata).map_err(address_error)?),
        RecordType::CNAME => RecordData::Cname(rdata_name()?),
        RecordType::NS => RecordData::Ns(rdata_name()?),
        RecordType::PTR => RecordData::Ptr(rdata_name()?),
        RecordType::TXT => RecordData::Txt(Txt::parse_rdata_bytes(&retain_rdata(range)).map_err(
            |error| MessageParseError::new(MessageParseErrorKind::InvalidTxtRdata { index, error }),
        )?),
        RecordType::SVCB | RecordType::HTTPS => RecordData::ServiceBinding(
            ServiceBinding::parse_rdata_bytes(&retain_rdata(range)).map_err(|error| {
                MessageParseError::new(MessageParseErrorKind::InvalidServiceBindingRdata {
                    index,
                    record_type,
                    error,
                })
            })?,
        ),
        _ => RecordData::Opaque(retain_rdata(range)),
    })
}

/// Parse RDATA that holds exactly one, possibly compressed, DNS name.
fn parse_rdata_name(
    message: &[u8],
    rdata_offset: usize,
    rdlength: usize,
    record_type: RecordType,
    index: usize,
) -> Result<Name, MessageParseError> {
    let (name, consumed) = Name::from_message(message, rdata_offset).map_err(|error| {
        MessageParseError::new(MessageParseErrorKind::InvalidRecordDataName {
            index,
            record_type,
            error,
        })
    })?;
    if consumed != rdlength {
        return Err(MessageParseError::new(
            MessageParseErrorKind::RdataNameLengthMismatch {
                index,
                record_type,
                rdlength,
                consumed,
            },
        ));
    }
    Ok(name)
}

/// Error returned when a DNS message cannot be decoded.
///
/// Every failure except a truncated header stops a section walk part-way. The
/// strict constructors attach what they had decoded until then, so a caller
/// that rejects the message can still read its header and the records before
/// the failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageParseError {
    kind: MessageParseErrorKind,
    partial: Option<Box<Message>>,
}

impl MessageParseError {
    const fn new(kind: MessageParseErrorKind) -> Self {
        Self {
            kind,
            partial: None,
        }
    }

    fn with_partial(mut self, partial: Message) -> Self {
        self.partial = Some(Box::new(partial));
        self
    }

    /// Return everything decoded before this failure.
    ///
    /// Only [`Message::parse_strict`] and [`Message::parse_bytes_strict`]
    /// attach a partial message, and only once the fixed header was intact.
    /// It is exactly what [`Message::parse`] returns for the same octets.
    #[must_use]
    pub fn partial(&self) -> Option<&Message> {
        self.partial.as_deref()
    }

    /// Take ownership of everything decoded before this failure.
    #[must_use]
    pub fn into_partial(self) -> Option<Message> {
        self.partial.map(|partial| *partial)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MessageParseErrorKind {
    TruncatedHeader {
        len: usize,
    },
    TruncatedQuestion {
        index: usize,
    },
    TruncatedRecord {
        index: usize,
    },
    TruncatedRdata {
        index: usize,
        rdlength: usize,
        available: usize,
    },
    InvalidQuestionName {
        index: usize,
        error: NameParseError,
    },
    InvalidRecordName {
        index: usize,
        error: NameParseError,
    },
    InvalidRecordDataName {
        index: usize,
        record_type: RecordType,
        error: NameParseError,
    },
    RdataNameLengthMismatch {
        index: usize,
        record_type: RecordType,
        rdlength: usize,
        consumed: usize,
    },
    InvalidAddressRdata {
        index: usize,
        error: AddressRdataParseError,
    },
    InvalidTxtRdata {
        index: usize,
        error: TxtParseError,
    },
    InvalidServiceBindingRdata {
        index: usize,
        record_type: RecordType,
        error: ServiceBindingParseError,
    },
}

impl fmt::Display for MessageParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            MessageParseErrorKind::TruncatedHeader { len } => write!(
                f,
                "DNS message header requires {} octets, got {len}",
                MessageHeader::WIRE_LEN
            ),
            MessageParseErrorKind::TruncatedQuestion { index } => write!(
                f,
                "DNS question {index} ends within its QTYPE and QCLASS fields"
            ),
            MessageParseErrorKind::TruncatedRecord { index } => {
                write!(f, "DNS answer {index} ends within its record fields")
            }
            MessageParseErrorKind::TruncatedRdata {
                index,
                rdlength,
                available,
            } => write!(
                f,
                "DNS answer {index} declares {rdlength} RDATA octets but {available} remain"
            ),
            MessageParseErrorKind::InvalidQuestionName { index, error } => {
                write!(f, "DNS question {index} has an invalid name: {error}")
            }
            MessageParseErrorKind::InvalidRecordName { index, error } => {
                write!(f, "DNS answer {index} has an invalid owner name: {error}")
            }
            MessageParseErrorKind::InvalidRecordDataName {
                index,
                record_type,
                error,
            } => write!(
                f,
                "DNS answer {index} has an invalid {} RDATA name: {error}",
                record_type.variant_name()
            ),
            MessageParseErrorKind::RdataNameLengthMismatch {
                index,
                record_type,
                rdlength,
                consumed,
            } => write!(
                f,
                "DNS answer {index} declares {rdlength} {} RDATA octets but its name uses {consumed}",
                record_type.variant_name()
            ),
            MessageParseErrorKind::InvalidAddressRdata { index, error } => {
                write!(f, "DNS answer {index} has invalid address RDATA: {error}")
            }
            MessageParseErrorKind::InvalidTxtRdata { index, error } => {
                write!(f, "DNS answer {index} has invalid TXT RDATA: {error}")
            }
            MessageParseErrorKind::InvalidServiceBindingRdata {
                index,
                record_type,
                error,
            } => write!(
                f,
                "DNS answer {index} has invalid {} RDATA: {error}",
                record_type.variant_name()
            ),
        }
    }
}

impl core::error::Error for MessageParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.kind {
            MessageParseErrorKind::InvalidQuestionName { error, .. }
            | MessageParseErrorKind::InvalidRecordName { error, .. }
            | MessageParseErrorKind::InvalidRecordDataName { error, .. } => Some(error),
            MessageParseErrorKind::InvalidAddressRdata { error, .. } => Some(error),
            MessageParseErrorKind::InvalidTxtRdata { error, .. } => Some(error),
            MessageParseErrorKind::InvalidServiceBindingRdata { error, .. } => Some(error),
            _ => None,
        }
    }
}
