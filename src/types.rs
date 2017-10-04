use std::fmt::{self, Display};

pub use asn1_exp::{BitString, ObjectIdentifier, OctetString, Asn1DisplayExt};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Version {
    Version1,
    Version2,
    Version3,
}

asn1_alias_info!(Version ::= u8);

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            &Version::Version1 => "v1",
            &Version::Version2 => "v2c",
            &Version::Version3 => "v3",
        };
        write!(f, "{}", s)
    }
}

impl From<u8> for Version {
    fn from(v: u8) -> Version {
        match v {
            0 => Version::Version1,
            1 => Version::Version2,
            3 => Version::Version3,
            _ => panic!("incorrect version"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct Community(OctetString);

asn1_newtype!(Community ::= OctetString);

impl Community {
    pub fn new(community: &str) -> Community {
        Community(OctetString::from_str(community))
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct RequestID(u32);

asn1_newtype!(RequestID ::= u32);

impl From<u32> for RequestID {
    fn from(v: u32) -> Self {
        RequestID(v)
    }
}

impl From<RequestID> for u32 {
    fn from(v: RequestID) -> Self {
        v.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct ErrorStatus(u32);

asn1_newtype!(ErrorStatus ::= u32);

impl From<u32> for ErrorStatus {
    fn from(v: u32) -> Self {
        ErrorStatus(v)
    }
}

impl From<ErrorStatus> for u32 {
    fn from(v: ErrorStatus) -> Self {
        v.0
    }
}

impl Display for ErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self.0 {
            0 => "noError",
            1 => "tooBig",
            2 => "noSuchName",
            3 => "badValue",
            4 => "readOnly",
            5 => "genErr",
            6 => "noAccess",
            7 => "wrongType",
            8 => "wrongLength",
            9 => "wrongEncoding",
            10 => "wrongValue",
            11 => "noCreation",
            12 => "inconsistentValue",
            13 => "resourceUnavailable",
            14 => "commitFailed",
            15 => "undoFailed",
            16 => "authorizationError",
            17 => "notWritable",
            18 => "inconsistentName",
            _  => "otherError",
        };
        f.write_str(s)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct ErrorIndex(u32);

asn1_newtype!(ErrorIndex ::= u32);

impl From<u32> for ErrorIndex {
    fn from(v: u32) -> Self {
        ErrorIndex(v)
    }
}

impl From<ErrorIndex> for u32 {
    fn from(v: ErrorIndex) -> Self {
        v.0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub enum Variable {
    Integer(i32),
    BitString(BitString),
    OctetString(OctetString),
    Null,
    Oid(ObjectIdentifier),
    IpAddress(u8, u8,u8, u8),
    Counter(u32),
    Gauge(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

asn1_typed!(Variable, "VARIABLE");

impl Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Variable::*;
        match self {
            &Integer(i) => i.asn1_fmt(f),
            &BitString(ref s) => s.asn1_fmt(f),
            &OctetString(ref s) => s.asn1_fmt(f),
            &Null => write!(f, "NULL"),
            &Oid(ref oid) => oid.asn1_fmt(f),
            &IpAddress(a, b, c, d) => write!(f, "IP ADDRESS: {}.{}.{}.{}", a, b, c, d),
            &Counter(i) => write!(f, "Counter32: {}", i),
            &Gauge(i) => write!(f, "Gauge32: {}", i),
            &TimeTicks(i) => write!(f, "TimeTicks: {}", i),
            &Opaque(ref s) => write!(f, "Opaque: {:?}", s),
            &Counter64(i) => write!(f, "Counter64: {}", i),
            &NoSuchObject => write!(f, "NO SUCH OBJECT"),
            &NoSuchInstance => write!(f, "NO SUCH INSTANCE"),
            &EndOfMibView => write!(f, "END OF MIB VIEW"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct VarBind {
    oid: ObjectIdentifier,
    value: Variable,
}

asn1_seq!(
    VarBind: "VARIABLE BINDING",
    oid;
    value
);

impl VarBind {
    pub fn new(oid: ObjectIdentifier, value: Variable) -> Self {
        VarBind {
            oid: oid,
            value: value,
        }
    }

    pub fn new_null(oid: ObjectIdentifier) -> Self {
        VarBind {
            oid: oid,
            value: Variable::Null,
        }
    }

    pub fn oid(&self) -> &ObjectIdentifier {
        &self.oid
    }

    pub fn value(&self) -> &Variable {
        &self.value
    }
}

impl Display for VarBind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {}", self.oid, self.value)
    }
}

pub type VarBindList = Vec<VarBind>;


#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct InnerPdu {
    request_id: RequestID,
    error_status: ErrorStatus,
    error_index: ErrorIndex,
    variable_bindings: VarBindList,
}

asn1_seq!(
    InnerPdu: "PDU",
    request_id;
    error_status;
    error_index;
    variable_bindings
);

impl InnerPdu {
    pub fn new(
        request_id: u32,
        error_status: u32,
        error_index: u32,
        bindings: VarBindList,
    ) -> Self {
        InnerPdu {
            request_id: request_id.into(),
            error_status: error_status.into(),
            error_index: error_index.into(),
            variable_bindings: bindings,
        }
    }

    pub fn request_id(&self) -> u32 {
        self.request_id.0
    }

    pub fn set_request_id(&mut self, value: u32) {
        self.request_id.0 = value
    }

    pub fn error_status(&self) -> u32 {
        self.error_status.0
    }

    pub fn set_error_status(&mut self, value: u32) {
        self.error_status.0 = value
    }

    pub fn error_index(&self) -> u32 {
        self.error_index.0
    }

    pub fn set_error_index(&mut self, value: u32) {
        self.error_index.0 = value
    }

    pub fn binds(&self) -> &VarBindList {
        &self.variable_bindings
    }

    pub fn binds_mut(&mut self) -> &mut VarBindList {
        &mut self.variable_bindings
    }

    pub fn set_binds(&mut self, value: VarBindList) {
        self.variable_bindings = value
    }

    pub fn into_binds(self) -> VarBindList {
        self.variable_bindings
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum RequestType {
    Get,
    GetNext,
    Set,
    GetBulk,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum ResponseType {
    GetResponse,
    Report,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub enum Pdu {
    GetRequest(InnerPdu),
    GetNextRequest(InnerPdu),
    GetResponse(InnerPdu),
    SetRequest(InnerPdu),
    GetBulkRequest(InnerPdu),
    Inform(InnerPdu),
    Trap(InnerPdu),
    Report(InnerPdu),
}

asn1_typed!(Pdu, "PDU");

impl Pdu {
    pub fn new_request(request_type: RequestType, request_id: u32, error_status: u32, error_index: u32, var_binds: VarBindList) -> Self {
        let pdu = InnerPdu::new(request_id, error_status, error_index, var_binds);
        match request_type {
            RequestType::Get => Pdu::GetRequest(pdu),
            RequestType::GetNext => Pdu::GetNextRequest(pdu),
            RequestType::Set => Pdu::SetRequest(pdu),
            RequestType::GetBulk => Pdu::GetBulkRequest(pdu),
        }
    }

    pub fn new_empty_request(request_type: RequestType) -> Pdu {
        Self::new_request(request_type, 0, 0, 0, Vec::new())
    }

    pub fn request_type(&self) -> Option<RequestType> {
        match self {
            &Pdu::GetRequest(_) => Some(RequestType::Get),
            &Pdu::GetNextRequest(_) => Some(RequestType::GetNext),
            &Pdu::SetRequest(_) => Some(RequestType::Set),
            &Pdu::GetBulkRequest(_) => Some(RequestType::GetBulk),
            _ => None,
        }
    }

    pub fn response_type(&self) -> Option<ResponseType> {
        match self {
            &Pdu::GetResponse(_) => Some(ResponseType::GetResponse),
            &Pdu::Report(_) => Some(ResponseType::Report),
            _ => None,
        }
    }

    pub fn is_request_type(&self) -> bool {
        self.request_type().is_some()
    }

    pub fn is_response_type(&self) -> bool {
        self.response_type().is_some()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct PacketV2 {
    version: Version,
    community: Community,
    pdu: Pdu,
}

asn1_seq!(
    PacketV2: "SNMP header",
    version;
    community;
    pdu
);

impl PacketV2 {
    pub fn new(version: Version, community: Community, pdu: Pdu) -> Self {
        PacketV2 {
            version,
            community,
            pdu,
        }
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn set_version(&mut self, value: Version) {
        self.version = value
    }

    pub fn community(&self) -> &Community {
        &self.community
    }

    pub fn set_community(&mut self, value: Community) {
        self.community = value
    }

    pub fn pdu(&self) -> &Pdu {
        &self.pdu
    }

    pub fn pdu_mut(&mut self) -> &mut Pdu {
        &mut self.pdu
    }

    pub fn set_pdu(&mut self, value: Pdu) {
        self.pdu = value
    }

    pub fn into_pdu(self) -> Pdu {
        self.pdu
    }
}

// --- SNMP V3 Types

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct MessageID(u32);
asn1_newtype!(MessageID ::= u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct MaxSize(u32);
asn1_newtype!(MaxSize ::= u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum SecurityLevel {
    NoAuthNoPriv = 0x00,
    AuthNoPriv = 0x01,
    AuthPriv = 0x03,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct MessageFlags {
    pub reportable: bool,
    pub security_level: SecurityLevel,
}
asn1_info!(MessageFlags => UNIVERSAL 0x04, "Message Flags");

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub enum SecurityModel {
    UserBasedSecurityModel,
}
asn1_info!(SecurityModel => UNIVERSAL 0x02, "Security Model");

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct AuthenticationParameter(OctetString);
asn1_newtype!(AuthenticationParameter ::= OctetString);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct PrivacyParameter(OctetString);
asn1_newtype!(PrivacyParameter ::= OctetString);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct EngineID(OctetString);
asn1_newtype!(EngineID ::= OctetString);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct EngineTime(u32);
asn1_newtype!(EngineTime ::= u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct EngineBootCount(u32);
asn1_newtype!(EngineBootCount ::= u32);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct UserName(OctetString);
asn1_newtype!(UserName ::= OctetString);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct SecurityParameter {
    engine_id: EngineID,
    engine_boots: EngineBootCount,
    engine_time: EngineTime,
    user_name: UserName,
    auth_parameters: AuthenticationParameter,
    privacy_parameters: PrivacyParameter,
}
asn1_seq!(SecurityParameter: "Security Parameters",
    engine_id;
    engine_boots;
    engine_time;
    user_name;
    auth_parameters;
    privacy_parameters
);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct ContextEngineID(OctetString);
asn1_newtype!(ContextEngineID ::= OctetString);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct ContextName(OctetString);
asn1_newtype!(ContextName ::= OctetString);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub struct ScopedPdu {
    context_engine_id: ContextEngineID,
    context_name: ContextName,
    pdu: Pdu,
}
asn1_seq!(ScopedPdu: "Scoped PDU",
    context_engine_id;
    context_name;
    pdu
);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub enum PduV3 {
    Scoped(ScopedPdu),
    Crypted(OctetString),
}
asn1_typed!(PduV3, "PDU V3");

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[cfg_attr(feature = "with-serde", derive(Serialize, Deserialize))]
pub(crate) struct PacketV3 {
    pub version: Version,
    pub msg_id: MessageID,
    pub max_size: MaxSize,
    pub flags: MessageFlags,
    pub security_model: SecurityModel,
    pub security_parameters: SecurityParameter,
    pub pdu: PduV3,
}

asn1_typed!(PacketV3, "SNMP V3 Packet");