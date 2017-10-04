use asn1_exp::{self, info, Tag, Asn1Serialize, Asn1Serializer, Asn1Deserialize, Asn1Deserializer, Asn1Visitor};
use asn1_exp::info::universal::*;
use asn1_exp::de::{Asn1Error, SeqAccess};

use ::types::*;

/// Tags

pub const TAG_APP_IP_ADDRESS: Tag = Tag {
    class: info::Application,
    tagnum: 0x00,
    content_type: info::ContentType::Primitive,
};
pub const TAG_APP_COUNTER32: Tag = Tag {
    class: info::Application,
    tagnum: 0x01,
    content_type: info::ContentType::Primitive,
};
pub const TAG_APP_GAUGE32: Tag = Tag {
    class: info::Application,
    tagnum: 0x02,
    content_type: info::ContentType::Primitive,
};
pub const TAG_APP_TIME_TICKS: Tag = Tag {
    class: info::Application,
    tagnum: 0x03,
    content_type: info::ContentType::Primitive,
};
pub const TAG_APP_OPAQUE: Tag = Tag {
    class: info::Application,
    tagnum: 0x04,
    content_type: info::ContentType::Primitive,
};
pub const TAG_APP_COUNTER64: Tag = Tag {
    class: info::Application,
    tagnum: 0x06,
    content_type: info::ContentType::Primitive,
};
pub const TAG_CTX_NO_SUCH_OBJECT: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x00,
    content_type: info::ContentType::Primitive,
};
pub const TAG_CTX_NO_SUCH_INSTANCE: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x01,
    content_type: info::ContentType::Primitive,
};
pub const TAG_CTX_END_OF_MIB_VIEW: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x02,
    content_type: info::ContentType::Primitive,
};

pub const TAG_CTX_GET_REQUEST: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x00,
    content_type: info::ContentType::Constructed,
};
pub const TAG_CTX_GET_NEXT_REQUEST: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x01,
    content_type: info::ContentType::Constructed,
};
pub const TAG_CTX_GET_RESPONSE: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x02,
    content_type: info::ContentType::Constructed,
};
pub const TAG_CTX_SET_REQUEST: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x03,
    content_type: info::ContentType::Constructed,
};
pub const TAG_CTX_GET_BULK_REQUEST: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x05,
    content_type: info::ContentType::Constructed,
};
pub const TAG_CTX_INFORM: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x06,
    content_type: info::ContentType::Constructed,
};
pub const TAG_CTX_TRAP: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x07,
    content_type: info::ContentType::Constructed,
};
pub const TAG_CTX_REPORT: Tag = Tag {
    class: info::ContextSpecific,
    tagnum: 0x08,
    content_type: info::ContentType::Constructed,
};


/// Impls

impl Asn1Serialize for Version {
    fn asn1_serialize<S: Asn1Serializer>(&self, serializer: S) -> Result<S::Ok, S::Err> {
        serializer.serialize_u8(*self as u8)
    }
}

impl Asn1Deserialize for Version {
    fn asn1_deserialize<'de, D: Asn1Deserializer<'de>>(deserializer: D) -> Result<Self, D::Err> {
        let u: u8 = Asn1Deserialize::asn1_deserialize(deserializer)?;
        match u {
            0 => Ok(Version::Version1),
            1 => Ok(Version::Version2),
            3 => Ok(Version::Version3),
            _ => Err(Asn1Error::invalid_value(
                "Version value must be within [0, 3]",
            )),
        }
    }
}

impl Asn1Serialize for Variable {
    fn asn1_serialize<S: asn1_exp::ser::Asn1Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Err> {
        use types::Variable::*;
        match self {
            &Integer(i) => i.asn1_serialize(serializer),
            &BitString(ref s) => s.asn1_serialize(serializer),
            &OctetString(ref s) => s.asn1_serialize(serializer),
            &Null => serializer.serialize_null(),
            &Oid(ref oid) => oid.asn1_serialize(serializer),
            &IpAddress(a, b, c, d) => {
                serializer
                    .serialize_implicit(TAG_APP_IP_ADDRESS)?
                    .serialize_bytes(&[a, b, c, d])
                    // .serialize_bytes(&ip.octets())
            }
            &Counter(i) => i.asn1_serialize(serializer.serialize_implicit(TAG_APP_COUNTER32)?),
            &Gauge(i) => i.asn1_serialize(serializer.serialize_implicit(TAG_APP_GAUGE32)?),
            &TimeTicks(i) => i.asn1_serialize(serializer.serialize_implicit(TAG_APP_TIME_TICKS)?),
            &Opaque(ref s) => s.asn1_serialize(serializer.serialize_implicit(TAG_APP_OPAQUE)?),
            &Counter64(i) => i.asn1_serialize(serializer.serialize_implicit(TAG_APP_COUNTER64)?),
            &NoSuchObject => {
                serializer
                    .serialize_implicit(TAG_CTX_NO_SUCH_OBJECT)?
                    .serialize_null()
            }
            &NoSuchInstance => {
                serializer
                    .serialize_implicit(TAG_CTX_NO_SUCH_INSTANCE)?
                    .serialize_null()
            }
            &EndOfMibView => {
                serializer
                    .serialize_implicit(TAG_CTX_END_OF_MIB_VIEW)?
                    .serialize_null()
            }
        }
    }
}

impl Asn1Deserialize for Variable {
    fn asn1_deserialize<'de, D: Asn1Deserializer<'de>>(deserializer: D) -> Result<Self, D::Err> {
        struct VariableVisitor;
        impl<'de> Asn1Visitor<'de> for VariableVisitor {
            type Value = Variable;

            fn visit_choice<A>(self, tag: &Tag, deserializer: A) -> Result<Self::Value, A::Err>
            where
                A: Asn1Deserializer<'de>,
            {
                match *tag {
                    TAG_INTEGER => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::Integer(v))
                    }
                    info::TAG_BIT_STRING => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::BitString(v))
                    }
                    info::TAG_OCTET_STRING => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::OctetString(v))
                    }
                    info::TAG_NULL => {
                        let () = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::Null)
                    }
                    info::TAG_OBJECT_IDENTIFIER => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::Oid(v))
                    }
                    TAG_APP_IP_ADDRESS => {
                        let v: u32 = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(
                            Variable::IpAddress(
                                (v >> 24) as u8,
                                (v >> 16) as u8,
                                (v >> 8 ) as u8,
                                (v      ) as u8,
                            )
                        )
                    }
                    TAG_APP_COUNTER32 => {
                        let v: u32 = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::Counter(v))
                    }
                    TAG_APP_GAUGE32 => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::Gauge(v))
                    }
                    TAG_APP_TIME_TICKS => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::TimeTicks(v))
                    }
                    TAG_APP_OPAQUE => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::Opaque(v))
                    }
                    TAG_APP_COUNTER64 => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::Counter64(v))
                    }
                    TAG_CTX_NO_SUCH_OBJECT => {
                        let () = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::NoSuchObject)
                    }
                    TAG_CTX_NO_SUCH_INSTANCE => {
                        let () = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::NoSuchObject)
                    }
                    TAG_CTX_END_OF_MIB_VIEW => {
                        let () = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Variable::NoSuchObject)
                    }
                    _ => Err(Asn1Error::invalid_tag("expected Variable related tag")),
                }
            }
        }
        deserializer.deserialize_choice(VariableVisitor)
    }
}

impl Asn1Serialize for Pdu {
    fn asn1_serialize<S: asn1_exp::ser::Asn1Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Err> {
        use types::Pdu::*;
        match self {
            &GetRequest(ref pdu) => {
                let s = serializer.serialize_implicit(TAG_CTX_GET_REQUEST)?;
                pdu.asn1_serialize(s)
            }
            &GetNextRequest(ref pdu) => {
                let s = serializer.serialize_implicit(TAG_CTX_GET_NEXT_REQUEST)?;
                pdu.asn1_serialize(s)
            }
            &GetResponse(ref pdu) => {
                let s = serializer.serialize_implicit(TAG_CTX_GET_RESPONSE)?;
                pdu.asn1_serialize(s)
            }
            &SetRequest(ref pdu) => {
                let s = serializer.serialize_implicit(TAG_CTX_SET_REQUEST)?;
                pdu.asn1_serialize(s)
            }
            &GetBulkRequest(ref pdu) => {
                let s = serializer.serialize_implicit(TAG_CTX_GET_BULK_REQUEST)?;
                pdu.asn1_serialize(s)
            }
            &Inform(ref pdu) => {
                let s = serializer.serialize_implicit(TAG_CTX_INFORM)?;
                pdu.asn1_serialize(s)
            }
            &Trap(ref pdu) => {
                let s = serializer.serialize_implicit(TAG_CTX_TRAP)?;
                pdu.asn1_serialize(s)
            }
            &Report(ref pdu) => {
                let s = serializer.serialize_implicit(TAG_CTX_REPORT)?;
                pdu.asn1_serialize(s)
            }
        }
    }
}

impl Asn1Deserialize for Pdu {
    fn asn1_deserialize<'de, D: Asn1Deserializer<'de>>(deserializer: D) -> Result<Self, D::Err> {
        struct PduVisitor;
        impl<'de> Asn1Visitor<'de> for PduVisitor {
            type Value = Pdu;

            fn visit_choice<A>(self, tag: &Tag, deserializer: A) -> Result<Self::Value, A::Err>
            where
                A: Asn1Deserializer<'de>,
            {
                match *tag {
                    TAG_CTX_GET_REQUEST => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Pdu::GetRequest(v))
                    }
                    TAG_CTX_GET_NEXT_REQUEST => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Pdu::GetNextRequest(v))
                    }
                    TAG_CTX_GET_RESPONSE => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Pdu::GetResponse(v))
                    }
                    TAG_CTX_SET_REQUEST => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Pdu::SetRequest(v))
                    }
                    TAG_CTX_GET_BULK_REQUEST => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Pdu::GetBulkRequest(v))
                    }
                    TAG_CTX_INFORM => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Pdu::Inform(v))
                    }
                    TAG_CTX_TRAP => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Pdu::Trap(v))
                    }
                    TAG_CTX_REPORT => {
                        let v = Asn1Deserialize::asn1_deserialize(deserializer)?;
                        Ok(Pdu::Report(v))
                    }
                    _ => Err(Asn1Error::invalid_tag("expected PDU related tag")),
                }
            }
        }
        deserializer.deserialize_choice(PduVisitor)
    }
}

impl Asn1Serialize for MessageFlags {
    fn asn1_serialize<S: asn1_exp::ser::Asn1Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Err> {
        let value: u8 = {
            let reportable: u8 = if self.reportable { 0x04 } else { 0x00 };
            self.security_level as u8 & reportable
        };

        serializer.serialize_bytes(&[value])
    }
}

impl Asn1Deserialize for MessageFlags {
    fn asn1_deserialize<'de, D: Asn1Deserializer<'de>>(deserializer: D) -> Result<Self, D::Err> {
        struct FlagsVisitor;
        impl<'de> Asn1Visitor<'de> for FlagsVisitor {
            type Value = MessageFlags;

            fn visit_byte_string<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                where E: Asn1Error
            {
                if v.len() != 1 {
                    return Err(Asn1Error::invalid_length("message flags must be encoded in 1 byte"))
                }

                let v = v[0];

                if v & 0xf8 != 0 {
                    return Err(Asn1Error::invalid_value("0-4 bits are reserved and should be zero"))
                }

                let reportable: bool = v & 0x04 == 0x04;
                let security_level = match v & 0x03 {
                    0x00 => SecurityLevel::NoAuthNoPriv,
                    0x01 => SecurityLevel::AuthNoPriv,
                    0x03 => SecurityLevel::AuthPriv,
                    _    => {
                        return Err(Asn1Error::invalid_value("invalid security level flag set"))
                    }
                };

                Ok(MessageFlags {
                    reportable: reportable,
                    security_level: security_level,
                })
            }
        }

        deserializer.deserialize_bytes(FlagsVisitor)
    }
}

impl Asn1Serialize for SecurityModel {
    fn asn1_serialize<S: asn1_exp::ser::Asn1Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Err> {
        let v = match *self {
            SecurityModel::UserBasedSecurityModel => 3,
        };
        serializer.serialize_u8(v)
    }
}

impl Asn1Deserialize for SecurityModel {
    fn asn1_deserialize<'de, D: Asn1Deserializer<'de>>(deserializer: D) -> Result<Self, D::Err> {
        struct SecurityModelVisitor;
        impl<'de> Asn1Visitor<'de> for SecurityModelVisitor {
            type Value = SecurityModel;

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
                where E: Asn1Error
            {
                match v {
                    3 => Ok(SecurityModel::UserBasedSecurityModel),
                    _ => Err(Asn1Error::invalid_value("security model should be UserBasedSecurityModel (3)"))
                }
            }
        }

        deserializer.deserialize_u8(SecurityModelVisitor)
    }
}

impl Asn1Serialize for PduV3 {
    fn asn1_serialize<S: asn1_exp::ser::Asn1Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Err> {
        match *self {
            PduV3::Scoped(ref scoped) => {
                scoped.asn1_serialize(serializer)
            },
            PduV3::Crypted(ref crypted) => {
                crypted.asn1_serialize(serializer)
            },
        }
    }
}

impl Asn1Deserialize for PduV3 {
    fn asn1_deserialize<'de, D: Asn1Deserializer<'de>>(deserializer: D) -> Result<Self, D::Err> {
        struct PduV3Visitor;
        impl<'de> Asn1Visitor<'de> for PduV3Visitor {
            type Value = PduV3;

            fn visit_choice<A>(self, tag: &Tag, deserializer: A) -> Result<Self::Value, A::Err>
            where
                A: Asn1Deserializer<'de>,
            {
                match *tag {
                    TAG_SEQUENCE => {
                        ScopedPdu::asn1_deserialize(deserializer).map(PduV3::Scoped)
                    },
                    TAG_OCTET_STRING => {
                        OctetString::asn1_deserialize(deserializer).map(PduV3::Crypted)
                    },
                    _ => {
                        Err(Asn1Error::invalid_tag("SNMP V3 PDU must be either ScopedPdu or CryptedPdu"))
                    },
                }
            }
        }

        deserializer.deserialize_choice(PduV3Visitor)
    }
}

// impl Asn1Serialize for PacketV3 {
//     fn asn1_serialize<S: asn1_exp::ser::Asn1Serializer>(
//         &self,
//         serializer: S,
//     ) -> Result<S::Ok, S::Err> {

//     }
// }

impl Asn1Deserialize for PacketV3 {
    fn asn1_deserialize<'de, D: Asn1Deserializer<'de>>(deserializer: D) -> Result<Self, D::Err> {
        struct PacketVisitor;
        impl<'de> Asn1Visitor<'de> for PacketVisitor {
            type Value = PacketV3;

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Err>
                where A: SeqAccess<'de>
            {
                let version: Version = seq.next_field()?;
                let msg_id: MessageID = seq.next_field()?;
                let max_size: MaxSize = seq.next_field()?;
                let flags: MessageFlags = seq.next_field()?;
                let security_model: SecurityModel = seq.next_field()?;
                let security_parameters: SecurityParameter = seq.next_field()?;
                let pdu: PduV3 = seq.next_field()?;

                Ok(PacketV3 {
                    version: version,
                    msg_id: msg_id,
                    max_size: max_size,
                    flags: flags,
                    security_model: security_model,
                    security_parameters: security_parameters,
                    pdu: pdu,
                })
            }
        }

        deserializer.deserialize_seq(PacketVisitor)
    }
}