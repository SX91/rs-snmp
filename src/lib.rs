#![cfg_attr(test, feature(test))]
#![cfg_attr(test, feature(plugin))]
// #![cfg_attr(test, plugin(quickcheck_macros))]
#![feature(conservative_impl_trait)]

#[cfg(test)]
extern crate test;

#[macro_use]
extern crate asn1_exp;

#[cfg(feature = "with-serde")]
#[macro_use]
extern crate serde_derive;

mod types;
mod asn1;

pub use types::*;

#[cfg(test)]
mod tests {
    use test;

    use super::*;

    use asn1_exp::{to_asn1, from_asn1, Asn1Serialize, Asn1Deserialize};
    use asn1_exp::der;


    #[allow(dead_code)]
    pub fn ser_deser<T>(v: &T) -> T
    where
        T: Asn1Serialize + for<'de> Asn1Deserialize,
    {
        from_asn1(&to_asn1(v).unwrap()).unwrap()
    }

    #[test]
    fn packet() {
        let p = PacketV2::new(Version::Version1, Community::new("test"), Pdu::new_empty_request(RequestType::Get));

        assert_eq!(p, ser_deser(&p))
    }

    #[bench]
    fn packet_serialize_bench(b: &mut test::Bencher) {
        let p = PacketV2::new(Version::Version1, Community::new("test"), Pdu::new_empty_request(RequestType::Get));

        b.iter(|| {
            to_asn1(&p).unwrap()
        })
    }

    #[bench]
    fn packet_deserialize_bench(b: &mut test::Bencher) {
        let p = PacketV2::new(Version::Version1, Community::new("test"), Pdu::new_empty_request(RequestType::Get));

        let buf = to_asn1(&p).unwrap();

        b.iter(|| {
            let deserializer = der::Deserializer::new(&buf[..]);
            PacketV2::asn1_deserialize(deserializer).unwrap()
        })
    }
}