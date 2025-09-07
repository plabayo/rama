#![allow(missing_docs)]
#![allow(non_camel_case_types)]

use rama_core::{
    bytes::{BufMut, Bytes, BytesMut},
    error::OpaqueError,
};
use rama_utils::macros::enums::enum_builder;

macro_rules! impl_u16_is_grease {
    ($enum_name:ident) => {
        impl $enum_name {
            /// returns true if this id is a (tls) grease object
            #[must_use]
            pub fn is_grease(&self) -> bool {
                match self {
                    $enum_name::Unknown(x) if x & 0x0f0f == 0x0a0a => true,
                    _ => false,
                }
            }
        }
    };
}

enum_builder! {
    /// The `ProtocolVersion` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum ProtocolVersion {
        SSLv2 => 0x0200,
        SSLv3 => 0x0300,
        TLSv1_0 => 0x0301,
        TLSv1_1 => 0x0302,
        TLSv1_2 => 0x0303,
        TLSv1_3 => 0x0304,
        DTLSv1_0 => 0xFEFF,
        DTLSv1_2 => 0xFEFD,
        DTLSv1_3 => 0xFEFC,
    }
}

impl_u16_is_grease!(ProtocolVersion);

enum_builder! {
    /// The `CipherSuite` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum CipherSuite {
        TLS_NULL_WITH_NULL_NULL => 0x0000,
        TLS_RSA_WITH_NULL_MD5 => 0x0001,
        TLS_RSA_WITH_NULL_SHA => 0x0002,
        TLS_RSA_EXPORT_WITH_RC4_40_MD5 => 0x0003,
        TLS_RSA_WITH_RC4_128_MD5 => 0x0004,
        TLS_RSA_WITH_RC4_128_SHA => 0x0005,
        TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 => 0x0006,
        TLS_RSA_WITH_IDEA_CBC_SHA => 0x0007,
        TLS_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x0008,
        TLS_RSA_WITH_DES_CBC_SHA => 0x0009,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA => 0x000a,
        TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA => 0x000b,
        TLS_DH_DSS_WITH_DES_CBC_SHA => 0x000c,
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA => 0x000d,
        TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x000e,
        TLS_DH_RSA_WITH_DES_CBC_SHA => 0x000f,
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA => 0x0010,
        TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA => 0x0011,
        TLS_DHE_DSS_WITH_DES_CBC_SHA => 0x0012,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => 0x0013,
        TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x0014,
        TLS_DHE_RSA_WITH_DES_CBC_SHA => 0x0015,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA => 0x0016,
        TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 => 0x0017,
        TLS_DH_anon_WITH_RC4_128_MD5 => 0x0018,
        TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA => 0x0019,
        TLS_DH_anon_WITH_DES_CBC_SHA => 0x001a,
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA => 0x001b,
        SSL_FORTEZZA_KEA_WITH_NULL_SHA => 0x001c,
        SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA => 0x001d,
        TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA => 0x001e,
        TLS_KRB5_WITH_3DES_EDE_CBC_SHA => 0x001f,
        TLS_KRB5_WITH_RC4_128_SHA => 0x0020,
        TLS_KRB5_WITH_IDEA_CBC_SHA => 0x0021,
        TLS_KRB5_WITH_DES_CBC_MD5 => 0x0022,
        TLS_KRB5_WITH_3DES_EDE_CBC_MD5 => 0x0023,
        TLS_KRB5_WITH_RC4_128_MD5 => 0x0024,
        TLS_KRB5_WITH_IDEA_CBC_MD5 => 0x0025,
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA => 0x0026,
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA => 0x0027,
        TLS_KRB5_EXPORT_WITH_RC4_40_SHA => 0x0028,
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 => 0x0029,
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 => 0x002a,
        TLS_KRB5_EXPORT_WITH_RC4_40_MD5 => 0x002b,
        TLS_PSK_WITH_NULL_SHA => 0x002c,
        TLS_DHE_PSK_WITH_NULL_SHA => 0x002d,
        TLS_RSA_PSK_WITH_NULL_SHA => 0x002e,
        TLS_RSA_WITH_AES_128_CBC_SHA => 0x002f,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA => 0x0030,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA => 0x0031,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA => 0x0032,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA => 0x0033,
        TLS_DH_anon_WITH_AES_128_CBC_SHA => 0x0034,
        TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA => 0x0036,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA => 0x0037,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA => 0x0038,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA => 0x0039,
        TLS_DH_anon_WITH_AES_256_CBC_SHA => 0x003a,
        TLS_RSA_WITH_NULL_SHA256 => 0x003b,
        TLS_RSA_WITH_AES_128_CBC_SHA256 => 0x003c,
        TLS_RSA_WITH_AES_256_CBC_SHA256 => 0x003d,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256 => 0x003e,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256 => 0x003f,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => 0x0040,
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0041,
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA => 0x0042,
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0043,
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA => 0x0044,
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0045,
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA => 0x0046,
        TLS_ECDH_ECDSA_WITH_NULL_SHA_draft => 0x0047,
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA_draft => 0x0048,
        TLS_ECDH_ECDSA_WITH_DES_CBC_SHA_draft => 0x0049,
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA_draft => 0x004a,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA_draft => 0x004b,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA_draft => 0x004c,
        TLS_ECDH_ECNRA_WITH_DES_CBC_SHA_draft => 0x004d,
        TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA_draft => 0x004e,
        TLS_ECMQV_ECDSA_NULL_SHA_draft => 0x004f,
        TLS_ECMQV_ECDSA_WITH_RC4_128_SHA_draft => 0x0050,
        TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA_draft => 0x0051,
        TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA_draft => 0x0052,
        TLS_ECMQV_ECNRA_NULL_SHA_draft => 0x0053,
        TLS_ECMQV_ECNRA_WITH_RC4_128_SHA_draft => 0x0054,
        TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA_draft => 0x0055,
        TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA_draft => 0x0056,
        TLS_ECDH_anon_NULL_WITH_SHA_draft => 0x0057,
        TLS_ECDH_anon_WITH_RC4_128_SHA_draft => 0x0058,
        TLS_ECDH_anon_WITH_DES_CBC_SHA_draft => 0x0059,
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA_draft => 0x005a,
        TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA_draft => 0x005b,
        TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA_draft => 0x005c,
        TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 => 0x0060,
        TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 => 0x0061,
        TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA => 0x0062,
        TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA => 0x0063,
        TLS_RSA_EXPORT1024_WITH_RC4_56_SHA => 0x0064,
        TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA => 0x0065,
        TLS_DHE_DSS_WITH_RC4_128_SHA => 0x0066,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => 0x0067,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256 => 0x0068,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256 => 0x0069,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => 0x006a,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => 0x006b,
        TLS_DH_anon_WITH_AES_128_CBC_SHA256 => 0x006c,
        TLS_DH_anon_WITH_AES_256_CBC_SHA256 => 0x006d,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD => 0x0072,
        TLS_DHE_DSS_WITH_AES_128_CBC_RMD => 0x0073,
        TLS_DHE_DSS_WITH_AES_256_CBC_RMD => 0x0074,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD => 0x0077,
        TLS_DHE_RSA_WITH_AES_128_CBC_RMD => 0x0078,
        TLS_DHE_RSA_WITH_AES_256_CBC_RMD => 0x0079,
        TLS_RSA_WITH_3DES_EDE_CBC_RMD => 0x007c,
        TLS_RSA_WITH_AES_128_CBC_RMD => 0x007d,
        TLS_RSA_WITH_AES_256_CBC_RMD => 0x007e,
        TLS_GOSTR341094_WITH_28147_CNT_IMIT => 0x0080,
        TLS_GOSTR341001_WITH_28147_CNT_IMIT => 0x0081,
        TLS_GOSTR341094_WITH_NULL_GOSTR3411 => 0x0082,
        TLS_GOSTR341001_WITH_NULL_GOSTR3411 => 0x0083,
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0084,
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA => 0x0085,
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0086,
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => 0x0087,
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0088,
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA => 0x0089,
        TLS_PSK_WITH_RC4_128_SHA => 0x008a,
        TLS_PSK_WITH_3DES_EDE_CBC_SHA => 0x008b,
        TLS_PSK_WITH_AES_128_CBC_SHA => 0x008c,
        TLS_PSK_WITH_AES_256_CBC_SHA => 0x008d,
        TLS_DHE_PSK_WITH_RC4_128_SHA => 0x008e,
        TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA => 0x008f,
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA => 0x0090,
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA => 0x0091,
        TLS_RSA_PSK_WITH_RC4_128_SHA => 0x0092,
        TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA => 0x0093,
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA => 0x0094,
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA => 0x0095,
        TLS_RSA_WITH_SEED_CBC_SHA => 0x0096,
        TLS_DH_DSS_WITH_SEED_CBC_SHA => 0x0097,
        TLS_DH_RSA_WITH_SEED_CBC_SHA => 0x0098,
        TLS_DHE_DSS_WITH_SEED_CBC_SHA => 0x0099,
        TLS_DHE_RSA_WITH_SEED_CBC_SHA => 0x009a,
        TLS_DH_anon_WITH_SEED_CBC_SHA => 0x009b,
        TLS_RSA_WITH_AES_128_GCM_SHA256 => 0x009c,
        TLS_RSA_WITH_AES_256_GCM_SHA384 => 0x009d,
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => 0x009e,
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => 0x009f,
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256 => 0x00a0,
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384 => 0x00a1,
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 => 0x00a2,
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 => 0x00a3,
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256 => 0x00a4,
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384 => 0x00a5,
        TLS_DH_anon_WITH_AES_128_GCM_SHA256 => 0x00a6,
        TLS_DH_anon_WITH_AES_256_GCM_SHA384 => 0x00a7,
        TLS_PSK_WITH_AES_128_GCM_SHA256 => 0x00a8,
        TLS_PSK_WITH_AES_256_GCM_SHA384 => 0x00a9,
        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 => 0x00aa,
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 => 0x00ab,
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 => 0x00ac,
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 => 0x00ad,
        TLS_PSK_WITH_AES_128_CBC_SHA256 => 0x00ae,
        TLS_PSK_WITH_AES_256_CBC_SHA384 => 0x00af,
        TLS_PSK_WITH_NULL_SHA256 => 0x00b0,
        TLS_PSK_WITH_NULL_SHA384 => 0x00b1,
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 => 0x00b2,
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 => 0x00b3,
        TLS_DHE_PSK_WITH_NULL_SHA256 => 0x00b4,
        TLS_DHE_PSK_WITH_NULL_SHA384 => 0x00b5,
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 => 0x00b6,
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 => 0x00b7,
        TLS_RSA_PSK_WITH_NULL_SHA256 => 0x00b8,
        TLS_RSA_PSK_WITH_NULL_SHA384 => 0x00b9,
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00ba,
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bb,
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bc,
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bd,
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00be,
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bf,
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c0,
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c1,
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c2,
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c3,
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c4,
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c5,
        TLS_SM4_GCM_SM3 => 0x00C6,
        TLS_SM4_CCM_SM3 => 0x00C7,
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 0x00ff,
        TLS13_AES_128_GCM_SHA256 => 0x1301,
        TLS13_AES_256_GCM_SHA384 => 0x1302,
        TLS13_CHACHA20_POLY1305_SHA256 => 0x1303,
        TLS13_AES_128_CCM_SHA256 => 0x1304,
        TLS13_AES_128_CCM_8_SHA256 => 0x1305,
        TLS_AEGIS_256_SHA512 => 0x1306,
        TLS_AEGIS_128L_SHA256 => 0x1307,
        TLS_FALLBACK_SCSV => 0x5600,
        TLS_ECDH_ECDSA_WITH_NULL_SHA => 0xc001,
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA => 0xc002,
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xc003,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA => 0xc004,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA => 0xc005,
        TLS_ECDHE_ECDSA_WITH_NULL_SHA => 0xc006,
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => 0xc007,
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xc008,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => 0xc009,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 0xc00a,
        TLS_ECDH_RSA_WITH_NULL_SHA => 0xc00b,
        TLS_ECDH_RSA_WITH_RC4_128_SHA => 0xc00c,
        TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA => 0xc00d,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA => 0xc00e,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA => 0xc00f,
        TLS_ECDHE_RSA_WITH_NULL_SHA => 0xc010,
        TLS_ECDHE_RSA_WITH_RC4_128_SHA => 0xc011,
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => 0xc012,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xc013,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xc014,
        TLS_ECDH_anon_WITH_NULL_SHA => 0xc015,
        TLS_ECDH_anon_WITH_RC4_128_SHA => 0xc016,
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA => 0xc017,
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA => 0xc018,
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA => 0xc019,
        TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA => 0xc01a,
        TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA => 0xc01b,
        TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA => 0xc01c,
        TLS_SRP_SHA_WITH_AES_128_CBC_SHA => 0xc01d,
        TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA => 0xc01e,
        TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA => 0xc01f,
        TLS_SRP_SHA_WITH_AES_256_CBC_SHA => 0xc020,
        TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA => 0xc021,
        TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA => 0xc022,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc023,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc024,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc025,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc026,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => 0xc027,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => 0xc028,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 => 0xc029,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 => 0xc02a,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02b,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02c,
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02d,
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02e,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xc02f,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xc030,
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 => 0xc031,
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => 0xc032,
        TLS_ECDHE_PSK_WITH_RC4_128_SHA => 0xc033,
        TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA => 0xc034,
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA => 0xc035,
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA => 0xc036,
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 => 0xc037,
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 => 0xc038,
        TLS_ECDHE_PSK_WITH_NULL_SHA => 0xc039,
        TLS_ECDHE_PSK_WITH_NULL_SHA256 => 0xc03a,
        TLS_ECDHE_PSK_WITH_NULL_SHA384 => 0xc03b,
        TLS_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc03c,
        TLS_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc03d,
        TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 => 0xc03e,
        TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 => 0xc03f,
        TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc040,
        TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc041,
        TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 => 0xc042,
        TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 => 0xc043,
        TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc044,
        TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc045,
        TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 => 0xc046,
        TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 => 0xc047,
        TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 => 0xc048,
        TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 => 0xc049,
        TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 => 0xc04a,
        TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 => 0xc04b,
        TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc04c,
        TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc04d,
        TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc04e,
        TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc04f,
        TLS_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc050,
        TLS_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc051,
        TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc052,
        TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc053,
        TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc054,
        TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc055,
        TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 => 0xc056,
        TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 => 0xc057,
        TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 => 0xc058,
        TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 => 0xc059,
        TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 => 0xc05a,
        TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 => 0xc05b,
        TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 => 0xc05c,
        TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 => 0xc05d,
        TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 => 0xc05e,
        TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 => 0xc05f,
        TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc060,
        TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc061,
        TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc062,
        TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc063,
        TLS_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc064,
        TLS_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc065,
        TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc066,
        TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc067,
        TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc068,
        TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc069,
        TLS_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06a,
        TLS_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06b,
        TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06c,
        TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06d,
        TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06e,
        TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06f,
        TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc070,
        TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc071,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc072,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc073,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc074,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc075,
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc076,
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc077,
        TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc078,
        TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc079,
        TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07a,
        TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07b,
        TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07c,
        TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07d,
        TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07e,
        TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07f,
        TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 => 0xc080,
        TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 => 0xc081,
        TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 => 0xc082,
        TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 => 0xc083,
        TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 => 0xc084,
        TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 => 0xc085,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc086,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc087,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc088,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc089,
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08a,
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08b,
        TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08c,
        TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08d,
        TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08e,
        TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08f,
        TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc090,
        TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc091,
        TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc092,
        TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc093,
        TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc094,
        TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc095,
        TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc096,
        TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc097,
        TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc098,
        TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc099,
        TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc09a,
        TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc09b,
        TLS_RSA_WITH_AES_128_CCM => 0xc09c,
        TLS_RSA_WITH_AES_256_CCM => 0xc09d,
        TLS_DHE_RSA_WITH_AES_128_CCM => 0xc09e,
        TLS_DHE_RSA_WITH_AES_256_CCM => 0xc09f,
        TLS_RSA_WITH_AES_128_CCM_8 => 0xc0a0,
        TLS_RSA_WITH_AES_256_CCM_8 => 0xc0a1,
        TLS_DHE_RSA_WITH_AES_128_CCM_8 => 0xc0a2,
        TLS_DHE_RSA_WITH_AES_256_CCM_8 => 0xc0a3,
        TLS_PSK_WITH_AES_128_CCM => 0xc0a4,
        TLS_PSK_WITH_AES_256_CCM => 0xc0a5,
        TLS_DHE_PSK_WITH_AES_128_CCM => 0xc0a6,
        TLS_DHE_PSK_WITH_AES_256_CCM => 0xc0a7,
        TLS_PSK_WITH_AES_128_CCM_8 => 0xc0a8,
        TLS_PSK_WITH_AES_256_CCM_8 => 0xc0a9,
        TLS_PSK_DHE_WITH_AES_128_CCM_8 => 0xc0aa,
        TLS_PSK_DHE_WITH_AES_256_CCM_8 => 0xc0ab,
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM => 0xc0ac,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM => 0xc0ad,
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 => 0xc0ae,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 => 0xc0af,
        TLS_ECCPWD_WITH_AES_128_GCM_SHA256 => 0xc0b0,
        TLS_ECCPWD_WITH_AES_256_GCM_SHA384 => 0xc0b1,
        TLS_ECCPWD_WITH_AES_128_CCM_SHA256 => 0xc0b2,
        TLS_ECCPWD_WITH_AES_256_CCM_SHA384 => 0xc0b3,
        TLS_SHA256_SHA256 => 0xc0b4,
        TLS_SHA384_SHA384 => 0xC0B5,
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC => 0xc100,
        TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC => 0xc101,
        TLS_GOSTR341112_256_WITH_28147_CNT_IMIT => 0xc102,
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L => 0xc103,
        TLS_GOSTR341112_256_WITH_MAGMA_MGM_L => 0xC104,
        TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S => 0xC105,
        TLS_GOSTR341112_256_WITH_MAGMA_MGM_S => 0xC106,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca8,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca9,
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xccaa,
        TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccab,
        TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccac,
        TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccad,
        TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccae,
        TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 => 0xd001,
        TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 => 0xd002,
        TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 => 0xd003,
        TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 => 0xd005,
        SSL_RSA_FIPS_WITH_DES_CBC_SHA => 0xfefe,
        SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA => 0xfeff,
        DRAFT_TLS_GOSTR341112_256_WITH_28147_CNT_IMIT => 0xff85,
    }
}

impl_u16_is_grease!(CipherSuite);

enum_builder! {
    /// The `SignatureScheme` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum SignatureScheme {
        RSA_PKCS1_SHA1 => 0x0201,
        ECDSA_SHA1_Legacy => 0x0203,
        SHA224_ECDSA => 0x0303,
        SHA224_RSA => 0x0301,
        SHA224_DSA => 0x0302,
        RSA_PKCS1_SHA256 => 0x0401,
        SHA256_DSA => 0x0402,
        ECDSA_NISTP256_SHA256 => 0x0403,
        RSA_PKCS1_SHA256_LEGACY => 0x0420,
        RSA_PKCS1_SHA384 => 0x0501,
        SHA384_DSA => 0x0502,
        ECDSA_NISTP384_SHA384 => 0x0503,  // also labeled as ecdsa_secp384r1_sha384
        RSA_PKCS1_SHA384_LEGACY => 0x0520,
        RSA_PKCS1_SHA512 => 0x0601,
        SHA512_DSA => 0x0602,
        ECDSA_NISTP521_SHA512 => 0x0603,
        RSA_PKCS1_SHA512_LEGACY => 0x0620,
        ECCSI_SHA256 => 0x0704,
        ISO_IBS1 => 0x0705,
        ISO_IBS2 => 0x0706,
        ISO_CHINESE_IBS => 0x0707,
        SM2SIG_SM3 => 0x0708,
        GOSTR34102012_256A => 0x0709,
        GOSTR34102012_256B => 0x070a,
        GOSTR34102012_256C => 0x070b,
        GOSTR34102012_256D => 0x070c,
        GOSTR34102012_512A => 0x070d,
        GOSTR34102012_512B => 0x070e,
        GOSTR34102012_512C => 0x070f,
        RSA_PSS_SHA256 => 0x0804,
        RSA_PSS_SHA384 => 0x0805,  // also known as RSA_PSS_RSAE_SHA384
        RSA_PSS_SHA512 => 0x0806,  // also known as RSA_PSS_RSAE_SHA512
        ED25519 => 0x0807,
        ED448 => 0x0808,
        RSA_PSS_PSS_SHA256 => 0x0809,
        RSA_PSS_PSS_SHA384 => 0x080a,
        RSA_PSS_PSS_SHA512 => 0x080b,
        ECDSA_BRAINPOOLP256R1TLS13_SHA256 => 0x081a,
        ECDSA_BRAINPOOLP384R1TLS13_SHA384 => 0x081b,
        ECDSA_BRAINPOOLP512R1TLS13_SHA512 => 0x081c,
        RSA_PKCS1_MD5_SHA1 => 0xff01,
    }
}

impl_u16_is_grease!(SignatureScheme);

enum_builder! {
    /// The `ExtensionId` enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum ExtensionId {
        SERVER_NAME => 0,
        MAX_FRAGMENT_LENGTH => 1,
        CLIENT_CERTIFICATE_URL => 2,
        TRUSTED_CA_KEYS => 3,
        TRUNCATED_HMAC => 4,
        STATUS_REQUEST => 5,
        USER_MAPPING => 6,
        CLIENT_AUTHZ => 7,
        SERVER_AUTHZ => 8,
        CERT_TYPE => 9,
        SUPPORTED_GROUPS => 10,
        EC_POINT_FORMATS => 11,
        SRP => 12,
        SIGNATURE_ALGORITHMS => 13,
        USE_SRTP => 14,
        HEARTBEAT => 15,
        APPLICATION_LAYER_PROTOCOL_NEGOTIATION => 16,
        STATUS_REQUEST_V2 => 17,
        SIGNED_CERTIFICATE_TIMESTAMP => 18,
        CLIENT_CERTIFICATE_TYPE => 19,
        SERVER_CERTIFICATE_TYPE => 20,
        PADDING => 21,
        ENCRYPT_THEN_MAC => 22,
        EXTENDED_MASTER_SECRET => 23,
        TOKEN_BINDING => 24,
        CACHED_INFO => 25,
        TLS_LTS => 26,
        COMPRESS_CERTIFICATE => 27,
        RECORD_SIZE_LIMIT => 28,
        PWD_PROTECT => 29,
        PWD_CLEAR => 30,
        PASSWORD_SALT => 31,
        TICKET_PINNING => 32,
        TLS_CERT_WITH_EXTERN_PSK => 33,
        DELEGATED_CREDENTIAL => 34,
        SESSION_TICKET => 35,
        TLMSP => 36,
        TLMSP_PROXYING => 37,
        TLMSP_DELEGATE => 38,
        SUPPORTED_EKT_CIPHERS => 39,
        PRE_SHARED_KEY => 41,
        EARLY_DATA => 42,
        SUPPORTED_VERSIONS => 43,
        COOKIE => 44,
        PSK_KEY_EXCHANGE_MODES => 45,
        CERTIFICATE_AUTHORITIES => 47,
        OID_FILTERS => 48,
        POST_HANDSHAKE_AUTH => 49,
        SIGNATURE_ALGORITHMS_CERT => 50,
        KEY_SHARE => 51,
        TRANSPARENCY_INFO => 52,
        CONNECTION_ID => 54,
        EXTERNAL_ID_HASH => 55,
        EXTERNAL_SESSION_ID => 56,
        QUIC_TRANSPORT_PARAMETERS => 57,
        TICKET_REQUEST => 58,
        DNSSEC_CHAIN => 59,
        SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS => 60,
        RRC => 61,
        NEXT_PROTOCOL_NEGOTIATION => 13172,
        OLD_APPLICATION_SETTINGS => 17513,
        APPLICATION_SETTINGS => 17613,
        ECH_OUTER_EXTENSIONS => 64768,
        ENCRYPTED_CLIENT_HELLO => 65037,
        RENEGOTIATION_INFO => 65281,
    }
}

impl_u16_is_grease!(ExtensionId);

enum_builder! {
    /// The `CompressionAlgorithm` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum CompressionAlgorithm {
        Null => 0x00,
        Deflate => 0x01,
    }
}

enum_builder! {
    /// The `ECPointFormat` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum ECPointFormat {
        Uncompressed => 0x00,
        ANSIX962CompressedPrime => 0x01,
        ANSIX962CompressedChar2 => 0x02,
    }
}

enum_builder! {
    /// The `SupportedGroup` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum SupportedGroup {
        SECT163K1 => 0x0001,
        SECT163R1 => 0x0002,
        SECT163R2 => 0x0003,
        SECT193R1 => 0x0004,
        SECT193R2 => 0x0005,
        SECT233K1 => 0x0006,
        SECT233R1 => 0x0007,
        SECT239K1 => 0x0008,
        SECT283K1 => 0x0009,
        SECT283R1 => 0x000a,
        SECT409K1 => 0x000b,
        SECT409R1 => 0x000c,
        SECT571K1 => 0x000d,
        SECT571R1 => 0x000e,
        SECP160K1 => 0x000f,
        SECP160R1 => 0x0010,
        SECP160R2 => 0x0011,
        SECP192K1 => 0x0012,
        SECP192R1 => 0x0013,
        SECP224K1 => 0x0014,
        SECP224R1 => 0x0015,
        SECP256K1 => 0x0016,
        SECP256R1 => 0x0017,
        SECP384R1 => 0x0018,
        SECP521R1 => 0x0019,
        BRAINPOOLP256R1 => 0x001a,
        BRAINPOOLP384R1 => 0x001b,
        BRAINPOOLP512R1 => 0x001c,
        X25519 => 0x001d,
        X448 => 0x001e,
        BRAINPOOLP256R1TLS13 => 0x001f,
        BRAINPOOLP384R1TLS13 => 0x0020,
        BRAINPOOLP512R1TLS13 => 0x0021,
        GC256A => 0x0022,
        GC256B => 0x0023,
        GC256C => 0x0024,
        GC256D => 0x0025,
        GC512A => 0x0026,
        GC512B => 0x0027,
        GC512C => 0x0028,
        CURVESM2 => 0x0029,
        FFDHE2048 => 0x0100,
        FFDHE3072 => 0x0101,
        FFDHE4096 => 0x0102,
        FFDHE6144 => 0x0103,
        FFDHE8192 => 0x0104,
        X25519KYBER768DRAFT00 => 0x6399,
        SECP256R1KYBER768DRAFT00 => 0x639a,
        ARBITRARY_EXPLICIT_PRIME_CURVES => 0xff01,
        ARBITRARY_EXPLICIT_CHAR2_CURVES => 0xff02,
    }
}

impl_u16_is_grease!(SupportedGroup);

enum_builder! {
    /// The Application Layer Negotiation Protocol (ALPN) identifiers
    /// as found in the IANA registry for Tls ExtensionType values.
    @Bytes
    pub enum ApplicationProtocol {
        HTTP_09 => b"http/0.9",
        HTTP_10 => b"http/1.0",
        HTTP_11 => b"http/1.1",
        SPDY_1 => b"spdy/1",
        SPDY_2 => b"spdy/2",
        SPDY_3 => b"spdy/3",
        STUN_TURN => b"stun.turn",
        STUN_NAT_DISCOVERY => b"stun.nat-discovery",
        HTTP_2 => b"h2",
        HTTP_2_TCP => b"h2c",
        WebRTC => b"webrtc",
        CWebRTC => b"c-webrtc",
        FTP => b"ftp",
        IMAP => b"imap",
        POP3 => b"pop3",
        ManageSieve => b"managesieve",
        CoAP_TLS => b"coap",
        CoAP_DTLS => b"co",
        XMPP_CLIENT => b"xmpp-client",
        XMPP_SERVER => b"xmpp-server",
        ACME_TLS => b"acme-tls/1",
        MQTT => b"mqtt",
        DNS_OVER_TLS => b"dot",
        NTSKE_1 => b"ntske/1",
        SunRPC => b"sunrpc",
        HTTP_3 => b"h3",
        SMB2 => b"smb",
        IRC => b"irc",
        NNTP => b"nntp",
        NNSP => b"nnsp",
        DoQ => b"doq",
        SIP => b"sip/2",
        TDS_80 => b"tds/8.0",
        DICOM => b"dicom",
        PostgreSQL => b"postgresql",
    }
}

impl ApplicationProtocol {
    pub fn encode_wire_format(&self, w: &mut impl std::io::Write) -> std::io::Result<usize> {
        let b = self.as_bytes();
        if b.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                OpaqueError::from_display("application protocol is too large"),
            ));
        }

        w.write_all(&[b.len() as u8])?;
        w.write_all(b)?;
        Ok(b.len() + 1)
    }

    pub fn decode_wire_format(r: &mut impl std::io::Read) -> std::io::Result<Self> {
        let mut length = [0];
        r.read_exact(&mut length)?;

        let length = length[0] as usize;

        let mut buf = vec![0; length];
        r.read_exact(&mut buf[..])?;

        Ok(buf.into())
    }

    pub fn encode_alpns(alpns: &[Self]) -> std::io::Result<Bytes> {
        let alpn_protos =
            BytesMut::with_capacity(alpns.iter().map(|alpn| alpn.as_bytes().len() + 1).sum());
        let mut writer = alpn_protos.writer();
        for alpn in alpns {
            alpn.encode_wire_format(&mut writer)?;
        }
        Ok(writer.into_inner().freeze())
    }
}

enum_builder! {
    /// The `CertificateCompressionAlgorithm` TLS protocol enum, the algorithm used to compress the certificate.
    /// The algorithm MUST be one of the algorithms listed in the peer's compress_certificate extension.
    @U16
    pub enum CertificateCompressionAlgorithm {
        Zlib => 0x0001,
        Brotli => 0x0002,
        Zstd => 0x0003,
    }
}

enum_builder! {
    /// Key derivation function used in hybrid public key encryption
    @U16
    pub enum KeyDerivationFunction {
        HKDF_SHA256 => 0x0001,
        HKDF_SHA384 => 0x0002,
        HKDF_SHA512 => 0x0003,
    }
}

enum_builder! {
    /// Authenticated encryption with associated data (AEAD) used in hybrid public key encryption
    @U16
    pub enum AuthenticatedEncryptionWithAssociatedData {
        AES_128_GCM => 0x0001,
        AES_256_GCM => 0x0002,
        ChaCha20Poly1305 => 0x0003,
        ExportOnly => 0xffff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_uint_display() {
        assert_eq!("X25519 (0x001d)", SupportedGroup::X25519.to_string());
        assert_eq!("Unknown (0xffff)", SupportedGroup::from(0xffff).to_string());
        assert_eq!("GREASE (0xdada)", SupportedGroup::from(0xdada).to_string());
    }

    #[test]
    fn test_enum_bytes_display() {
        assert_eq!("http/1.1", ApplicationProtocol::HTTP_11.to_string());
        assert_eq!(
            "Unknown (h42)",
            ApplicationProtocol::from(b"h42").to_string()
        );
        assert_eq!(
            "GREASE (0xdada)",
            ApplicationProtocol::from(&[0xda, 0xda]).to_string()
        );
        assert_eq!("Unknown (\0)", ApplicationProtocol::from(&[0]).to_string());
    }

    #[test]
    fn test_application_protocol_wire_format() {
        let test_cases = [
            (ApplicationProtocol::HTTP_11, "\x08http/1.1"),
            (ApplicationProtocol::HTTP_2, "\x02h2"),
        ];
        for (proto, expected_wire_format) in test_cases {
            let mut buf = Vec::new();
            proto.encode_wire_format(&mut buf).unwrap();
            assert_eq!(
                &buf[..],
                expected_wire_format.as_bytes(),
                "proto({proto}) => expected_wire_format({expected_wire_format})",
            );

            let mut reader = std::io::Cursor::new(&buf[..]);
            let output_proto = ApplicationProtocol::decode_wire_format(&mut reader).unwrap();
            assert_eq!(
                output_proto, proto,
                "expected_wire_format({expected_wire_format}) => proto({proto})",
            );
        }
    }

    #[test]
    fn test_application_protocol_decode_wire_format_multiple() {
        const INPUT: &str = "\x02h2\x08http/1.1";
        let mut r = std::io::Cursor::new(INPUT);
        assert_eq!(
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::decode_wire_format(&mut r).unwrap()
        );
        assert_eq!(3, r.position());
        assert_eq!(&INPUT.as_bytes()[0..3], b"\x02h2");
        assert_eq!(
            ApplicationProtocol::HTTP_11,
            ApplicationProtocol::decode_wire_format(&mut r).unwrap()
        );
        assert_eq!(12, r.position());
        assert_eq!(&INPUT.as_bytes()[3..12], b"\x08http/1.1");
    }

    #[test]
    fn test_enum_u8_serialize_deserialize() {
        let p: ECPointFormat = serde_json::from_str(
            &serde_json::to_string(&ECPointFormat::ANSIX962CompressedChar2).unwrap(),
        )
        .unwrap();
        assert_eq!(ECPointFormat::ANSIX962CompressedChar2, p);

        let p: ECPointFormat =
            serde_json::from_str(&serde_json::to_string(&ECPointFormat::from(42u8)).unwrap())
                .unwrap();
        assert_eq!(ECPointFormat::from(42u8), p);
    }

    #[test]
    fn test_enum_u16_serialize_deserialize() {
        let p: SupportedGroup =
            serde_json::from_str(&serde_json::to_string(&SupportedGroup::BRAINPOOLP384R1).unwrap())
                .unwrap();
        assert_eq!(SupportedGroup::BRAINPOOLP384R1, p);

        let p: SupportedGroup =
            serde_json::from_str(&serde_json::to_string(&SupportedGroup::from(0xffffu16)).unwrap())
                .unwrap();
        assert_eq!(SupportedGroup::from(0xffffu16), p);
    }

    #[test]
    fn test_enum_bytes_serialize_deserialize() {
        let p: ApplicationProtocol =
            serde_json::from_str(&serde_json::to_string(&ApplicationProtocol::HTTP_3).unwrap())
                .unwrap();
        assert_eq!(ApplicationProtocol::HTTP_3, p);

        let p: ApplicationProtocol = serde_json::from_str(
            &serde_json::to_string(&ApplicationProtocol::from(b"foobar")).unwrap(),
        )
        .unwrap();
        assert_eq!(ApplicationProtocol::from(b"foobar"), p);
    }
}
