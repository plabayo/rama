// Test-only material. Not used at runtime in any production path.
//
// The demo `tproxy_rs` handler factory expects a JSON config with
// `ca_cert_pem` + `ca_key_pem` overrides; when present it uses the
// supplied PEMs and skips the system keychain / Secure Enclave path.
// We bake test PEMs in so the engine can construct without needing an
// SE-capable host.

import Foundation

@testable import RamaAppleNetworkExtension

enum TestFixtures {
    static let caCertPem: String = """
        -----BEGIN CERTIFICATE-----
        MIICwDCCAagCCQC2kPPbSbt9bjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQKDBZS
        YW1hIFN3aWZ0IEZGSSBUZXN0IENBMCAXDTI2MDUwNzEwMDUwMFoYDzIxMjYwNDEz
        MTAwNTAwWjAhMR8wHQYDVQQKDBZSYW1hIFN3aWZ0IEZGSSBUZXN0IENBMIIBIjAN
        BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0UeuPbxtbIi/RK5lExGti8IIfOR6
        M/FdkRlzr40mWarBCsxvnWCn1xcCDX2oDkrZEMgl8anawgzBn566a5Qc/3opiLLn
        PdQaDPMtgyekQYrA+EG8SnyHbUA38QkOGJltAgUh2tbtIIU1UexuR3p2TRbuOCnk
        pvTw/WUtTopLptYcZOafP2ddWqSr1ObFguZONYTaCjOcYdA3HcpCdH1cr8/WmGn5
        XMFT3JxeefHB4Uxp/gPE9zE+PqHRp6vhENzXrE/rkM81GlhdGVOEbhEoxoI4pTJs
        1/XW6Vu2V4hygyw3l+LXsYrKQJ4pryDflA5sChpRIIAlrbsl0z5zqViqVQIDAQAB
        MA0GCSqGSIb3DQEBCwUAA4IBAQC2wBRYPP4RcGCzISNss1NJFHYKKcad5xkP9A68
        HE4C6Waj5wvIQ+rvzJfiVfS06TVSfmuOSFI23Rk5JjV83TwGsf8WOFsTZohh5OLv
        9f1/qg8xt1nByy3pURmH0ipJqdTzEXcxXiQutre93ewZvm3a1YqM7iOqsi+9tAWV
        +pSVR0w8urgXElFKT+TMSbURNp+TzMQZbbuNIn8FOgBZlDR8Tg+d1r0HOoNypvIo
        FZYOFFAqgwDPJrsoTvCcXU+DKVwTtjcWFhhxNhecx9vp9RSwMA1K8tmxzTTPjB2u
        CVSxlUHMuIs9AuqQ4AuEnBHzsks+FUepFlHtAor2nDpxEneJ
        -----END CERTIFICATE-----
        """.replacingOccurrences(of: "    ", with: "")

    static let caKeyPem: String = """
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRR649vG1siL9E
        rmUTEa2Lwgh85Hoz8V2RGXOvjSZZqsEKzG+dYKfXFwINfagOStkQyCXxqdrCDMGf
        nrprlBz/eimIsuc91BoM8y2DJ6RBisD4QbxKfIdtQDfxCQ4YmW0CBSHa1u0ghTVR
        7G5HenZNFu44KeSm9PD9ZS1Oikum1hxk5p8/Z11apKvU5sWC5k41hNoKM5xh0Dcd
        ykJ0fVyvz9aYaflcwVPcnF558cHhTGn+A8T3MT4+odGnq+EQ3NesT+uQzzUaWF0Z
        U4RuESjGgjilMmzX9dbpW7ZXiHKDLDeX4texispAnimvIN+UDmwKGlEggCWtuyXT
        PnOpWKpVAgMBAAECggEBAL1iu7hciz17pnMVypvuFHnz9lBnRns5Am5rdPg5qKne
        T2FhTeRCcsC/rnjc7Lc6XqLELSo7hp6ygonbT2JJH9DGEU4GcCLQjV6ItfgJaKhz
        U1uVyToy5S8lvTof8qSqOy5nzJJIi0Axq+XeKpH+rY3noV4r8yJvaKI27EA2AG4R
        k5yAsRtWqZ21OtQzz6Mq3H7gS9kZgrbGR8ZmJFj75wwttSa2XZgYhbufD+GbxJjT
        UiJE6m67wILtTvLtbBULsb9An77X/EHQPs5uSvdktsVD9JsHjV+a2oggOayAERXe
        oGkwaP5qkDAFbN/+/sOQQBhsKv3SD5paJM0ssFNkj2ECgYEA6lpHM3U6p8NZw+PW
        skCT79Pw4NTMLZ7aJLS7B39XKBAG0G6HX2JPqy5sLgyPcuaR/vVD0RhcRK8LiJAy
        gNioZh6dmxyP84PiD9kQF+8Flvvnb/3Q//+lYBMCD5ozoNReIK9gdcLjxdCLBmIn
        bgIqyHFAKw0C//MX7c9BUMPQ6/kCgYEA5JyC4cO1oS9oUzs0dtZG7DbvnUuRXToD
        52xsI+Xw6MlthEX4dYKkiMAf0H52MZ/evMytMth/sTekm7exddxOm14tvJKEBbSb
        RkBDUG59B1FFzhNQhRpobc/BbzEBsXo/kLnCAMOE8cVHv4SkDQgGE+bF2t+sT+vY
        1oaKOD3P8D0CgYBRIS/FALBto5NP3XBWBUUxoY2iSAjnQjcCvg6BafQiSmoRfjIf
        M0mhWVDaID8I6Ali2kW//U7z+CVmAYV6VYb202J8cEblZqK8GckYgAbPXiWg/517
        AmWd/PaZsChvZRWw+wXJvs5bjPaUHybHTrjA63Prc3W2ZdHC4h0aeK+7AQKBgB8O
        X/1Zf+gYr5x284adT18xi1Wb+XBnvDYJFZu+1f5ZtsX8V2dnSwDE0M2bEGVnaXPO
        fkzk+lvRykvZJYN0XT1gCuiOIt8/jMR7YGmhyNxgnxICr7KVRtB8I7P+PVOl3tLD
        WWaPKRVLDpcm5r5ac7DqbcBxGFB3Iqrp9gbz5ralAoGBAK/7690KDpJCtZoq87Ao
        tZ4E7EhtUpr0/34AgJFxLIqZ95kjBWyk4SkCb/6Zkzaorq1U4ekOgPNAbjsco2nF
        b2fsdYjXknOj1rB6NlmFW6ZE++kUGgP6nY9fm533EzRtR2R5edH4mx/QkeD8LXMk
        wQGI0roeJo1n27m0gbeQdCr6
        -----END PRIVATE KEY-----
        """.replacingOccurrences(of: "    ", with: "")

    /// JSON config the demo `tproxy_rs` handler factory accepts. Embeds
    /// our test CA so engine construction does not touch the system
    /// keychain or the Secure Enclave.
    static func engineConfigJson() -> Data {
        let payload: [String: Any] = [
            "html_badge_enabled": false,
            "html_badge_label": "rama-swift-ffi-test",
            "peek_duration_s": 0.5,
            "exclude_domains": [],
            "ca_cert_pem": caCertPem,
            "ca_key_pem": caKeyPem,
        ]
        return try! JSONSerialization.data(withJSONObject: payload)
    }

    /// One-time test-process FFI initialisation. Idempotent — repeated
    /// calls observe the same NSLock-guarded init flag.
    static func ensureInitialized() {
        struct Once { static let token: Bool = {
            let dir = NSTemporaryDirectory().appending("rama-swift-ffi-tests")
            try? FileManager.default.createDirectory(
                atPath: dir, withIntermediateDirectories: true, attributes: nil)
            _ = RamaTransparentProxyEngineHandle.initialize(
                storageDir: dir, appGroupDir: nil)
            return true
        }() }
        _ = Once.token
    }
}
