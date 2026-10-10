//! Counted runtime metadata uses the existing typed Web API/source model.

use super::{
    CanonicalDomain, CanonicalValue, JsProfile, JsProfileNavigator, JsProfileScreen,
    JsProfileWebApis, ProfileCaptureCompleteness, ProfileDataError, UserAgentRuntimeProfile,
    UserAgentSourceInfo,
    canonical::{CanonicalReader, CanonicalWriter},
};
use rama_utils::octets::kib;
use serde::Serialize;
use std::str;

/// Runtime metadata describes a captured report. It grants no network emulation
/// capability and does not replace protocol observations or their request bindings.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeProfileCapture {
    pub completeness: ProfileCaptureCompleteness,
    pub runtime: UserAgentRuntimeProfile,
}

impl RuntimeProfileCapture {
    /// Validate the borrowed metadata budget before retaining a copy.
    pub fn capture(
        completeness: ProfileCaptureCompleteness,
        runtime: &UserAgentRuntimeProfile,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        encode(completeness, runtime, maximum_bytes, false)?;
        let mut runtime = runtime.clone();
        normalize_runtime(&mut runtime);
        Ok(Self {
            completeness,
            runtime,
        })
    }
    /// The HTTP adapter borrows decoded report fields and validates their aggregate
    /// budget before cloning them into its already reserved queue slot.
    pub fn capture_report(
        source: Option<&UserAgentSourceInfo>,
        web_apis: Option<&JsProfileWebApis>,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        let completeness = ProfileCaptureCompleteness::Complete;
        encode_parts(
            completeness,
            source,
            web_apis.map_or(RuntimeJs::Absent, RuntimeJs::WebApis),
            maximum_bytes,
            false,
        )?;
        let mut runtime = UserAgentRuntimeProfile {
            source_info: source.cloned(),
            js_info: web_apis.map(|value| JsProfile {
                web_apis: Some(value.clone()),
            }),
        };
        normalize_runtime(&mut runtime);
        Ok(Self {
            completeness,
            runtime,
        })
    }

    pub fn canonical(&self, maximum_bytes: usize) -> Result<CanonicalValue, ProfileDataError> {
        encode(self.completeness, &self.runtime, maximum_bytes, false)
    }
    /// Presence, rather than screen dimensions or language strings, groups the
    /// bounded complete samples. No permutation rule is inferred for metadata.
    pub fn structural(&self, maximum_bytes: usize) -> Result<CanonicalValue, ProfileDataError> {
        self.canonical(maximum_bytes)?;
        encode(self.completeness, &self.runtime, maximum_bytes, true)
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        decode(value, maximum_bytes, false)
    }

    pub(super) fn validate_structure(
        value: &CanonicalValue,
        maximum_bytes: usize,
    ) -> Result<(), ProfileDataError> {
        decode(value, maximum_bytes, true)?;
        Ok(())
    }
}

fn normalize_runtime(runtime: &mut UserAgentRuntimeProfile) {
    if let Some(screen) = runtime
        .js_info
        .as_mut()
        .and_then(|js| js.web_apis.as_mut())
        .and_then(|apis| apis.screen.as_mut())
        && let Some(value) = &mut screen.moz_brightness
        && value.to_bits() & 0x7fff_ffff == 0
    {
        *value = 0.0;
    }
}

fn validate_text(value: &str, maximum: usize) -> Result<(), ProfileDataError> {
    if value.len() > maximum {
        return Err(ProfileDataError::LimitExceeded("runtime text field"));
    }
    if value.chars().any(char::is_control) {
        return Err(ProfileDataError::Invalid("runtime text control character"));
    }
    Ok(())
}

fn encode(
    completeness: ProfileCaptureCompleteness,
    runtime: &UserAgentRuntimeProfile,
    maximum_bytes: usize,
    structural: bool,
) -> Result<CanonicalValue, ProfileDataError> {
    encode_parts(
        completeness,
        runtime.source_info.as_ref(),
        match &runtime.js_info {
            None => RuntimeJs::Absent,
            Some(js) => js
                .web_apis
                .as_ref()
                .map_or(RuntimeJs::WithoutWebApis, RuntimeJs::WebApis),
        },
        maximum_bytes,
        structural,
    )
}

#[derive(Clone, Copy)]
enum RuntimeJs<'a> {
    Absent,
    WithoutWebApis,
    WebApis(&'a JsProfileWebApis),
}

fn encode_parts(
    completeness: ProfileCaptureCompleteness,
    source: Option<&UserAgentSourceInfo>,
    js: RuntimeJs<'_>,
    maximum_bytes: usize,
    structural: bool,
) -> Result<CanonicalValue, ProfileDataError> {
    completeness.require_complete("runtime metadata")?;
    if source.is_none() && matches!(js, RuntimeJs::Absent) {
        return Err(ProfileDataError::Incomplete("empty runtime metadata"));
    }
    let mut writer = CanonicalWriter::new(
        if structural {
            CanonicalDomain::RuntimeMetadataStructure
        } else {
            CanonicalDomain::RuntimeMetadata
        },
        maximum_bytes,
    )?;
    writer.u8(completeness.tag())?;
    writer.u8(u8::from(source.is_some()))?;
    if let Some(source) = source {
        write_source(&mut writer, source, structural)?;
    }
    writer.u8(u8::from(!matches!(js, RuntimeJs::Absent)))?;
    match js {
        RuntimeJs::Absent => {}
        RuntimeJs::WithoutWebApis => writer.u8(0)?,
        RuntimeJs::WebApis(apis) => {
            writer.u8(1)?;
            writer.u8(u8::from(apis.navigator.is_some()))?;
            if let Some(navigator) = &apis.navigator {
                write_navigator(&mut writer, navigator, structural)?;
            }
            writer.u8(u8::from(apis.screen.is_some()))?;
            if let Some(screen) = &apis.screen {
                write_screen(&mut writer, screen, structural)?;
            }
        }
    }
    Ok(writer.finish())
}

fn decode(
    value: &CanonicalValue,
    maximum_bytes: usize,
    structural: bool,
) -> Result<RuntimeProfileCapture, ProfileDataError> {
    let domain = if structural {
        CanonicalDomain::RuntimeMetadataStructure
    } else {
        CanonicalDomain::RuntimeMetadata
    };
    value.verify(domain, maximum_bytes)?;
    let mut reader = CanonicalReader::new(&value.bytes, domain)?;
    let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
    completeness.require_complete("runtime metadata")?;
    let source_info = if flag(&mut reader)? {
        Some(read_source(&mut reader, maximum_bytes, structural)?)
    } else {
        None
    };
    let js_info = if flag(&mut reader)? {
        Some(JsProfile {
            web_apis: if flag(&mut reader)? {
                Some(JsProfileWebApis {
                    navigator: if flag(&mut reader)? {
                        Some(read_navigator(&mut reader, maximum_bytes, structural)?)
                    } else {
                        None
                    },
                    screen: if flag(&mut reader)? {
                        Some(read_screen(&mut reader, maximum_bytes, structural)?)
                    } else {
                        None
                    },
                })
            } else {
                None
            },
        })
    } else {
        None
    };
    reader.finish()?;
    let capture = RuntimeProfileCapture {
        completeness,
        runtime: UserAgentRuntimeProfile {
            source_info,
            js_info,
        },
    };
    if encode(completeness, &capture.runtime, maximum_bytes, structural)?.bytes != value.bytes {
        return Err(ProfileDataError::Invalid("noncanonical runtime metadata"));
    }
    Ok(capture)
}

fn flag(reader: &mut CanonicalReader<'_>) -> Result<bool, ProfileDataError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProfileDataError::Invalid("runtime presence flag")),
    }
}

fn write_text(
    writer: &mut CanonicalWriter,
    value: Option<&str>,
    structural: bool,
) -> Result<(), ProfileDataError> {
    write_text_bounded(writer, value, structural, kib(1))
}

fn write_text_bounded(
    writer: &mut CanonicalWriter,
    value: Option<&str>,
    structural: bool,
    maximum: usize,
) -> Result<(), ProfileDataError> {
    writer.u8(u8::from(value.is_some()))?;
    if let Some(value) = value {
        validate_text(value, maximum)?;
        if !structural {
            writer.bytes(value.as_bytes())?;
        }
    }
    Ok(())
}

fn read_text(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
    structural: bool,
) -> Result<Option<String>, ProfileDataError> {
    read_text_bounded(reader, maximum.min(kib(1)), structural)
}

fn read_text_bounded(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
    structural: bool,
) -> Result<Option<String>, ProfileDataError> {
    if !flag(reader)? {
        return Ok(None);
    }
    if structural {
        return Ok(Some(String::new()));
    }
    let value = str::from_utf8(reader.bytes(maximum)?)
        .map_err(|_error| ProfileDataError::Invalid("runtime UTF-8"))?;
    validate_text(value, maximum)?;
    Ok(Some(value.to_owned()))
}

fn write_texts(
    writer: &mut CanonicalWriter,
    value: Option<&[String]>,
    structural: bool,
) -> Result<(), ProfileDataError> {
    writer.u8(u8::from(value.is_some()))?;
    if let Some(value) = value {
        if value.len() > 64 {
            return Err(ProfileDataError::LimitExceeded("runtime languages"));
        }
        if !structural {
            writer.u64(value.len() as u64)?;
            for text in value {
                validate_text(text, kib(1))?;
                writer.bytes(text.as_bytes())?;
            }
        }
    }
    Ok(())
}

fn read_texts(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
    structural: bool,
) -> Result<Option<Vec<String>>, ProfileDataError> {
    if !flag(reader)? {
        return Ok(None);
    }
    let mut values = Vec::new();
    if !structural {
        for _ in 0..reader.count(64)? {
            let text = str::from_utf8(reader.bytes(maximum.min(kib(1)))?)
                .map_err(|_error| ProfileDataError::Invalid("runtime UTF-8"))?;
            validate_text(text, kib(1))?;
            values.push(text.to_owned());
        }
    }
    Ok(Some(values))
}

fn write_bool(
    writer: &mut CanonicalWriter,
    value: Option<bool>,
    structural: bool,
) -> Result<(), ProfileDataError> {
    writer.u8(u8::from(value.is_some()))?;
    if let Some(value) = value
        && !structural
    {
        writer.u8(u8::from(value))?;
    }
    Ok(())
}

fn read_bool(
    reader: &mut CanonicalReader<'_>,
    _maximum: usize,
    structural: bool,
) -> Result<Option<bool>, ProfileDataError> {
    if !flag(reader)? {
        return Ok(None);
    }
    Ok(Some(if structural { false } else { flag(reader)? }))
}

fn write_int(
    writer: &mut CanonicalWriter,
    value: Option<i32>,
    structural: bool,
) -> Result<(), ProfileDataError> {
    writer.u8(u8::from(value.is_some()))?;
    if let Some(value) = value
        && !structural
    {
        writer.u32(u32::from_be_bytes(value.to_be_bytes()))?;
    }
    Ok(())
}

fn read_int(
    reader: &mut CanonicalReader<'_>,
    _maximum: usize,
    structural: bool,
) -> Result<Option<i32>, ProfileDataError> {
    if !flag(reader)? {
        return Ok(None);
    }
    Ok(Some(if structural {
        0
    } else {
        i32::from_be_bytes(reader.u32()?.to_be_bytes())
    }))
}

fn write_float(
    writer: &mut CanonicalWriter,
    value: Option<f32>,
    structural: bool,
) -> Result<(), ProfileDataError> {
    writer.u8(u8::from(value.is_some()))?;
    if let Some(value) = value {
        if !value.is_finite() {
            return Err(ProfileDataError::Invalid("nonfinite runtime number"));
        }
        if !structural {
            writer.u32(if value.to_bits() & 0x7fff_ffff == 0 {
                0
            } else {
                value.to_bits()
            })?;
        }
    }
    Ok(())
}

fn read_float(
    reader: &mut CanonicalReader<'_>,
    _maximum: usize,
    structural: bool,
) -> Result<Option<f32>, ProfileDataError> {
    if !flag(reader)? {
        return Ok(None);
    }
    Ok(Some(if structural {
        0.0
    } else {
        f32::from_bits(reader.u32()?)
    }))
}

fn write_source(
    writer: &mut CanonicalWriter,
    value: &UserAgentSourceInfo,
    structural: bool,
) -> Result<(), ProfileDataError> {
    write_text(writer, value.device_name.as_deref(), structural)?;
    write_text(writer, value.os.as_deref(), structural)?;
    write_text(writer, value.os_version.as_deref(), structural)?;
    write_text(writer, value.browser_name.as_deref(), structural)?;
    write_text(writer, value.browser_version.as_deref(), structural)?;
    Ok(())
}

fn read_source(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
    structural: bool,
) -> Result<UserAgentSourceInfo, ProfileDataError> {
    Ok(UserAgentSourceInfo {
        device_name: read_text(reader, maximum, structural)?,
        os: read_text(reader, maximum, structural)?,
        os_version: read_text(reader, maximum, structural)?,
        browser_name: read_text(reader, maximum, structural)?,
        browser_version: read_text(reader, maximum, structural)?,
    })
}

fn write_navigator(
    writer: &mut CanonicalWriter,
    value: &JsProfileNavigator,
    structural: bool,
) -> Result<(), ProfileDataError> {
    write_text(writer, value.app_code_name.as_deref(), structural)?;
    write_text(writer, value.app_name.as_deref(), structural)?;
    write_text(writer, value.build_id.as_deref(), structural)?;
    write_bool(writer, value.cookie_enabled, structural)?;
    write_text(writer, value.do_not_track.as_deref(), structural)?;
    write_text(writer, value.language.as_deref(), structural)?;
    write_texts(writer, value.languages.as_deref(), structural)?;
    write_text(writer, value.oscpu.as_deref(), structural)?;
    write_bool(writer, value.pdf_viewer_enabled, structural)?;
    write_text(writer, value.platform.as_deref(), structural)?;
    write_text(writer, value.product.as_deref(), structural)?;
    write_text(writer, value.product_sub.as_deref(), structural)?;
    write_text_bounded(writer, value.user_agent.as_deref(), structural, kib(8))?;
    write_text(writer, value.vendor.as_deref(), structural)?;
    write_text(writer, value.vendor_sub.as_deref(), structural)?;
    Ok(())
}

fn read_navigator(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
    structural: bool,
) -> Result<JsProfileNavigator, ProfileDataError> {
    Ok(JsProfileNavigator {
        app_code_name: read_text(reader, maximum, structural)?,
        app_name: read_text(reader, maximum, structural)?,
        build_id: read_text(reader, maximum, structural)?,
        cookie_enabled: read_bool(reader, maximum, structural)?,
        do_not_track: read_text(reader, maximum, structural)?,
        language: read_text(reader, maximum, structural)?,
        languages: read_texts(reader, maximum, structural)?,
        oscpu: read_text(reader, maximum, structural)?,
        pdf_viewer_enabled: read_bool(reader, maximum, structural)?,
        platform: read_text(reader, maximum, structural)?,
        product: read_text(reader, maximum, structural)?,
        product_sub: read_text(reader, maximum, structural)?,
        user_agent: read_text_bounded(reader, maximum.min(kib(8)), structural)?,
        vendor: read_text(reader, maximum, structural)?,
        vendor_sub: read_text(reader, maximum, structural)?,
    })
}

fn write_screen(
    writer: &mut CanonicalWriter,
    value: &JsProfileScreen,
    structural: bool,
) -> Result<(), ProfileDataError> {
    write_int(writer, value.width, structural)?;
    write_int(writer, value.height, structural)?;
    write_int(writer, value.avail_width, structural)?;
    write_int(writer, value.avail_height, structural)?;
    write_int(writer, value.avail_left, structural)?;
    write_int(writer, value.left, structural)?;
    write_int(writer, value.avail_top, structural)?;
    write_int(writer, value.top, structural)?;
    write_int(writer, value.color_depth, structural)?;
    write_int(writer, value.pixel_depth, structural)?;
    write_text(writer, value.screen_type.as_deref(), structural)?;
    write_text(writer, value.moz_orientation.as_deref(), structural)?;
    write_float(writer, value.moz_brightness, structural)?;
    write_text(writer, value.lock_orientation.as_deref(), structural)?;
    write_text(writer, value.unlock_orientation.as_deref(), structural)?;
    Ok(())
}

fn read_screen(
    reader: &mut CanonicalReader<'_>,
    maximum: usize,
    structural: bool,
) -> Result<JsProfileScreen, ProfileDataError> {
    Ok(JsProfileScreen {
        width: read_int(reader, maximum, structural)?,
        height: read_int(reader, maximum, structural)?,
        avail_width: read_int(reader, maximum, structural)?,
        avail_height: read_int(reader, maximum, structural)?,
        avail_left: read_int(reader, maximum, structural)?,
        left: read_int(reader, maximum, structural)?,
        avail_top: read_int(reader, maximum, structural)?,
        top: read_int(reader, maximum, structural)?,
        color_depth: read_int(reader, maximum, structural)?,
        pixel_depth: read_int(reader, maximum, structural)?,
        screen_type: read_text(reader, maximum, structural)?,
        moz_orientation: read_text(reader, maximum, structural)?,
        moz_brightness: read_float(reader, maximum, structural)?,
        lock_orientation: read_text(reader, maximum, structural)?,
        unlock_orientation: read_text(reader, maximum, structural)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits, ValueId,
    };
    use rama_utils::octets::kib;
    use sha2::{Digest as _, Sha256};

    fn source() -> UserAgentRuntimeProfile {
        UserAgentRuntimeProfile {
            js_info: None,
            source_info: Some(UserAgentSourceInfo {
                device_name: None,
                os: Some("TestOS".into()),
                os_version: Some("1.2".into()),
                browser_name: None,
                browser_version: None,
            }),
        }
    }

    fn fixture() -> UserAgentRuntimeProfile {
        serde_json::from_value(serde_json::json!({"source_info":{"device_name":"synthetic","os":"OS","os_version":"1.2","browser_name":"Browser","browser_version":"3.4"},"js_info":{"web_apis":{"navigator":{"app_code_name":"Mozilla","app_name":"Netscape","build_id":"7","cookie_enabled":false,"do_not_track":"1","language":"en-US","languages":["en-US","en","fr"],"oscpu":"test","pdf_viewer_enabled":true,"platform":"platform","product":"Gecko","product_sub":"1","user_agent":"Synthetic/1","vendor":"Vendor","vendor_sub":""},"screen":{"width":1024,"height":768,"avail_width":1000,"avail_height":700,"avail_left":-100,"left":-200,"avail_top":-300,"top":-400,"color_depth":24,"pixel_depth":24,"type":"lcd","moz_orientation":"landscape","moz_brightness":0.5,"lock_orientation":"lock","unlock_orientation":"unlock"}}}})).unwrap()
    }

    fn resign(bytes: Vec<u8>) -> CanonicalValue {
        CanonicalValue {
            id: ValueId(Sha256::digest(&bytes).into()),
            bytes: bytes.into(),
        }
    }

    #[test]
    fn runtime_metadata_uses_versioned_independent_canonical_bytes() {
        let capture = RuntimeProfileCapture::capture(
            ProfileCaptureCompleteness::Complete,
            &source(),
            kib(16),
        )
        .unwrap();
        let value = capture.canonical(kib(16)).unwrap();
        assert_eq!(
            value.id.0,
            [
                248, 21, 44, 247, 187, 105, 103, 44, 201, 136, 13, 6, 247, 67, 171, 168, 102, 10,
                16, 251, 252, 191, 178, 35, 232, 149, 161, 55, 133, 193, 173, 193
            ]
        );
        assert_eq!(value.bytes.len(), 50);
        let restored = RuntimeProfileCapture::from_canonical(&value, kib(16)).unwrap();
        assert_eq!(
            serde_json::to_value(&capture.runtime).unwrap(),
            serde_json::to_value(restored.runtime).unwrap()
        );
        assert_eq!(
            capture.structural(kib(16)).unwrap().id.0,
            [
                245, 62, 106, 110, 79, 245, 208, 105, 161, 48, 129, 237, 136, 201, 156, 52, 39, 68,
                172, 161, 64, 199, 29, 142, 224, 175, 145, 171, 57, 149, 103, 223
            ]
        );
    }

    #[test]
    fn runtime_round_trip_preserves_every_typed_field_and_absence() {
        for runtime in [
            source(),
            fixture(),
            UserAgentRuntimeProfile {
                source_info: None,
                js_info: Some(JsProfile { web_apis: None }),
            },
        ] {
            let capture = RuntimeProfileCapture::capture(
                ProfileCaptureCompleteness::Complete,
                &runtime,
                kib(16),
            )
            .unwrap();
            let value = capture.canonical(kib(16)).unwrap();
            let restored = RuntimeProfileCapture::from_canonical(&value, kib(16)).unwrap();
            assert_eq!(
                serde_json::to_value(runtime).unwrap(),
                serde_json::to_value(restored.runtime).unwrap()
            );
            assert_eq!(
                value.validated_domain(kib(16)).unwrap(),
                CanonicalDomain::RuntimeMetadata
            );
            assert_eq!(
                capture
                    .structural(kib(16))
                    .unwrap()
                    .validated_domain(kib(16))
                    .unwrap(),
                CanonicalDomain::RuntimeMetadataStructure
            );
        }
    }

    #[test]
    fn runtime_budget_completeness_and_language_limits_precede_retention() {
        let runtime = fixture();
        let value =
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap()
                .canonical(kib(16))
                .unwrap();
        for budget in [0, 1, value.bytes.len() - 1] {
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, budget)
                .unwrap_err();
            RuntimeProfileCapture::from_canonical(&value, budget).unwrap_err();
        }
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Incomplete, &runtime, kib(16))
            .unwrap_err();
        let mut capture =
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap();
        capture.completeness = ProfileCaptureCompleteness::Incomplete;
        capture.canonical(kib(16)).unwrap_err();
        capture.structural(kib(16)).unwrap_err();
        let mut runtime = runtime;
        runtime
            .js_info
            .as_mut()
            .unwrap()
            .web_apis
            .as_mut()
            .unwrap()
            .navigator
            .as_mut()
            .unwrap()
            .languages = Some(vec![String::new(); 65]);
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
            .unwrap_err();
        let empty = UserAgentRuntimeProfile {
            source_info: None,
            js_info: None,
        };
        RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &empty, kib(16))
            .unwrap_err();
    }

    #[test]
    fn runtime_floats_are_finite_and_negative_zero_has_one_identity() {
        let mut runtime = fixture();
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            runtime
                .js_info
                .as_mut()
                .unwrap()
                .web_apis
                .as_mut()
                .unwrap()
                .screen
                .as_mut()
                .unwrap()
                .moz_brightness = Some(value);
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap_err();
        }
        let mut ids = Vec::new();
        for value in [0.0, -0.0] {
            runtime
                .js_info
                .as_mut()
                .unwrap()
                .web_apis
                .as_mut()
                .unwrap()
                .screen
                .as_mut()
                .unwrap()
                .moz_brightness = Some(value);
            ids.push(
                RuntimeProfileCapture::capture(
                    ProfileCaptureCompleteness::Complete,
                    &runtime,
                    kib(16),
                )
                .unwrap()
                .canonical(kib(16))
                .unwrap()
                .id,
            );
        }
        assert_eq!(ids[0], ids[1]);
    }

    #[test]
    fn runtime_structures_group_values_but_preserve_field_presence() {
        let mut runtime = fixture();
        let original =
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap();
        let structure = original.structural(kib(16)).unwrap();
        runtime.source_info.as_mut().unwrap().browser_version = Some("different".into());
        runtime
            .js_info
            .as_mut()
            .unwrap()
            .web_apis
            .as_mut()
            .unwrap()
            .screen
            .as_mut()
            .unwrap()
            .width = Some(1920);
        let varied =
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap();
        assert_ne!(
            original.canonical(kib(16)).unwrap().id,
            varied.canonical(kib(16)).unwrap().id
        );
        assert_eq!(structure.id, varied.structural(kib(16)).unwrap().id);
        runtime.source_info.as_mut().unwrap().browser_version = None;
        assert_ne!(
            structure.id,
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap()
                .structural(kib(16))
                .unwrap()
                .id
        );
    }

    #[test]
    fn runtime_decode_rejects_bad_envelopes_tags_strings_and_trailing_bytes() {
        let original = RuntimeProfileCapture::capture(
            ProfileCaptureCompleteness::Complete,
            &source(),
            kib(16),
        )
        .unwrap()
        .canonical(kib(16))
        .unwrap();
        let mut bad = original.clone();
        bad.id.0[0] ^= 1;
        RuntimeProfileCapture::from_canonical(&bad, kib(16)).unwrap_err();
        for (index, byte) in [
            (14, 2),
            (17, 0),
            (17, 2),
            (18, 2),
            (19, 2),
            (20, 2),
            (29, 0xff),
        ] {
            let mut bytes = original.bytes.to_vec();
            bytes[index] = byte;
            resign(bytes).validated_domain(kib(16)).unwrap_err();
        }
        let mut bytes = original.bytes.to_vec();
        bytes.push(0);
        resign(bytes).validated_domain(kib(16)).unwrap_err();
        for length in 0..original.bytes.len() {
            resign(original.bytes[..length].to_vec())
                .validated_domain(kib(16))
                .unwrap_err();
        }
        let structure = RuntimeProfileCapture::capture(
            ProfileCaptureCompleteness::Complete,
            &source(),
            kib(16),
        )
        .unwrap()
        .structural(kib(16))
        .unwrap();
        let mut bytes = structure.bytes.to_vec();
        bytes[20] = 2;
        resign(bytes).validated_domain(kib(16)).unwrap_err();
    }

    #[test]
    fn runtime_metadata_is_request_owned_in_complete_joint_samples() {
        let value = RuntimeProfileCapture::capture(
            ProfileCaptureCompleteness::Complete,
            &fixture(),
            kib(16),
        )
        .unwrap()
        .canonical(kib(16))
        .unwrap();
        let mut joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: Box::new([CapturedSlot {
                kind: CapturedSlotKind::RuntimeMetadata,
                value,
            }]),
        };
        let limits = JointCaptureLimits::default();
        let encoded = joint.canonical(limits).unwrap();
        JointCapture::from_canonical(&encoded, limits).unwrap();
        joint
            .structural(limits)
            .unwrap()
            .validated_domain(limits.bytes)
            .unwrap();
        joint.level = CaptureLevel::Connection;
        joint.canonical(limits).unwrap_err();
        joint.structural(limits).unwrap_err();
    }

    #[test]
    fn runtime_report_adapter_checks_budgets_before_cloning_metadata() {
        let runtime = fixture();
        let web = runtime.js_info.as_ref().unwrap().web_apis.as_ref();
        let capture =
            RuntimeProfileCapture::capture_report(runtime.source_info.as_ref(), web, kib(16))
                .unwrap();
        assert_eq!(
            serde_json::to_value(&capture.runtime).unwrap(),
            serde_json::to_value(&runtime).unwrap()
        );
        for maximum in [0, 1, capture.canonical(kib(16)).unwrap().bytes.len() - 1] {
            RuntimeProfileCapture::capture_report(runtime.source_info.as_ref(), web, maximum)
                .unwrap_err();
        }
        RuntimeProfileCapture::capture_report(None, None, kib(16)).unwrap_err();
    }
    fn text_paths(value: &serde_json::Value, prefix: &str, paths: &mut Vec<String>) {
        match value {
            serde_json::Value::String(_) => paths.push(prefix.into()),
            serde_json::Value::Object(values) => {
                for (key, value) in values {
                    text_paths(value, &format!("{prefix}/{key}"), paths);
                }
            }
            serde_json::Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    text_paths(value, &format!("{prefix}/{index}"), paths);
                }
            }
            _ => (),
        }
    }

    #[test]
    fn every_runtime_text_field_has_a_local_bound_and_rejects_controls() {
        let source = serde_json::to_value(fixture()).unwrap();
        let mut paths = Vec::new();
        text_paths(&source, "", &mut paths);
        assert_eq!(paths.len(), 24);
        for path in paths {
            let maximum = if path.ends_with("/user_agent") {
                kib(8)
            } else {
                kib(1)
            };
            for text in [
                "x\0y".to_owned(),
                "x\u{7f}y".to_owned(),
                "x\u{85}y".to_owned(),
                "x".repeat(maximum + 1),
            ] {
                let mut invalid = source.clone();
                *invalid.pointer_mut(&path).unwrap() = text.into();
                let runtime: UserAgentRuntimeProfile = serde_json::from_value(invalid).unwrap();
                RuntimeProfileCapture::capture(
                    ProfileCaptureCompleteness::Complete,
                    &runtime,
                    kib(16),
                )
                .unwrap_err();
                RuntimeProfileCapture::capture_report(
                    runtime.source_info.as_ref(),
                    runtime.js_info.as_ref().and_then(|js| js.web_apis.as_ref()),
                    kib(16),
                )
                .unwrap_err();
            }
            let mut valid = source.clone();
            *valid.pointer_mut(&path).unwrap() = "x".repeat(maximum).into();
            let runtime: UserAgentRuntimeProfile = serde_json::from_value(valid).unwrap();
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap();
        }
    }

    #[test]
    fn imported_runtime_text_controls_are_rejected() {
        let value = RuntimeProfileCapture::capture(
            ProfileCaptureCompleteness::Complete,
            &source(),
            kib(16),
        )
        .unwrap()
        .canonical(kib(16))
        .unwrap();
        let mut bytes = value.bytes.to_vec();
        let start = bytes
            .windows(6)
            .position(|value| value == b"TestOS")
            .unwrap();
        bytes[start] = 0;
        RuntimeProfileCapture::from_canonical(&resign(bytes), kib(16)).unwrap_err();
    }

    #[test]
    fn retained_runtime_numbers_match_their_canonical_zero() {
        let mut runtime = fixture();
        runtime
            .js_info
            .as_mut()
            .unwrap()
            .web_apis
            .as_mut()
            .unwrap()
            .screen
            .as_mut()
            .unwrap()
            .moz_brightness = Some(-0.0);
        let captured =
            RuntimeProfileCapture::capture(ProfileCaptureCompleteness::Complete, &runtime, kib(16))
                .unwrap();
        let report = RuntimeProfileCapture::capture_report(
            runtime.source_info.as_ref(),
            runtime.js_info.as_ref().and_then(|js| js.web_apis.as_ref()),
            kib(16),
        )
        .unwrap();
        for captured in [captured, report] {
            let retained = captured
                .runtime
                .js_info
                .as_ref()
                .unwrap()
                .web_apis
                .as_ref()
                .unwrap()
                .screen
                .as_ref()
                .unwrap()
                .moz_brightness
                .unwrap();
            assert_eq!(retained.to_bits(), 0);
            let decoded = RuntimeProfileCapture::from_canonical(
                &captured.canonical(kib(16)).unwrap(),
                kib(16),
            )
            .unwrap();
            assert_eq!(
                serde_json::to_vec(&captured).unwrap(),
                serde_json::to_vec(&decoded).unwrap()
            );
        }
    }
}
