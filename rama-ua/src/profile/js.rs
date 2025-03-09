use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct JsProfile {
    pub web_apis: Option<Arc<JsProfileWebApis>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsProfileWebApis {
    pub navigator: Option<JsProfileNavigator>,
    pub screen: Option<JsProfileScreen>,
}

impl<'de> Deserialize<'de> for JsProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let profile = JsProfileDeserialize::deserialize(deserializer)?;
        Ok(Self {
            web_apis: profile.web_apis.map(Arc::new),
        })
    }
}

impl Serialize for JsProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        JsProfileSerialize {
            web_apis: self.web_apis.as_deref(),
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Serialize)]
struct JsProfileSerialize<'a> {
    pub web_apis: Option<&'a JsProfileWebApis>,
}

#[derive(Debug, Deserialize)]
struct JsProfileDeserialize {
    pub web_apis: Option<JsProfileWebApis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsProfileNavigator {
    #[serde(alias = "appCodeName")]
    pub app_code_name: Option<String>,
    #[serde(alias = "appName")]
    pub app_name: Option<String>,
    #[serde(alias = "appVersion")]
    pub app_version: Option<String>,
    #[serde(alias = "buildID")]
    pub build_id: Option<String>,
    #[serde(alias = "cookieEnabled")]
    pub cookie_enabled: Option<bool>,
    #[serde(alias = "doNotTrack")]
    pub do_not_track: Option<String>,
    pub language: Option<String>,
    pub languages: Option<Vec<String>>,
    pub oscpu: Option<String>,
    #[serde(alias = "pdfViewerEnabled")]
    pub pdf_viewer_enabled: Option<bool>,
    pub platform: Option<String>,
    pub product: Option<String>,
    #[serde(alias = "productSub")]
    pub product_sub: Option<String>,
    #[serde(alias = "userAgent")]
    pub user_agent: Option<String>,
    pub vendor: Option<String>,
    #[serde(alias = "vendorSub")]
    pub vendor_sub: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsProfileScreen {
    pub width: Option<i32>,
    pub height: Option<i32>,
    #[serde(alias = "availWidth")]
    pub avail_width: Option<i32>,
    #[serde(alias = "availHeight")]
    pub avail_height: Option<i32>,
    #[serde(alias = "availLeft")]
    pub avail_left: Option<i32>,
    pub left: Option<i32>,
    #[serde(alias = "availTop")]
    pub avail_top: Option<i32>,
    pub top: Option<i32>,
    #[serde(alias = "colorDepth")]
    pub color_depth: Option<i32>,
    #[serde(alias = "pixelDepth")]
    pub pixel_depth: Option<i32>,
    #[serde(rename = "type")]
    pub screen_type: Option<String>,
    #[serde(alias = "mozOrientation")]
    pub moz_orientation: Option<String>,
    #[serde(alias = "mozBrightness")]
    pub moz_brightness: Option<f32>,
    #[serde(alias = "lockOrientation")]
    pub lock_orientation: Option<String>,
    #[serde(alias = "unlockOrientation")]
    pub unlock_orientation: Option<String>,
}
