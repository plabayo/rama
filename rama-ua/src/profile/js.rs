use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone)]
/// Javascript information for a user-agent which supports Javascript and Web APIs.
///
/// For now this profile collection only contains some WebAPI data as deemed
/// relevant enough for user-agent emulation especially in the context of information
/// that sometimes is required in request payloads or headers.
pub struct JsProfile {
    /// Source Information injected by fingerprinting service.
    pub source_info: Option<Arc<JsProfileSourceInfo>>,

    /// WebAPI data, if Web APIs are supported by the user-agent.
    ///
    /// Web APIs are the interfaces that allow JavaScript to interact with the browser environment.
    /// See [MDN Web API reference](https://developer.mozilla.org/en-US/docs/Web/API) for more information.
    pub web_apis: Option<Arc<JsProfileWebApis>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Source information injected by fingerprinting service.
pub struct JsProfileSourceInfo {
    /// Name of the device.
    #[serde(alias = "deviceName")]
    pub device_name: Option<String>,
    /// Name of the operating system.
    #[serde(alias = "os")]
    pub os: Option<String>,
    /// Version of the operating system.
    #[serde(alias = "osVersion")]
    pub os_version: Option<String>,
    /// Name of the browser.
    #[serde(alias = "browserName")]
    pub browser_name: Option<String>,
    /// Version of the browser.
    #[serde(alias = "browserVersion")]
    pub browser_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsProfileWebApis {
    /// Navigator information, if the user-agent supports the Navigator API.
    ///
    /// The Navigator API provides information about the user's browser and operating system.
    /// See [MDN Navigator API reference](https://developer.mozilla.org/en-US/docs/Web/API/Navigator) for more information.
    pub navigator: Option<JsProfileNavigator>,
    /// Screen information, if the user-agent supports the Screen API.
    ///
    /// The Screen API provides information about the user's screen.
    /// See [MDN Screen API reference](https://developer.mozilla.org/en-US/docs/Web/API/Screen) for more information.
    pub screen: Option<JsProfileScreen>,
}

impl<'de> Deserialize<'de> for JsProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let profile = JsProfileDeserialize::deserialize(deserializer)?;
        Ok(Self {
            source_info: profile.source_info.map(Arc::new),
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
            source_info: self.source_info.as_deref(),
            web_apis: self.web_apis.as_deref(),
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Serialize)]
struct JsProfileSerialize<'a> {
    source_info: Option<&'a JsProfileSourceInfo>,
    web_apis: Option<&'a JsProfileWebApis>,
}

#[derive(Debug, Deserialize)]
struct JsProfileDeserialize {
    pub source_info: Option<JsProfileSourceInfo>,
    pub web_apis: Option<JsProfileWebApis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Navigator information, if the user-agent supports the Navigator API.
///
/// The Navigator API provides information about the user's browser and operating system.
/// See [MDN Navigator API reference](https://developer.mozilla.org/en-US/docs/Web/API/Navigator) for more information.
///
/// ## Notes
///
/// The `window.navigator.appVersion`, `window.navigator.appName` and `window.navigator.userAgent` properties
/// have been used in "browser sniffing" code: scripts that attempt to find out what kind of browser you are using
/// and adjust pages accordingly. This lead to the current situation, where browsers had to return fake values from
/// these properties in order not to be locked out of some websites.
pub struct JsProfileNavigator {
    /// The code name of the application, often the fake value "Mozilla".
    #[serde(alias = "appCodeName")]
    pub app_code_name: Option<String>,
    /// The name of the application, often the fake value "Netscape".
    #[serde(alias = "appName")]
    pub app_name: Option<String>,
    /// Supposed to be the build identifier of the browser.
    /// In modern browsers this property now returns a fixed timestamp as a privacy measure, e.g. 20181001000000 in Firefox 64 onwards.
    #[serde(alias = "buildID")]
    pub build_id: Option<String>,
    /// Whether cookies are enabled.
    #[serde(alias = "cookieEnabled")]
    pub cookie_enabled: Option<bool>,
    /// Whether the user has opted out of tracking.
    #[serde(alias = "doNotTrack")]
    pub do_not_track: Option<String>,
    /// The primary language of the user's browser.
    pub language: Option<String>,
    /// The languages supported by the user's browser.
    pub languages: Option<Vec<String>>,
    /// The operating system of the user's browser.
    pub oscpu: Option<String>,
    /// Whether the PDF viewer is enabled.
    #[serde(alias = "pdfViewerEnabled")]
    pub pdf_viewer_enabled: Option<bool>,
    /// The platform of the user's browser.
    pub platform: Option<String>,
    /// The value of the Navigator.product property is always "Gecko", in any browser.
    /// This property is kept only for compatibility purposes.
    pub product: Option<String>,
    /// This is the sub-product of the user's browser, another fake value,
    /// it returns either the string "20030107", or the string "20100101".
    #[serde(alias = "productSub")]
    pub product_sub: Option<String>,
    /// The user agent of the user's browser.
    #[serde(alias = "userAgent")]
    pub user_agent: Option<String>,
    /// The vendor of the user's browser.
    ///
    /// The value of the Navigator vendor property is always either "Google Inc.", "Apple Computer, Inc.", or (in Firefox) the empty string.
    pub vendor: Option<String>,
    /// The value of the Navigator.vendorSub property is always the empty string, in any browser.
    #[serde(alias = "vendorSub")]
    pub vendor_sub: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Screen information, if the user-agent supports the Screen API.
///
/// The Screen API provides information about the user's screen.
/// See [MDN Screen API reference](https://developer.mozilla.org/en-US/docs/Web/API/Screen) for more information.
pub struct JsProfileScreen {
    /// The width of the screen.
    pub width: Option<i32>,
    /// The height of the screen.
    pub height: Option<i32>,
    /// The amount of horizontal space in pixels available to the window.
    #[serde(alias = "availWidth")]
    pub avail_width: Option<i32>,
    /// Specifies the height of the screen, in pixels, minus permanent or
    /// semipermanent user interface features displayed by the operating system, such as the Taskbar on Windows.
    #[serde(alias = "availHeight")]
    pub avail_height: Option<i32>,
    #[serde(alias = "availLeft")]
    /// A number representing the x-coordinate (left-hand edge) of the available screen area.
    pub avail_left: Option<i32>,
    /// A number representing the x-coordinate (left-hand edge) of the total screen area.
    pub left: Option<i32>,
    #[serde(alias = "availTop")]
    /// A number representing the y-coordinate (top edge) of the available screen area.
    pub avail_top: Option<i32>,
    /// A number representing the y-coordinate (top edge) of the total screen area.
    pub top: Option<i32>,
    /// The color depth of the screen.
    #[serde(alias = "colorDepth")]
    pub color_depth: Option<i32>,
    /// Gets the bit depth of the screen.
    #[serde(alias = "pixelDepth")]
    pub pixel_depth: Option<i32>,
    /// Usually not defined, is non-standard.
    #[serde(rename = "type")]
    pub screen_type: Option<String>,
    /// Firefox-specific orientation of the screen.
    #[serde(alias = "mozOrientation")]
    pub moz_orientation: Option<String>,
    /// Firefox-specific brightness of the screen.
    #[serde(alias = "mozBrightness")]
    pub moz_brightness: Option<f32>,
    /// Firefox-specific lock orientation of the screen.
    #[serde(alias = "lockOrientation")]
    pub lock_orientation: Option<String>,
    /// Firefox-specific unlock orientation of the screen.
    #[serde(alias = "unlockOrientation")]
    pub unlock_orientation: Option<String>,
}
