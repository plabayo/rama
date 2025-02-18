use bytes::{Buf, BytesMut, Bytes};
use std::collections::HashMap;
use rama_http_types::{HeaderMap, Method, StatusCode, Version};

use crate::{Error, Result, IcapMessage, Method as IcapMethod, Version as IcapVersion, State, Encapsulated};

// Constants
const MAX_HEADERS: usize = 100;
const MAX_HEADER_NAME_LEN: usize = 100;
const MAX_HEADER_VALUE_LEN: usize = 4096;

/// ICAP 解碼器的狀態
#[derive(Debug, Clone, PartialEq)]
enum DecodeState {
    /// 初始狀態，準備解析起始行
    Initial,
    /// 解析頭部
    Headers,
    /// 解析消息體
    Body,
    /// 解析完成
    Done,
}

/// ICAP 解碼器
/// 
/// 負責將原始字節流解碼為 ICAP 消息。支持以下功能：
/// - 解析請求/響應行
/// - 解析頭部
/// - 解析消息體
/// - 處理分塊編碼
/// - 處理預覽
#[derive(Debug)]
pub(crate) struct Decoder {
    /// 當前解碼狀態
    state: DecodeState,
    /// 消息頭部
    headers: HeaderMap,
    /// Encapsulated 頭部解析結果
    encapsulated: HashMap<String, usize>,
    /// 請求方法
    method: Option<IcapMethod>,
    /// ICAP 版本
    version: Option<IcapVersion>,
    /// 狀態碼
    status_code: Option<u16>,
    /// 狀態文本
    status_text: Option<String>,
    /// 請求 URI
    uri: Option<String>,
    /// 消息體
    body: Option<Bytes>,
    /// 預覽大小
    preview_size: Option<usize>,
}

impl Decoder {
    /// 創建新的解碼器
    pub(crate) fn new() -> Self {
        Self {
            state: DecodeState::Initial,
            headers: HeaderMap::new(),
            encapsulated: HashMap::new(),
            method: None,
            version: None,
            status_code: None,
            status_text: None,
            uri: None,
            body: None,
            preview_size: None,
        }
    }

    /// 解碼 ICAP 消息
    /// 
    /// 從提供的緩衝區中解碼 ICAP 消息。如果消息不完整，返回 None；
    /// 如果解碼成功，返回解碼後的消息；如果出錯，返回錯誤。
    pub(crate) fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<IcapMessage>> {
        loop {
            match self.state {
                DecodeState::Initial => {
                    if let Some(line) = self.read_line(buf)? {
                        self.parse_start_line(&line)?;
                        self.state = DecodeState::Headers;
                    } else {
                        return Ok(None);
                    }
                }
                DecodeState::Headers => {
                    match self.parse_headers(buf)? {
                        true => self.state = DecodeState::Body,
                        false => return Ok(None),
                    }
                }
                DecodeState::Body => {
                    match self.parse_body(buf)? {
                        true => {
                            self.state = DecodeState::Done;
                            return Ok(Some(self.build_message()?));
                        }
                        false => return Ok(None),
                    }
                }
                DecodeState::Done => {
                    return Ok(None);
                }
            }
        }
    }

    // === 私有輔助方法 ===

    /// 解析起始行
    fn parse_start_line(&mut self, line: &[u8]) -> Result<()> {
        let line = String::from_utf8_lossy(line);
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() < 3 {
            return Err(Error::Protocol("invalid start line".into()));
        }

        if parts[0].starts_with("ICAP/") {
            self.parse_response_line(&parts)?;
        } else {
            self.parse_request_line(&parts)?;
        }

        Ok(())
    }

    /// 解析請求行
    fn parse_request_line(&mut self, parts: &[&str]) -> Result<()> {
        self.method = Some(IcapMethod::from_str(parts[0])?);
        self.uri = Some(parts[1].to_string());
        self.version = Some(self.parse_version(parts[2])?);
        Ok(())
    }

    /// 解析響應行
    fn parse_response_line(&mut self, parts: &[&str]) -> Result<()> {
        self.version = Some(self.parse_version(parts[0])?);
        self.status_code = Some(parts[1].parse().map_err(|_| Error::InvalidStatus)?);
        self.status_text = Some(parts[2..].join(" "));
        Ok(())
    }

    /// 解析版本號
    fn parse_version(&self, version: &str) -> Result<IcapVersion> {
        match version {
            "ICAP/1.0" => Ok(IcapVersion::V1_0),
            _ => Err(Error::InvalidVersion(version.to_string())),
        }
    }

    /// 解析頭部
    fn parse_headers(&mut self, buf: &mut BytesMut) -> Result<bool> {
        while let Some(line) = self.read_line(buf)? {
            if line.is_empty() {
                return Ok(true);
            }

            let (name, value) = self.parse_header(&line)?;
            self.process_header(name, value)?;
        }
        Ok(false)
    }

    /// 處理單個頭部
    fn process_header(&mut self, name: String, value: String) -> Result<()> {
        match name.as_str() {
            "Encapsulated" => {
                self.parse_encapsulated_header(&value)?;
            }
            "Preview" => {
                self.preview_size = Some(value.parse().map_err(|_| 
                    Error::InvalidFormat("invalid preview size".into()))?);
            }
            _ => {
                self.headers.insert(name, value.parse()
                    .map_err(|_| Error::InvalidHeaderValue)?);
            }
        }
        Ok(())
    }

    /// 解析頭部行
    fn parse_header(&self, line: &[u8]) -> Result<(String, String)> {
        let line = String::from_utf8_lossy(line);
        let mut parts = line.splitn(2, ':');
        
        let name = parts.next()
            .ok_or_else(|| Error::InvalidFormat("missing header name".into()))?;
        let value = parts.next()
            .ok_or_else(|| Error::InvalidFormat("missing header value".into()))?;
        
        Ok((name.trim().to_string(), value.trim().to_string()))
    }

    /// 解析 Encapsulated 頭部
    fn parse_encapsulated_header(&mut self, value: &str) -> Result<()> {
        for part in value.split(',') {
            let mut kv = part.trim().split('=');
            let key = kv.next()
                .ok_or_else(|| Error::InvalidEncapsulated("missing key".into()))?;
            let value = kv.next()
                .ok_or_else(|| Error::InvalidEncapsulated("missing value".into()))?;
            
            self.encapsulated.insert(
                key.trim().to_string(),
                value.trim().parse()
                    .map_err(|_| Error::InvalidEncapsulated("invalid offset".into()))?,
            );
        }
        Ok(())
    }

    /// 解析消息體
    fn parse_body(&mut self, buf: &mut BytesMut) -> Result<bool> {
        if self.encapsulated.contains_key("null-body") {
            return Ok(true);
        }

        if let Some(preview_size) = self.preview_size {
            return self.parse_preview_body(buf, preview_size);
        }

        if !buf.is_empty() {
            self.body = Some(buf.split().freeze());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 解析預覽消息體
    fn parse_preview_body(&mut self, buf: &mut BytesMut, preview_size: usize) -> Result<bool> {
        if buf.len() >= preview_size {
            self.body = Some(buf.split_to(preview_size).freeze());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 讀取一行
    fn read_line(&self, buf: &mut BytesMut) -> Result<Option<Vec<u8>>> {
        let mut pos = 0;
        while pos + 1 < buf.len() {
            if buf[pos] == b'\r' && buf[pos + 1] == b'\n' {
                let line = buf.split_to(pos).to_vec();
                buf.advance(2);
                return Ok(Some(line));
            }
            pos += 1;
        }
        Ok(None)
    }

    /// 構建 ICAP 消息
    fn build_message(&self) -> Result<IcapMessage> {
        let mut msg = if let Some(method) = &self.method {
            // 請求消息
            let mut msg = IcapMessage::new(method.clone(), self.version.clone().unwrap_or_default());
            if let Some(uri) = &self.uri {
                msg.set_uri(uri.parse().map_err(|_| Error::InvalidUri)?);
            }
            msg
        } else {
            // 響應消息
            let mut msg = IcapMessage::new_response(
                self.status_code.unwrap_or(200),
                self.status_text.clone().unwrap_or_else(|| "OK".to_string()),
                self.version.clone().unwrap_or_default(),
            );
            msg
        };

        // 設置頭部和消息體
        msg.headers = self.headers.clone();
        if let Some(body) = &self.body {
            msg.set_body(body.clone());
        }

        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_line() {
        let mut decoder = Decoder::new();
        let line = b"REQMOD icap://example.com/virus_scan ICAP/1.0";
        
        decoder.parse_start_line(line).unwrap();
        
        assert_eq!(decoder.method, Some(IcapMethod::REQMOD));
        assert_eq!(decoder.uri, Some("icap://example.com/virus_scan".to_string()));
        assert_eq!(decoder.version, Some(IcapVersion::V1_0));
    }

    #[test]
    fn test_parse_response_line() {
        let mut decoder = Decoder::new();
        let line = b"ICAP/1.0 200 OK";
        
        decoder.parse_start_line(line).unwrap();
        
        assert_eq!(decoder.version, Some(IcapVersion::V1_0));
        assert_eq!(decoder.status_code, Some(200));
        assert_eq!(decoder.status_text, Some("OK".to_string()));
    }

    #[test]
    fn test_parse_headers() {
        let mut decoder = Decoder::new();
        let mut buf = BytesMut::from(
            "Host: icap.example.org\r\n\
             Encapsulated: req-hdr=0, req-body=278\r\n\
             Preview: 1024\r\n\r\n"
        );
        
        assert!(decoder.parse_headers(&mut buf).unwrap());
        
        assert_eq!(decoder.headers.get("Host").unwrap(), "icap.example.org");
        assert_eq!(decoder.preview_size, Some(1024));
        assert_eq!(decoder.encapsulated.get("req-hdr"), Some(&0));
        assert_eq!(decoder.encapsulated.get("req-body"), Some(&278));
    }

    #[test]
    fn test_parse_body() {
        let mut decoder = Decoder::new();
        let body = b"Hello, World!";
        let mut buf = BytesMut::from(&body[..]);
        
        assert!(decoder.parse_body(&mut buf).unwrap());
        assert_eq!(decoder.body.as_ref().unwrap(), body);
    }

    #[test]
    fn test_parse_preview_body() {
        let mut decoder = Decoder::new();
        decoder.preview_size = Some(5);
        let mut buf = BytesMut::from("Hello, World!");
        
        assert!(decoder.parse_body(&mut buf).unwrap());
        assert_eq!(decoder.body.as_ref().unwrap(), b"Hello");
    }

    #[test]
    fn test_parse_error_cases() {
        let mut decoder = Decoder::new();
        
        // 無效的起始行
        assert!(decoder.parse_start_line(b"INVALID").is_err());
        
        // 無效的版本號
        assert!(decoder.parse_start_line(b"REQMOD icap://example.com ICAP/2.0").is_err());
        
        // 無效的頭部格式
        let mut buf = BytesMut::from("Invalid Header\r\n");
        assert!(decoder.parse_headers(&mut buf).is_err());
        
        // 無效的 Encapsulated 頭部
        assert!(decoder.parse_encapsulated_header("invalid").is_err());
    }
}
