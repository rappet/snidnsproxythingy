// Copyright 2024 Raphael Peters
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, IResult, SNIType, TlsExtension, TlsMessage,
    TlsMessageHandshake, TlsPlaintext,
};
use tracing::warn;

pub(crate) fn extract_sni_from_header(buffer: &[u8]) -> IResult<&[u8], Option<&str>> {
    let (rest, header) = parse_tls_plaintext(buffer)?;
    Ok((rest, extract_sni(header)))
}

fn extract_sni(header: TlsPlaintext) -> Option<&str> {
    for msg in &header.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) = &msg {
            if let Some((_rest, extensions)) =
                hello.ext.and_then(|ext| parse_tls_extensions(ext).ok())
            {
                for extension in extensions {
                    if let Some(extension) = extract_sni_from_extensions(extension) {
                        return Some(extension);
                    }
                }
            }
        }
    }

    None
}

fn extract_sni_from_extensions(extension: TlsExtension) -> Option<&str> {
    match extension {
        TlsExtension::SNI(sni) => {
            for (sni_type, sni_content) in sni {
                if sni_type == SNIType::HostName {
                    if let Ok(sni_content_str) = std::str::from_utf8(sni_content) {
                        return Some(sni_content_str);
                    }
                }
            }
            None
        }
        TlsExtension::EncryptedServerName { .. } => {
            warn!("got ESNI :(");
            None
        }
        _ => None,
    }
}
