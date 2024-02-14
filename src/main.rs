// Copyright 2024 Raphael Peters
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

mod sni;

use anyhow::{bail, Context, Result};
use argh::FromArgs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::io::{copy, AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::{join, spawn};
use tracing::{debug, error};

use crate::sni::extract_sni_from_header;

#[derive(FromArgs, Clone)]
/// Proxy TLS connections to another host by looking in the SNI header and searching the destination host by
/// looking the AAAA record of the SNI hostname up.
struct Opts {
    /// list of hostnames which are themself allowed and their subdomains are allowed
    #[argh(short = 'a', option)]
    allow_hostname: Vec<String>,

    /// port to listen to for TLS connections
    #[argh(short = 'p', option, default = "443")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let opts: Arc<Opts> = Arc::new(argh::from_env());

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, opts.port)).await?;

    loop {
        let (client_stream, addr) = listener.accept().await?;
        debug!(%addr, "accepted connection");
        let config = Arc::clone(&opts);
        spawn(async move {
            if let Err(error) = handle_client_connection(client_stream, config).await {
                error!(%error, "failed handling client connection");
            }
        });
    }
}

async fn handle_client_connection(mut client_stream: TcpStream, config: Arc<Opts>) -> Result<()> {
    let mut buffer = vec![0u8; 4096];
    let len = client_stream.read(&mut buffer).await.unwrap();
    buffer.truncate(len);

    let sni = {
        let (_, sni_opt) = extract_sni_from_header(&buffer)
            .map_err(|err| anyhow::Error::msg(err.to_string()))
            .context("failed parsing TLS header")?;
        sni_opt.context("TLS header does not contain SNI")?
    };

    if !config.allow_hostname.is_empty()
        && !config
            .allow_hostname
            .iter()
            .any(|entry| entry.as_str() == sni || sni.ends_with(&format!(".{entry}")))
    {
        bail!("SNI name {sni:?} is not found in host allowlist")
    }

    let addrs: Vec<_> = lookup_host(format!("{}:443", sni)).await.unwrap().collect();
    println!("{addrs:?}");
    let addr = addrs
        .iter()
        .filter_map(|addr| match addr {
            SocketAddr::V4(_) => None, // that's me!
            SocketAddr::V6(addr) => Some(addr),
        })
        .next()
        .with_context(|| format!("{sni} does not have a valid IPv6 address"))?;

    let mut server_stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("can't connect to {sni} on {addr}"))?;
    server_stream
        .write_all(&buffer)
        .await
        .context("failed transferring TLS header from client to server")?;

    let (mut server_read, mut server_write) = server_stream.split();
    let (mut client_read, mut client_write) = client_stream.split();

    join!(
        async move {
            // TODO splice/sendfile?
            if let Err(error) = copy(&mut client_read, &mut server_write).await {
                error!(%error, "failed transferring data from client to server");
            }
        },
        async move {
            // TODO splice/sendfile?
            if let Err(error) = copy(&mut server_read, &mut client_write).await {
                error!(%error, "failed transferring data from server to client");
            }
        }
    );

    Ok(())
}
