use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use std::collections::HashMap;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

const PORT: u16 = 19234;

type TokenSender = mpsc::Sender<String>;
type TokenReceiver = mpsc::Receiver<String>;

/// Handle an HTTP request, hopefully containing the token as a query parameter.
/// If the request contains the token, send it on the channel.
async fn read_token(
    token_channel: &TokenSender,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, &'static str> {
    if req.method() != Method::GET {
        return Err("Invalid method (not GET)");
    }

    let params: HashMap<String, String> = req
        .uri()
        .query()
        .map(|v| {
            url::form_urlencoded::parse(v.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_else(HashMap::new);

    match params.get("token") {
        None => return Err("Missing token parameter"),
        Some(tok) => token_channel.send(tok.to_string()).await.unwrap(),
    };

    Ok(Response::new(Full::new(Bytes::from(
        "Successfully authenticated - you can close this tab and go back to your terminal.",
    ))))
}

async fn server_task(token_channel: TokenSender) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], PORT));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);

        let service = service_fn(|req| async { read_token(&token_channel, req).await });

        let _ = http1::Builder::new().serve_connection(io, service).await;
    }
}

pub fn start_token_listener() -> (JoinHandle<anyhow::Result<()>>, TokenReceiver) {
    // This could in theory be a oneshot channel, but that complicates things
    // in the server task. Specifically, the channel would have to be passed
    // back if the request does not contain a valid token, but that is messy.
    let (send, recv) = mpsc::channel::<String>(1);

    let jh = tokio::spawn(server_task(send));

    (jh, recv)
}
