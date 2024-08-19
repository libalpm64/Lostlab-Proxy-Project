// Copyright Libalpm 2024
// This code is protected under GNU License.

// - This is a simple reverse proxy with specific challenges based on difficulty stages.
// - There is no reason to add a POW but I have an implementation of it.
// - The goal of this project is to be as lightweight as possible!
// - If you like to contribute to the credits will be given!

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::fmt;
use std::error::Error as StdError;
use lazy_static::lazy_static;
use blake3;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use serde::{Deserialize, Serialize};
use dashmap::DashMap;
use tokio::time::timeout;

/* Start Global Variables */

#[derive(Clone, Serialize, Deserialize)]
struct DomainSettings {
    backend: String,
    cloudflare_mode: bool,
    #[serde(default)]
    stage: Option<u8>,
    #[serde(skip)]
    total_requests: u64,
    #[serde(skip)]
    bypassed_requests: u64,
    #[serde(skip)]
    last_reset: Option<Instant>,
    #[serde(skip)]
    current_stage: u8,
}

#[derive(Serialize, Deserialize)]
struct Config {
    domains: HashMap<String, DomainSettings>,
    cookie_secret: String,
}

struct AppState {
    domains: DashMap<String, DomainSettings>,
    ip_requests: DashMap<String, (u64, Instant)>,
    cookie_secret: Vec<u8>,
}

const STAGE_THRESHOLD: u64 = 500; // Number of requests before it goes to the next stage.
const COOKIE_VALIDITY_DURATION: u64 = 3600; // Cookie is validation in seconds.

/* End Global Variables */


lazy_static! {
    static ref STATE: Arc<AppState> = {
        let config: Config = serde_json::from_reader(BufReader::new(File::open("config.json").unwrap())).unwrap();

        let domains: DashMap<String, DomainSettings> = config.domains.into_iter().map(|(k, mut v)| {
            v.current_stage = v.stage.unwrap_or(0);
            v.last_reset = Some(Instant::now());
            (k, v)
        }).collect();

        Arc::new(AppState {
            domains,
            ip_requests: DashMap::new(),
            cookie_secret: config.cookie_secret.into_bytes(),
        })
    };
}

//* Start Custom Errors */ 

#[derive(Debug)]
enum ProxyError {
    Hyper(hyper::Error),
    Io(io::Error),
    InvalidDomain,
    Blocked,
    Timeout,
}


impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Hyper(e) => write!(f, "Hyper error: {}", e),
            ProxyError::Io(e) => write!(f, "I/O error: {}", e),
            ProxyError::InvalidDomain => write!(f, "Invalid domain"),
            ProxyError::Blocked => write!(f, "Request blocked"),
            ProxyError::Timeout => write!(f, "Request timed out"),
        }
    }
}

impl StdError for ProxyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ProxyError::Hyper(e) => Some(e),
            ProxyError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<hyper::Error> for ProxyError {
    fn from(err: hyper::Error) -> Self {
        ProxyError::Hyper(err)
    }
}

impl From<io::Error> for ProxyError {
    fn from(err: io::Error) -> Self {
        ProxyError::Io(err)
    }
}
//* End Custom Errors */ 

async fn handle_request(
    req: Request<Body>,
    state: Arc<AppState>,
    client: Client<hyper::client::HttpConnector>,
) -> Result<Response<Body>, ProxyError> {
    let domain = req.headers().get("host").and_then(|h| h.to_str().ok()).ok_or(ProxyError::InvalidDomain)?;
    
    let mut domain_settings = state.domains.get_mut(domain).ok_or(ProxyError::InvalidDomain)?;
    domain_settings.total_requests += 1;

    let ip = if domain_settings.cloudflare_mode {
        req.headers().get("CF-Connecting-IP").and_then(|h| h.to_str().ok()).unwrap_or("")
    } else {
        req.headers().get("x-forwarded-for").and_then(|h| h.to_str().ok()).unwrap_or("")
    };

    let mut ip_entry = state.ip_requests.entry(ip.to_string()).or_insert((0, Instant::now()));
    let (count, last_reset) = &mut *ip_entry;
    if last_reset.elapsed() > Duration::from_secs(60) {
        *count = 1;
        *last_reset = Instant::now();
    } else {
        *count += 1;
    }

    if domain_settings.last_reset.map_or(true, |last_reset| last_reset.elapsed() >= Duration::from_secs(1)) {
        if domain_settings.bypassed_requests >= STAGE_THRESHOLD {
            domain_settings.current_stage = (domain_settings.current_stage + 1).min(2);
        }
        domain_settings.bypassed_requests = 0;
        domain_settings.last_reset = Some(Instant::now());
    }

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let challenge_cookie = create_challenge_cookie(ip, current_time, &state.cookie_secret);

    let cookie_valid = req.headers().get("cookie")
        .and_then(|c| c.to_str().ok())
        .map_or(false, |cookie_str| {
            verify_challenge_cookie(cookie_str, ip, current_time, &state.cookie_secret)
        });

    if !cookie_valid {
        match domain_settings.current_stage {
            0 => {},
            1 => {
                return Ok(Response::builder()
                    .status(307)
                    .header("Set-Cookie", format!("{}; SameSite=None; Secure", challenge_cookie))
                    .header("Location", req.uri().to_string())
                    .body(Body::empty())
                    .unwrap());
            },
            2 => {
                let js_challenge = format!(
                    r#"<script>document.cookie = '{}; SameSite=None; Secure'; window.location.reload();</script>"#,
                    challenge_cookie
                );
                return Ok(Response::builder()
                    .header("Content-Type", "text/html")
                    .body(Body::from(js_challenge))
                    .unwrap());
            },
            _ => return Err(ProxyError::Blocked),
        }
    }

    domain_settings.bypassed_requests += 1;

    let (parts, body) = req.into_parts();
    let mut backend_req = Request::from_parts(parts, body);

    *backend_req.uri_mut() = format!("http://{}{}", domain_settings.backend, backend_req.uri().path_and_query().map_or("", |x| x.as_str())).parse().unwrap();

    // Wrap the client request in a timeout 
    // This was added because the idle timer causes problems which causes the backend host to lose connectivity assuming to be an issue with the handler, will do more testing later.

    match timeout(Duration::from_secs(30), client.request(backend_req)).await {
        Ok(result) => result.map_err(ProxyError::from),
        Err(_) => Err(ProxyError::Timeout),
    }

}

#[inline]
fn create_challenge_cookie(ip: &str, timestamp: u64, secret: &[u8]) -> String {
    let cookie_value = hash_ip_with_timestamp(ip, timestamp, secret);
    format!("Lostlab={}", cookie_value)
}

#[inline]
fn verify_challenge_cookie(cookie_str: &str, ip: &str, current_time: u64, secret: &[u8]) -> bool {
    if let Some(lostlab_cookie) = cookie_str.split(';').find(|s| s.trim().starts_with("Lostlab=")) {
        let hash = lostlab_cookie.trim_start_matches("Lostlab=");
        // Check all possible timestamps with current time ify in rust. 
        for t in (current_time - COOKIE_VALIDITY_DURATION)..=current_time {
            if hash == hash_ip_with_timestamp(ip, t, secret) {
                return true;
            }
        }
    }
    false
}

#[inline]
fn hash_ip_with_timestamp(ip: &str, timestamp: u64, secret: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ip.as_bytes());
    hasher.update(&timestamp.to_be_bytes());
    hasher.update(secret);
    hasher.finalize().to_hex().to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    let client = Client::builder()
        .pool_idle_timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(10)
        .build_http();
    
    let make_svc = make_service_fn(move |_conn| {
        let client = client.clone();
        async move {
            Ok::<_, ProxyError>(service_fn(move |req| {
                handle_request(req, STATE.clone(), client.clone())
            }))
        }
    });
    // Setting up the socket, looking for a better way to do this in Rust.
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let server = Server::builder(hyper::server::conn::AddrIncoming::bind(&addr)?)
        .http1_keepalive(true)
        .http1_half_close(true)
        .serve(make_svc);

    println!("Lostlab proxy is running on http://{}", addr);
    println!("Configured domains:");
    for entry in STATE.domains.iter() {
        let domain = entry.key();
        let settings = entry.value();
        println!("  {} -> {} (Cloudflare mode: {}, Initial stage: {})", 
                 domain, settings.backend, settings.cloudflare_mode, settings.current_stage);
    }

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            for entry in STATE.domains.iter() {
                let domain = entry.key();
                let settings = entry.value();
                println!(
                    "{}: Total requests: {}, Bypassed requests: {}, Current stage: {}",
                    domain, settings.total_requests, settings.bypassed_requests, settings.current_stage
                );
            }
        }
    });

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }

    Ok(())
}