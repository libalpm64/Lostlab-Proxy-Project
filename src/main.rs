use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use actix_web::{
    web, App, HttpRequest, HttpResponse, HttpServer, Responder, http::header,
    Error as ActixError,
};
use serde::{Deserialize, Serialize};
use rustls::{
    Certificate, PrivateKey, ServerConfig,
    sign::{any_supported_type, CertifiedKey},
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde_json;
use std::error::Error as StdError;

struct Logger;

impl Logger {
    fn log(message: &str) {
        let mut stdout = io::stdout();
        let _ = stdout.write_all(message.as_bytes());
        let _ = stdout.write_all(b"\n");
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct DomainSettings {
    backend: String,
    cloudflare_mode: bool,
    #[serde(default)]
    stage: Option<u8>,
    ssl_cert_path: String,
    ssl_key_path: String,
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
    domains: Vec<DomainEntry>,
    cookie_secret: String,
}

#[derive(Serialize, Deserialize)]
struct DomainEntry {
    domain: String,
    backend: String,
    cloudflare_mode: bool,
    stage: u8,
    ssl_cert_path: String,
    ssl_key_path: String,
}

struct AppState {
    domains: Mutex<Vec<(String, DomainSettings)>>,
    ip_requests: Mutex<Vec<IpRequestEntry>>, 
    cookie_secret: Vec<u8>,
    hash_cache: Mutex<Vec<Option<String>>>,
}

struct IpRequestEntry {
    ip: String,
    count: u64,
    last_seen: Instant,
}

const STAGE_THRESHOLD: u64 = 500;
const COOKIE_VALIDITY_DURATION: u64 = 3600;

#[derive(Debug)]
enum ProxyError {
    InvalidDomain,
    Blocked,
    Timeout,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::InvalidDomain => write!(f, "Invalid domain"),
            ProxyError::Blocked => write!(f, "Request blocked"),
            ProxyError::Timeout => write!(f, "Request timed out"),
        }
    }
}

impl StdError for ProxyError {}

async fn handle_request(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<Arc<AppState>>,
) -> actix_web::Result<impl Responder> {
    let host = match req.headers().get("host").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => return Ok(HttpResponse::BadRequest().body("Invalid domain")),
    };

    let mut domains = data.domains.lock().unwrap();
    let domain_settings = match domains.iter_mut().find(|(d, _)| d == host) {
        Some(settings) => &mut settings.1,
        None => return Ok(HttpResponse::BadRequest().body("Invalid domain")),
    };
    domain_settings.total_requests += 1;

    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("")
        .to_string();

    {
        let mut ip_requests = data.ip_requests.lock().unwrap();
        let mut found = false;
        for entry in ip_requests.iter_mut() {
            if entry.ip == ip {
                if entry.last_seen.elapsed() > Duration::from_secs(60) {
                    entry.count = 1;
                    entry.last_seen = Instant::now();
                } else {
                    entry.count += 1;
                }
                found = true;
                break;
            }
        }
        if !found {
            ip_requests.push(IpRequestEntry {
                ip: ip.clone(),
                count: 1,
                last_seen: Instant::now(),
            });
        }
    }

    if domain_settings
        .last_reset
        .map_or(true, |last_reset| last_reset.elapsed() >= Duration::from_secs(1))
    {
        if domain_settings.bypassed_requests >= STAGE_THRESHOLD {
            domain_settings.current_stage += 1;
            if domain_settings.current_stage > 2 {
                domain_settings.current_stage = 2;
            }
        }
        domain_settings.bypassed_requests = 0;
        domain_settings.last_reset = Some(Instant::now());
    }

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let challenge_cookie = {
        let cache_index = (current_time % 60) as usize;
        let mut cache = data.hash_cache.lock().unwrap();
        if cache.len() <= cache_index || cache[cache_index].is_none() {
            while cache.len() <= cache_index {
                cache.push(None);
            }
            cache[cache_index] = Some(hash_ip_with_timestamp(&ip, current_time, &data.cookie_secret));
        }
        cache[cache_index].as_ref().unwrap().clone()
    };

    let cookie_header = req
        .cookie("Lostlab")
        .map(|c| c.value().to_string())
        .unwrap_or_else(|| "".to_string());

    let cookie_valid = verify_challenge_cookie(&cookie_header, &ip, current_time, &data.cookie_secret, &data.hash_cache);

    if !cookie_valid {
        match domain_settings.current_stage {
            0 => {}
            1 => {
                let location = req.uri().to_string();

                let set_cookie = format!(
                    "Lostlab={}; SameSite=None; Secure",
                    challenge_cookie
                );

                return Ok(HttpResponse::Found()
                    .insert_header((header::LOCATION, location))
                    .insert_header((header::SET_COOKIE, set_cookie))
                    .finish());
            }
            2 => {
                let js_challenge = format!(
                    "<script>document.cookie = 'Lostlab={}; SameSite=None; Secure'; window.location.reload();</script>",
                    challenge_cookie
                );
                return Ok(HttpResponse::Ok()
                    .content_type("text/html")
                    .body(js_challenge));
            }
            _ => return Ok(HttpResponse::Forbidden().body("Request blocked")),
        }
    }

    domain_settings.bypassed_requests += 1;

    let backend_url = format!("http://{}", domain_settings.backend);
    let uri = req.uri().path_and_query().map(|x| x.as_str()).unwrap_or("");
    let target = format!("{}{}", backend_url, uri);

    let client = awc::Client::default();

    let forwarded_req = client
        .request_from(target.as_str(), req.head())
        .no_decompress();

    let mut response = match forwarded_req.send_body(body).await {
        Ok(resp) => resp,
        Err(_) => return Ok(HttpResponse::RequestTimeout().body("Request timed out")),
    };

    let mut client_resp = HttpResponse::build(response.status());
    for (header_name, header_value) in response.headers().iter() {
        client_resp.insert_header((header_name.clone(), header_value.clone()));
    }

    let body = response.body().await.unwrap_or_else(|_| web::Bytes::new());
    Ok(client_resp.body(body))
}

#[inline]
fn create_challenge_cookie(ip: &str, timestamp: u64, secret: &[u8]) -> String {
    let cookie_value = hash_ip_with_timestamp(ip, timestamp, secret);
    format!("Lostlab={}; SameSite=None; Secure", cookie_value)
}

#[inline]
fn verify_challenge_cookie(
    cookie_str: &str,
    _ip: &str,
    current_time: u64,
    secret: &[u8],
    cache: &Mutex<Vec<Option<String>>>,
) -> bool {
    if let Some(lostlab_cookie) = cookie_str
        .split(';')
        .find(|s| s.trim_start().starts_with("Lostlab="))
    {
        let hash = lostlab_cookie.trim_start_matches("Lostlab=");
        let interval = 60;
        let start_time = current_time.saturating_sub(COOKIE_VALIDITY_DURATION);
        let cache = cache.lock().unwrap();
        for t in (start_time..=current_time).step_by(interval as usize) {
            let cache_index = (t % 60) as usize;
            if let Some(ref cached_hash) = cache[cache_index] {
                if hash == cached_hash {
                    return true;
                }
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

fn parse_config(file_path: &str) -> io::Result<Config> {
    let file = File::open(file_path).map_err(|e| {
        eprintln!("Failed to open config file '{}': {}", file_path, e);
        e
    })?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| {
        eprintln!("Failed to parse config.json: {}", e);
        io::Error::new(io::ErrorKind::InvalidData, e)
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = parse_config("config.json")?;

    let mut server_configs = Vec::new();

    for domain_entry in &config.domains {
        let cert_file = &mut BufReader::new(File::open(&domain_entry.ssl_cert_path).map_err(|e| {
            eprintln!(
                "Failed to open certificate file '{}': {}",
                &domain_entry.ssl_cert_path, e
            );
            e
        })?);
        let key_file = &mut BufReader::new(File::open(&domain_entry.ssl_key_path).map_err(|e| {
            eprintln!(
                "Failed to open key file '{}': {}",
                &domain_entry.ssl_key_path, e
            );
            e
        })?);

        let cert_chain = certs(cert_file).map_err(|e| {
            eprintln!(
                "Failed to parse certificates from '{}': {}",
                &domain_entry.ssl_cert_path, e
            );
            io::Error::new(io::ErrorKind::InvalidData, "Invalid certificate")
        })?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

        let mut keys = pkcs8_private_keys(key_file).map_err(|e| {
            eprintln!(
                "Failed to parse private keys from '{}': {}",
                &domain_entry.ssl_key_path, e
            );
            io::Error::new(io::ErrorKind::InvalidData, "Invalid private key")
        })?;

        if keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("No private keys found in {}", &domain_entry.ssl_key_path),
            ));
        }

        let key = PrivateKey(keys.remove(0));

        let signing_key = any_supported_type(&key).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported private key format",
            )
        })?;

        let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

        server_configs.push((domain_entry.domain.clone(), certified_key));
    }

    let domains = {
        let mut domain_vec = Vec::new();
        for entry in &config.domains {
            let settings = DomainSettings {
                backend: entry.backend.clone(),
                cloudflare_mode: entry.cloudflare_mode,
                stage: Some(entry.stage),
                ssl_cert_path: entry.ssl_cert_path.clone(),
                ssl_key_path: entry.ssl_key_path.clone(),
                total_requests: 0,
                bypassed_requests: 0,
                last_reset: None,
                current_stage: entry.stage,
            };
            domain_vec.push((entry.domain.clone(), settings));
        }
        Mutex::new(domain_vec)
    };

    let ip_requests = Mutex::new(Vec::with_capacity(1024)); 

    let hash_cache = Mutex::new(vec![None; 60]);

    let state = Arc::new(AppState {
        domains,
        ip_requests,
        cookie_secret: config.cookie_secret.clone().into_bytes(),
        hash_cache,
    });

    let shared_state = web::Data::new(state.clone());

    Logger::log("Lostlab proxy is running on https://127.0.0.1:443");
    Logger::log("Configured domains:");
    {
        let domains = state.domains.lock().unwrap();
        for (domain, settings) in domains.iter() {
            let log_msg = format!(
                "  {} -> {} (Cloudflare mode: {}, Initial stage: {})",
                domain,
                settings.backend,
                settings.cloudflare_mode,
                settings.current_stage
            );
            Logger::log(&log_msg);
        }
    }

    let log_state = state.clone();
    actix_web::rt::spawn(async move {
        loop {
            actix_web::rt::time::sleep(Duration::from_secs(60)).await;
            let domains = log_state.domains.lock().unwrap();
            for (domain, settings) in domains.iter() {
                let log_msg = format!(
                    "{}: Total requests: {}, Bypassed requests: {}, Current stage: {}",
                    domain, settings.total_requests, settings.bypassed_requests, settings.current_stage
                );
                Logger::log(&log_msg);
            }
        }
    });

    let cert_resolver = Arc::new(ServerConfigResolver { configs: server_configs });
    let mut rustls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);

    rustls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    HttpServer::new(move || {
        App::new()
            .app_data(shared_state.clone())
            .default_service(web::to(handle_request))
    })
    .bind_rustls("127.0.0.1:443", rustls_config)?
    .run()
    .await?;

    Ok(())
}

struct ServerConfigResolver {
    configs: Vec<(String, Arc<CertifiedKey>)>,
}

impl rustls::server::ResolvesServerCert for ServerConfigResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        for (domain, certified_key) in &self.configs {
            if server_name == domain {
                return Some(certified_key.clone());
            }
        }
        self.configs.first().map(|(_, cert)| cert.clone())
    }
}
