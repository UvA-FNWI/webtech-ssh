mod server;

use std::{
    collections::HashMap,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use ssh_key::{Algorithm, Certificate, PrivateKey, PublicKey};

use anyhow::{anyhow, bail};
use reqwest::StatusCode;

use serde::Deserialize;

use std::fs::OpenOptions;

use colored::*;

type HTTPClient = reqwest::Client;

const CERTIFICATE_REQ_URL: &str = "https://webtech-admin.datanose.nl/sign";
const USER_INFO_URL: &str = "https://webtech-admin.datanose.nl/user_info";
const HOST_CA_URL: &str = "https://webtech-admin.datanose.nl/host_ca";
const LOGIN_URL: &str = "https://webtech-admin.datanose.nl/login_api";
const CA_TRUSTED_DOMAINS: &str = "*.webtech-uva.nl";

const KEY_NAME: &str = "id_webtech";

#[derive(Deserialize)]
#[allow(dead_code)]
struct UserInfo {
    pub user_id: String,
    pub first_name: String,
    pub last_name: String,
    pub username: String,
    pub groups: Vec<String>,
}

/// Get the access token for the SSH-CA server
async fn get_token() -> anyhow::Result<String> {
    let (server_handle, mut recv_channel) = server::start_token_listener();

    println!(
        "{}",
        format!(
            "Please open the following URL in your browser to authenticate: {}",
            LOGIN_URL
        )
        .blue()
        .bold()
    );

    println!("{}", "Waiting to receive token...".dimmed());

    let token = recv_channel
        .recv()
        .await
        .ok_or(anyhow!("token sent on channel"))?;

    println!("{}", "Got token.".dimmed());

    // kill the server task once we have a token.
    server_handle.abort();

    Ok(token)
}

/// Generate a new Ed25519 SSH keypair.
///
/// The keypair is saved to the given path, with the public key
/// saved to <private_key_path>.pub.
fn generate_key(private_key_path: &Path) -> anyhow::Result<PrivateKey> {
    println!("{}", "Generating public/private SSH keypair...".dimmed());

    let mut private_key = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519)?;
    private_key.set_comment("webtech-ssh");

    let public_key = private_key.public_key();

    let public_key_path = private_key_path.with_extension("pub");

    private_key.write_openssh_file(private_key_path, ssh_key::LineEnding::LF)?;
    public_key.write_openssh_file(&public_key_path)?;

    Ok(private_key)
}

/// Get a user certificate for the given public key.
async fn get_user_certificate(
    client: &HTTPClient,
    token: &str,
    public_key: &PublicKey,
) -> anyhow::Result<Certificate> {
    println!("{}", "Requesting certificate for key...".dimmed());
    let mut body = HashMap::new();
    body.insert("public_key", public_key.to_openssh()?);

    let response = client
        .post(CERTIFICATE_REQ_URL)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;

    if response.status() == StatusCode::UNAUTHORIZED {
        bail!("Unauthorized; invalid token? Please try again.");
    }

    if response.status() != StatusCode::OK {
        bail!("Unable to request certificate; please try again.")
    }

    let text = response.text().await?;

    let cert = Certificate::from_openssh(&text)?;

    Ok(cert)
}

/// Get the public key for the host certificate authority
async fn get_host_ca_key(client: &HTTPClient, token: &str) -> anyhow::Result<PublicKey> {
    println!("{}", "Getting the host CA key...".dimmed());
    let response = client.get(HOST_CA_URL).bearer_auth(token).send().await?;

    if response.status() != StatusCode::OK {
        bail!("Unable to request host CA key; please try again.")
    }

    let text = response.text().await?;

    let key = PublicKey::from_openssh(&text)?;

    Ok(key)
}

async fn get_user_info(client: &HTTPClient, token: &str) -> anyhow::Result<UserInfo> {
    let response = client.get(USER_INFO_URL).bearer_auth(token).send().await?;

    if response.status() != StatusCode::OK {
        bail!("Unable to request user info; please try again.")
    }

    let info = response.json::<UserInfo>().await?;

    Ok(info)
}

/// Trust the host certificate authority by adding it to the known_hosts file.
fn trust_host_ca_key(home: &Path, ca_key: &PublicKey) -> anyhow::Result<()> {
    println!("{}", "Trusting host CA key...".dimmed());

    let ca_key_encoded = ca_key.to_openssh()?;
    let entry = format!(
        "\n@cert-authority {} {}",
        CA_TRUSTED_DOMAINS, ca_key_encoded
    );

    let known_hosts_path = home.join(".ssh").join("known_hosts");

    let mut known_hosts = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o644)
        .open(&known_hosts_path)?;

    let mut buf = String::new();
    known_hosts
        .read_to_string(&mut buf)
        .map_err(|_| anyhow!("known_hosts is not readable"))?;

    if buf.contains(&entry) {
        println!("{}", "Already trusted, skipping...".dimmed());
    } else {
        writeln!(known_hosts, "{}", entry)?;
    }

    Ok(())
}

/// Ensure the current user has an `~/.ssh` directory, with appropriate permissions.
fn ensure_ssh_dir(home: &Path) -> anyhow::Result<()> {
    println!(
        "{}",
        "Ensuring ~/.ssh exists and has the right permissions...".dimmed()
    );

    let ssh_dir = home.join(".ssh");

    std::fs::create_dir_all(&ssh_dir)?;
    std::fs::set_permissions(&ssh_dir, PermissionsExt::from_mode(0o700))?;

    Ok(())
}

/// Save the user certificate to `"{private_key_path}-cert.pub"`.
fn save_user_certificate(private_key_path: &Path, cert: &Certificate) -> anyhow::Result<()> {
    println!("{}", "Saving user certificate...".dimmed());

    let text = cert.to_openssh()?;

    let mut cert_path: PathBuf = private_key_path.into();
    cert_path.as_mut_os_string().push("-cert.pub");

    let mut cert_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(cert_path)?;

    writeln!(cert_file, "{}", text)?;

    Ok(())
}

/// Write a Match block to ~/.ssh/config that enables the webtech key
/// when connecting to *.webtech-uva.nl.
fn enable_webtech_key(home: &Path, key_path: &Path) -> anyhow::Result<()> {
    println!("{}", "Enabling key for webtech domains...".dimmed());

    let config_path = home.join(".ssh").join("config");

    let mut config = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .open(&config_path)?;

    let mut buf = String::new();
    config
        .read_to_string(&mut buf)
        .map_err(|_| anyhow!("ssh config is not readable"))?;

    let entry = format!(
        "\nMatch Host \"{}\"\n    IdentityFile {}",
        CA_TRUSTED_DOMAINS,
        key_path.to_str().ok_or(anyhow!("invalid utf-8 key path"))?
    );

    if buf.contains(&entry) {
        println!("{}", "Already enabled, skipping...".dimmed());
    } else {
        writeln!(config, "{}", entry)?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let home: PathBuf = std::env::var("HOME")?.into();
    let private_key_path = home.join(".ssh").join(KEY_NAME);

    ensure_ssh_dir(&home)?;

    let token = get_token().await?;

    let key = generate_key(&private_key_path)?;

    let client = HTTPClient::new();

    let cert = get_user_certificate(&client, &token, key.public_key()).await?;
    save_user_certificate(&private_key_path, &cert)?;

    enable_webtech_key(&home, &private_key_path)?;

    let host_ca = get_host_ca_key(&client, &token).await?;
    trust_host_ca_key(&home, &host_ca)?;

    let user_info = get_user_info(&client, &token).await?;

    let output: String;

    if user_info.groups.len() == 1 {
        output = format!(
            "\nDone! You are all set up to connect to your server.\n\
             Your username is {}; to connect to your server, run 'ssh {}@{}.webtech-uva.nl'.",
            user_info.username, user_info.username, user_info.groups[0]
        );
    } else {
        output = format!(
            "\nDone! You are all set up to connect to your servers.\n\
             Your username is {}; to connect to a server, run 'ssh {}@<group>.webtech-uva.nl', filling in the appropriate group name.\n\
             Your groups are: {}",
            user_info.username, user_info.username, user_info.groups.join(", ")
        );
    }
    println!("{}", output.green().bold());

    Ok(())
}
