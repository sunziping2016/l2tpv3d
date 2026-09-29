use std::{net::Ipv4Addr, path::PathBuf};

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
pub struct RouterId(Ipv4Addr);

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PseudowireType {
    Ethernet,
    EthernetVlan,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// L2TPv3 configuration.
    pub l2tp: L2tpConfig,

    /// Listeners to accept incoming control connections.
    #[serde(default)]
    pub listen: Vec<ListenerConfig>,

    /// Connectors to initiate outgoing control connections.
    #[serde(default)]
    pub connect: Vec<ConnectorConfig>,

    /// Peers configuration.
    pub peer: Vec<PeerConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct L2tpConfig {
    /// Hostname of the L2TPv3 endpoint.
    #[serde(default)]
    pub hostname: String,

    /// Router ID of the L2TPv3 endpoint.
    pub router_id: RouterId,

    /// Pseudowire types advertised in SCCRQ/SCCRP.
    #[serde(default)]
    pub pseudowire_types: Option<Vec<PseudowireType>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Ip,
    Udp,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ListenerConfig {
    /// Tag of the listener
    #[serde(default)]
    pub tag: Option<String>,

    pub transport: Transport,

    #[serde(default)]
    pub local_address: Option<String>,

    #[serde(default)]
    pub interface: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ConnectorConfig {
    /// Tag of the connector
    #[serde(default)]
    pub tag: Option<String>,

    pub transport: Transport,

    /// The local address to bind to.
    #[serde(default)]
    pub local_address: Option<String>,

    /// The remote address to connect to.
    pub remote_address: String,

    /// Specify the expect remote Router ID for tie-breaking.
    #[serde(default)]
    pub remote_router_id: Option<RouterId>,

    #[serde(default)]
    pub interface: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PeerConfig {
    pub r#match: Vec<PeerMatchConfig>,
    pub session: Vec<SessionConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AuthenticationConfig {
    /// Mode of the authentication. Defaults to `required`.
    #[serde(default)]
    pub mode: AuthenticationMode,

    /// File containing the password.
    #[serde(default)]
    pub password_file: PathBuf,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticationMode {
    Optional,
    Required,
}

impl Default for AuthenticationMode {
    fn default() -> Self {
        AuthenticationMode::Required
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PeerMatchConfig {
    /// Match by hostname.
    #[serde(default)]
    pub hostname: Option<OneOrMany<String>>,

    /// Match by hostname regex.
    #[serde(default)]
    pub hostname_regex: Option<String>,

    /// Match by router ID.
    #[serde(default)]
    pub router_id: Option<OneOrMany<RouterId>>,

    /// Match by listener or connector tag.
    #[serde(default)]
    pub tag: Option<OneOrMany<String>>,

    /// Match by remote IP.
    #[serde(default)]
    pub remote_ip: Option<OneOrMany<IpNet>>,

    /// Authentication configuration.
    ///
    /// When unspecified, Control Message Authentication is disabled.
    #[serde(default)]
    pub authentication: Option<AuthenticationConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SessionConfig {
    pub name: String,

    #[serde(default)]
    pub pseudowire_type: Option<PseudowireType>,

    #[serde(default)]
    pub sequencing: Sequencing,

    pub script: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Sequencing {
    All,
    None,
}

impl Default for Sequencing {
    fn default() -> Self {
        Sequencing::None
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, JsonSchema)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}
