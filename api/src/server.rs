use serde::{Deserialize, Serialize};

use axum::{
    debug_handler, extract::State, http::StatusCode, response::IntoResponse, routing::post, Json,
    Router,
};

use std::net::SocketAddr;
use tokio::{net::TcpListener, sync::mpsc::Sender};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{debug, info};

use web3::signing::recover;

use crate::eff_ecdsa_input::hash_msg;
use crate::user::UserProfile;

pub type Signature = String;

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiError {
    code: ApiErrorCode,
    message: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct ApiResult {
    errors: Vec<ApiError>,
}
impl Default for ApiResult {
    fn default() -> Self {
        Self { errors: vec![] }
    }
}

impl Into<ApiResult> for ApiErrorCode {
    fn into(self) -> ApiResult {
        ApiResult {
            errors: vec![ApiError {
                code: self.clone(),
                message: self.message().to_string(),
            }],
        }
    }
}

impl IntoResponse for ApiResult {
    fn into_response(self) -> axum::response::Response {
        serde_json::to_string(&self).unwrap().into_response()
    }
}

pub async fn run_server(port: u16, tx: Sender<SignedUserProfileUpdate>) {
    let app = Router::new()
        .route("/profile_update", post(handle_post_signed_message))
        .with_state(tx)
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener = TcpListener::bind(addr).await.unwrap();

    debug!("Listening on {}", addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[derive(Debug, Clone, Deserialize, Serialize)]
enum ApiErrorCode {
    InvalidSig,
    SignatureNotDeser,
}
impl ApiErrorCode {
    fn message(&self) -> &'static str {
        match self {
            ApiErrorCode::InvalidSig => "Invalid signature",
            ApiErrorCode::SignatureNotDeser => "Signature is not deserializable",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserProfileUpdate {
    pub timestamp_ms: u64,
    pub parsed_profile: UserProfile,
    pub unparsed_profile: String,
}
impl TryFrom<&str> for UserProfileUpdate {
    type Error = &'static str;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut parts = value.splitn(2, ", ");
        // get UserProfile from parts
        let timestamp_ms = parts
            .next()
            .ok_or("missing timestamp")?
            .to_string()
            .parse::<u64>()
            .or(Err("timestamp is not a number"))?;
        let profile = parts.next().ok_or("missing profile")?.try_into()?;
        Ok(UserProfileUpdate {
            timestamp_ms,
            parsed_profile: profile,
            unparsed_profile: value.to_owned(),
        })
    }
}
impl Default for UserProfileUpdate {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            parsed_profile: UserProfile {
                wallet_address: "".to_string(),
                first_name: "".to_string(),
                last_name: "".to_string(),
                email_address: None,
            },
            unparsed_profile: "".to_string(),
        }
    }
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedUserProfileUpdate {
    pub user_signature: String,
    pub profile_update: UserProfileUpdate,
}
impl Default for SignedUserProfileUpdate {
    fn default() -> Self {
        Self {
            user_signature: "".to_string(),
            profile_update: UserProfileUpdate {
                timestamp_ms: 0,
                parsed_profile: UserProfile {
                    wallet_address: "".to_string(),
                    first_name: "".to_string(),
                    last_name: "".to_string(),
                    email_address: None,
                },
                unparsed_profile: "".to_string(),
            },
        }
    }
}
impl SignedUserProfileUpdate {
    pub fn timestamp_ms(&self) -> u64 {
        self.profile_update.timestamp_ms
    }
    pub fn eth_address(&self) -> String {
        self.profile_update.parsed_profile.wallet_address.clone()
    }
    pub fn from_profile_update(profile_update: UserProfileUpdate, user_signature: String) -> Self {
        Self {
            user_signature,
            profile_update,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ApiSignedMessage {
    message: String, // UTF-8 encoded message "1702548662, 0x71C7656EC7ab88b098defB751B7401B5f6d8976F, Nick, Zakirov, nikolay.zakirov@terminal3.io"
    signature: String, // Signature of the message, "0x...."
}
impl ApiSignedMessage {
    fn get_signed_profile_update(&self) -> Result<SignedUserProfileUpdate, &'static str> {
        let update = self.message.as_str().try_into()?;
        Ok(SignedUserProfileUpdate {
            user_signature: self.signature.clone(),
            profile_update: update,
        })
    }
    fn get_checked_profile_update(&self) -> Result<SignedUserProfileUpdate, ApiErrorCode> {
        let message = &self.message;
        let signed_profile_update = self
            .get_signed_profile_update()
            .or(Err(ApiErrorCode::SignatureNotDeser))?;
        let signature = &self.signature;
        let address = signed_profile_update.eth_address();
        // let m_hash = hash_message(message).to_fixed_bytes();
        let m_hash = hash_msg(message.as_bytes());
        let decoded_sig = hex::decode(&signature[2..]).unwrap();
        let recovery_id = decoded_sig[64] as i32;
        // check that the signature is valid
        let recovered_address = recover(&m_hash, &decoded_sig[..64], recovery_id - 27).unwrap();
        debug!("Recovered address: {:?}", recovered_address);
        if "0x".to_owned() + &hex::encode(recovered_address) != address.to_lowercase() {
            return Err(ApiErrorCode::InvalidSig);
        }
        Ok(signed_profile_update)
    }
}

#[debug_handler]
async fn handle_post_signed_message(
    State(tx): State<Sender<SignedUserProfileUpdate>>,

    Json(payload): Json<ApiSignedMessage>,
) -> (StatusCode, ApiResult) {
    let profile_update = match payload.get_checked_profile_update() {
        Ok(u) => {
            debug!("Signature is valid");
            u
        }
        Err(e) => {
            info!("{:?}", e.message());
            return (StatusCode::BAD_REQUEST, e.into());
        }
    };
    debug!("Sending profile to proof system");
    tx.send(profile_update).await.unwrap();
    (StatusCode::OK, ApiResult::default())
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::Rng;
    use reqwest::StatusCode;
    use serde_json::json;
    use std::net::TcpListener;
    use tracing_test::traced_test;
    const MESSAGE: &str =
        "1703459910, 0x631438556b66c4908579Eab920dc162FF58958ea, Brad, Pitt, brad.pitt@gmail.com";
    const SIGNATURE: &str = "0x7c62b0e515eb044b731e244904d6efc7cb6dad49b061095b92c33443cb9bfa68f1a61d9f25c990e3c6fc94b280b181bfc77266eca37e77d123e0e67892ee5efc1b";

    #[test]
    fn deserialize_profile_update() {
        let profile_update: UserProfileUpdate =
            "10234345, 0x53e16f6d33c1809c14ba489a6917e9de849ab20c, tom, hanks"
                .try_into()
                .unwrap();
        assert_eq!(
            profile_update.parsed_profile.wallet_address,
            "0x53e16f6d33c1809c14ba489a6917e9de849ab20c"
        );
        assert_eq!(profile_update.parsed_profile.first_name, "tom");
        assert_eq!(profile_update.parsed_profile.last_name, "hanks");
    }
    #[test]
    fn test_get_profile_update() {
        let signed_message = json!({
            "message": MESSAGE,
            "signature": SIGNATURE,
        });
        let api_signed_message: ApiSignedMessage = serde_json::from_value(signed_message).unwrap();
        let profile_update = api_signed_message.get_signed_profile_update().unwrap();
        assert_eq!(profile_update.timestamp_ms(), 1703459910);
        assert_eq!(
            profile_update.profile_update.parsed_profile.first_name,
            "Brad"
        );
        assert_eq!(
            profile_update.profile_update.parsed_profile.last_name,
            "Pitt"
        );
        assert_eq!(
            profile_update
                .profile_update
                .parsed_profile
                .email_address
                .unwrap(),
            "brad.pitt@gmail.com"
        );
    }
    #[test]
    fn test_verify_signature() {
        // following signature was obtain with personal_sign method in metamask
        let address = &MESSAGE.to_string()[12..54];
        let mut m_hash = hash_msg(MESSAGE.as_bytes());
        let decoded_sig = hex::decode(&SIGNATURE[2..]).unwrap();
        let recovery_id = decoded_sig[64] as i32;
        // check that the signature is valid
        let recovered_address = recover(&m_hash, &decoded_sig[..64], recovery_id - 27).unwrap();
        assert_eq!(
            "0x".to_owned() + &hex::encode(recovered_address),
            address.to_lowercase()
        );
        // now check that a different hash would not produce the same address
        m_hash[0] += 1;
        let recovered_address = recover(&m_hash, &decoded_sig[..64], recovery_id - 27).unwrap();
        assert_ne!(
            "0x".to_owned() + &hex::encode(recovered_address),
            address.to_lowercase()
        );
    }
    #[tokio::test]
    #[traced_test]
    async fn test_post_profile() {
        let client = reqwest::Client::new();
        const PORT_FROM: u16 = 5000;
        const PORT_TO: u16 = 6000;
        // Generate a random port number
        let mut port: u16 = rand::thread_rng().gen_range(PORT_FROM..PORT_TO);

        // Check if the port is available
        // TODO: NikZak move to utils
        loop {
            match TcpListener::bind(("127.0.0.1", port)) {
                Ok(_) => break, // the port is available, exit the loop
                Err(_) => {
                    port = rand::thread_rng().gen_range(PORT_FROM..PORT_TO); // the port is not available, generate a new one
                }
            }
        }

        let profile_update: UserProfileUpdate = MESSAGE.try_into().unwrap();
        let signed_profile_update =
            SignedUserProfileUpdate::from_profile_update(profile_update, SIGNATURE.to_string());
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);

        // Start the server
        tokio::spawn(run_server(port, tx));

        // test ok response
        let signed_message = json!({
            "message": MESSAGE,
            "signature": SIGNATURE,
        });

        let server_response = client
            .post(format!("http://localhost:{port}/profile_update"))
            .json(&signed_message)
            .send()
            .await;
        assert_eq!(server_response.unwrap().status(), StatusCode::OK);
        assert_eq!(rx.recv().await.unwrap(), signed_profile_update);

        // test bad signature
        let wrong_signature_message = json!({
            "message": MESSAGE,
            "signature": SIGNATURE.to_string().replace('a', "1").as_str(),
        });
        let server_response = client
            .post(format!("http://localhost:{port}/profile_update"))
            .json(&wrong_signature_message)
            .send()
            .await;
        assert_eq!(server_response.unwrap().status(), StatusCode::BAD_REQUEST);

        // test bad message
        let wrong_message = json!({
            "message": "17000000, 0x1232134, wrong message",
            "signature": SIGNATURE,
        });
        let server_response = client
            .post(format!("http://localhost:{port}/profile_update"))
            .json(&wrong_message)
            .send()
            .await;
        assert_eq!(server_response.unwrap().status(), StatusCode::BAD_REQUEST);
    }
}
