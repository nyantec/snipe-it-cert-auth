//! # snipe-it-cert-auth
//!
//! This crate parses a given client certificate for a matching user in the Snipe-IT database and
//! creates a new user over the REST API if such a user does not exist yet.
use std::{env, sync::Arc};

use custom_error::custom_error;
use hyper::{
    Body,
    header,
    Request, Response, Server, service::{make_service_fn, service_fn}, StatusCode,
};
use rand::{distributions::Alphanumeric, Rng};
use x509_parser::pem::Pem;
use certificate_parser::CertificateParser;

use crate::snipe_it::{SnipeItClient, User};

mod certificate_parser;
mod snipe_it;

custom_error! {CustomError
    SystemTimeError{source: std::time::SystemTimeError} = "System time is before unix time",
    ToStrError{source: header::ToStrError} = "Error converting header value to string: {source}",
    MissingHeader = "Missing x-ssl-client-escaped-cert header",
    NoCertificate = "No certificate given",
    InvalidSAN = "SAN exists but could not be parsed",
    NoEmail = "Could not get email from certificate",
    NoCommonName = "Certificate has no Common Name",
    UrlEncoding{source: urlencoding::FromUrlEncodingError} = "Invalid urlencoding {source}",
    PEM{source: x509_parser::prelude::PEMError} = "Decoding cert: {source}",
    X509{source: x509_parser::prelude::X509Error} = "Decoding cert: {source}",
    Nom{source: x509_parser::nom::Err<x509_parser::prelude::X509Error>} = "Decoding cert: {source}",
    HttpError{source: hyper::http::Error} = "HttpError: {source}",
    Infallible{source: std::convert::Infallible} = "",
    Reqwest{source: reqwest::Error} = "Reqwest Error",
    HyperError{source: hyper::Error} = "Hyper Error",
}

pub(crate) type Result<T> = std::result::Result<T, CustomError>;

struct State {
    snipe_it_client: SnipeItClient,
    certificate_parser: CertificateParser,
}

impl State {
    fn new(api_url: String, api_token: String) -> Self {
        Self {
            snipe_it_client: SnipeItClient {
                client: Default::default(),
                api_url,
                api_token,
            },
            certificate_parser: CertificateParser {},
        }
    }

    /// Retrieves the username and other relevant values from the client certificate
    /// and checks whether a matching user exists in the Snipe-IT database.
    ///
    /// If such a user does not yet exist, it creates a new user via the Snipe-IT REST API.
    async fn process_request(&self, req: Request<Body>) -> crate::Result<Response<Body>> {
        let escaped_cert_str = req
            .headers()
            .get("x-ssl-client-escaped-cert")
            .ok_or(CustomError::MissingHeader)?
            .to_str()?;

        let cert_str = urlencoding::decode(escaped_cert_str)?;

        let cert_pem = Pem::iter_from_buffer(&cert_str.as_bytes())
            .next()
            .ok_or(CustomError::NoCertificate)??;

        let cert = cert_pem.parse_x509()?;

        let email = self
            .certificate_parser
            .get_email_from_san(&cert)
            .transpose()
            .or_else(|| self.certificate_parser.get_email_from_dn(&cert).transpose())
            .ok_or(CustomError::NoEmail)??;

        let name = cert
            .subject()
            .iter_common_name()
            .next()
            .map(|x| Ok::<_, CustomError>(x.as_str()?))
            .transpose()?
            .ok_or(CustomError::NoCommonName)?;

        let uid = self.certificate_parser.get_uid(&cert)?.unwrap_or(name);

        let users = self.snipe_it_client.get_users().await?;
        if !self.snipe_it_client.contains_username(uid, &users) {
            let password: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(64)
                .map(char::from)
                .collect();

            let user = User {
                username: uid.to_string(),
                first_name: name.split(" ").take(1).collect(),
                last_name: name.split(" ").skip(1).collect(),
                email: email.to_string(),
                activated: true,
                password: password.clone(),
                password_confirmation: password,
            };

            let _response = self.snipe_it_client.post_users(&user).await?;
        }

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("success"))?)
    }

    /// This function returns a HTTP response depending on the result of `process_request`.
    async fn handle(&self, req: Request<hyper::Body>) -> Result<Response<hyper::Body>> {
        match self.process_request(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                println!("Error while processing request: {}", e);
                Ok(
                    Response::builder()
                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(hyper::Body::from("error"))
                        .unwrap(), // error handling error
                )
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let port = env::var("PORT")
        .or(Ok::<String, ()>("8124".to_string()))
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let addr = ([127, 0, 0, 1], port).into();

    let api_url = env::var("API_URL").expect("missing API URL, exiting");
    let api_token = env::var("API_TOKEN")
        .expect("missing API_TOKEN, exiting")
        .to_string();

    let state = Arc::new(State::new(api_url, api_token));
    let make_svc = make_service_fn(|_conn| {
        let state = Arc::clone(&state);
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let state = Arc::clone(&state);
                async move { state.handle(req).await }
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("listening on port {}", port);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}
