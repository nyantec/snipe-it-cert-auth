#![feature(try_trait)]

use std::time::{SystemTime, UNIX_EPOCH};
use serde_derive::{Serialize};
use jsonwebtoken::{encode, Header, Key};
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::header;
use hyper::service::{make_service_fn, service_fn};
use custom_error::custom_error;
use std::env;


custom_error!{CustomError
	SystemTimeError{source: std::time::SystemTimeError} = "System time is before unix time",
	JWTError{source: jsonwebtoken::errors::Error} = "JWT Error: {source}",
	NoneError{e: std::option::NoneError} = @{ "NoneError" },
	ToStrError{source: header::ToStrError} = "Error converting header value to string: {source}",
	MissingField{name: String} = "Missing field: {name}",
	HttpError{source: hyper::http::Error} = "HttpError: {source}",
}

// NoneError doesn't implement std::error::Error, which breaks custom_error's automatic impl
impl From<(std::option::NoneError)> for CustomError {
	fn from(e: std::option::NoneError) -> Self {
		CustomError::NoneError{e}
	}
}

type Result<T> = std::result::Result<T, CustomError>;

#[derive(Debug, Serialize)]
struct Claims {
	email: String,
	name: String,
	exp: u64,
	iat: u64,
}


fn process_request(req: Request<Body>, jwt_secret: String) -> Result<Response<Body>> {
	let dn = req.headers().get("x-ssl-client-dn")?.to_str()?;
	let mut email = "";
	let mut name = "";
	for pair in dn.split(',') {
		let (key, val) = pair.split_at(pair.find('=')?);
		if key == "emailAddress" { email = val; }
		if key == "CN" { name = val; }
	}
	if email == "" { Err(CustomError::MissingField{name: "emailAddress".to_string()})? }
	if name == "" { Err(CustomError::MissingField{name: "CN".to_string()})? }

	let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let exp = iat + 3600;
	let my_claims = Claims{ email: email.to_string(), name: name.to_string(), exp: exp, iat: iat };
	let token = encode(&Header::default(), &my_claims, Key::Hmac(jwt_secret.as_str().as_ref()))?;

	Ok(Response::builder()
		.status(StatusCode::TEMPORARY_REDIRECT)
		.header(header::LOCATION, format!("/users/auth/jwt/callback?jwt={}", token))
		.body(Body::from("success"))?)
}


#[tokio::main]
async fn main() {
	let port = env::var("PORT").or(Ok::<String, ()>("8123".to_string())).unwrap().parse::<u16>().unwrap();
	let addr = ([127, 0, 0, 1], port).into();
	let jwt_secret = env::var("JWT_SECRET").expect("missing JWT_SECRET, exiting").to_string();

	let make_svc = make_service_fn(|_| {
		let jwt_secret = jwt_secret.clone();
		async move {
			Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
				let jwt_secret = jwt_secret.clone();
				async {
					Ok::<_, hyper::Error>(
						match process_request(req, jwt_secret) {
							Ok(resp) => resp,
							Err(e) => {
								println!("Error while processing request: {}", e);
								Response::builder()
									.status(StatusCode::INTERNAL_SERVER_ERROR)
									.body(Body::from("error")).unwrap() // error handling error
							},
						}
					)
				}
			}))
		}
	});

	let server = Server::bind(&addr)
		.serve(make_svc);

	println!("listening on port {}", port);

	if let Err(e) = server.await {
		eprintln!("server error: {}", e);
	}
}
