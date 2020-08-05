use std::time::{SystemTime, UNIX_EPOCH};
use serde_derive::{Serialize};
use jsonwebtoken::{encode, Header, Key};
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::header;
use hyper::service::{make_service_fn, service_fn};
use futures_util::future::ok;
use custom_error::custom_error;
use std::env;

custom_error!{CustomError
       SystemTimeError{source: std::time::SystemTimeError} = "System time is before unix time",
       JWTError{source: jsonwebtoken::errors::Error} = "JWT Error: {source}",
       ToStrError{source: header::ToStrError} = "Error converting header value to string: {source}",
       MissingHeader{name: String} = "Missing header: {name}",
       MissingField{name: String} = "Missing field: {name}",
       HttpError{source: hyper::http::Error} = "HttpError: {source}",
       ParseError = "Error while parsing",
}

type Result<T> = std::result::Result<T, CustomError>;

#[derive(Debug, Serialize)]
struct Claims {
	email: String,
	name: String,
	uid: String,
	exp: u64,
	iat: u64,
}

fn process_request(req: Request<Body>) -> Result<Response<Body>> {
	let dn = req.headers().get("x-ssl-client-dn").ok_or(CustomError::MissingHeader{name: "x-ssl-client-dn".to_string()})?.to_str()?;
	let mut email = "";
	let mut name = "";
	let mut uid = "";
	for pair in dn.split(',') {
		let (key, _) = pair.split_at(pair.find('=').ok_or(CustomError::ParseError)?);
		let (_, val) = pair.split_at(pair.find('=').ok_or(CustomError::ParseError)? + 1);
		if key == "emailAddress" { email = val; }
		if key == "CN" { name = val; }
		if key == "UUID" { uid = val; }
	}
	if email == "" { Err(CustomError::MissingField{name: "emailAddress".to_string()})? }
	if name == "" { Err(CustomError::MissingField{name: "CN".to_string()})? }
	if uid == "" {
		uid = name;
	}

	let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let exp = iat + 3600;
	let my_claims = Claims{ email: email.to_string(), name: name.to_string(), uid: uid.to_string(), exp: exp, iat: iat };
	let jwt_secret = env::var("JWT_SECRET").unwrap().to_string();
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

    // check that JWT_SECRET is set so we can unwrap later
    env::var("JWT_SECRET").expect("missing JWT_SECRET, exiting").to_string();

	let make_svc = make_service_fn(|_| {
        ok::<_, hyper::Error>(service_fn(|req: Request<Body>| {
            ok::<_, hyper::Error>(
                match process_request(req) {
                    Ok(resp) => resp,
                    Err(e) => {
                        println!("Error while processing request: {}", e);
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Body::from("error")).unwrap() // error handling error
                    },
                }
            )
        }))
	});

	let server = Server::bind(&addr)
		.serve(make_svc);

	println!("listening on port {}", port);

	if let Err(e) = server.await {
		eprintln!("server error: {}", e);
	}
}
