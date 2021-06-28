use std::time::{SystemTime, UNIX_EPOCH};
use serde_derive::{Serialize};
use jsonwebtoken::{encode, Header, EncodingKey};
use hyper::{Body, Request, Response, Server, StatusCode};
use hyper::header;
use hyper::service::{make_service_fn, service_fn};
use futures_util::future::ok;
use custom_error::custom_error;
use std::env;
use der_parser::oid;
use x509_parser::pem::Pem;
use x509_parser::prelude::X509Certificate;
use x509_parser::extensions::{ParsedExtension, GeneralName};

custom_error!{CustomError
       SystemTimeError{source: std::time::SystemTimeError} = "System time is before unix time",
       JWTError{source: jsonwebtoken::errors::Error} = "JWT Error: {source}",
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

fn get_email_from_san<'a>(cert: &'a X509Certificate) -> Result<Option<&'a str>> {
    cert.extensions().get(&oid!(2.5.29.17)).and_then(|r| {
        if let ParsedExtension::SubjectAlternativeName(san) = r.parsed_extension() {
            // We got the SAN, maybe it has an email
            san.general_names.iter().filter_map(|x| {
                if let GeneralName::RFC822Name(email) = x {
                    Some(Ok(email.to_owned()))
                } else {
                    None
                }
            }).next()
        } else {
            // This is supposed to be a SAN, but we can't parse it
            Some(Err(CustomError::InvalidSAN))
        }
    }).transpose().map(|x| x)
}

fn get_email_from_dn<'a>(cert: &'a X509Certificate) -> Result<Option<&'a str>> {
    cert.subject().iter_email().next()
        .map(|x| Ok(x.as_str()?))
        .transpose()
}

fn get_uid<'a>(cert: &'a X509Certificate) -> Result<Option<&'a str>> {
    cert.subject().iter_by_oid(&oid!(0.9.2342.19200300.100.1.1)).next()
        .map(|x| Ok(x.as_str()?))
        .transpose()
}

fn process_request(req: Request<Body>) -> Result<Response<Body>> {
	let escaped_cert_str = req.headers().get("x-ssl-client-escaped-cert")
        .ok_or(CustomError::MissingHeader)?.to_str()?;

    let cert_str = urlencoding::decode(escaped_cert_str)?;

    let cert_pem = Pem::iter_from_buffer(&cert_str.as_bytes()).next()
        .ok_or(CustomError::NoCertificate)??;

    let cert = cert_pem.parse_x509()?;

    let email = get_email_from_san(&cert).transpose()
        .or_else(|| get_email_from_dn(&cert).transpose())
        .ok_or(CustomError::NoEmail)??;


    let name = cert.subject().iter_common_name().next()
        .map(|x| Ok::<_, CustomError>(x.as_str()?))
        .transpose()?
        .ok_or(CustomError::NoCommonName)?;

	let uid = get_uid(&cert)?.unwrap_or(name);

	let iat = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let exp = iat + 3600;
	let my_claims = Claims{ email: email.to_string(), name: name.to_string(), uid: uid.to_string(), exp: exp, iat: iat };
	let jwt_secret = env::var("JWT_SECRET").unwrap().to_string();
	let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret(jwt_secret.as_str().as_ref()))?;

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
