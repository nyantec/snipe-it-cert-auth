use serde_derive::{Deserialize, Serialize};

/// Return value of GET `/users`.
/// Some entries not relevant to this application are omitted.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct User {
    pub(crate) username: String,
    pub(crate) first_name: String,
    pub(crate) last_name: String,
    pub(crate) email: String,
    pub(crate) activated: bool,
    #[serde(skip_deserializing)]
    pub(crate) password: String,
    #[serde(skip_deserializing)]
    pub(crate) password_confirmation: String,
}

/// Return value of GET `/users`
#[derive(Deserialize, Debug)]
pub(crate) struct Users {
    /// Number of results in the response
    pub(crate) total: i32,
    /// The returned users
    pub(crate) rows: Vec<User>,
}

/// Return value of POST `/users`
#[derive(Deserialize, Debug)]
pub(crate) struct PostUsersResponse {
    status: String,
    messages: String,
    payload: User,
}

pub(super) struct SnipeItClient {
    /// An instance of a reqwest HTTP client.
    pub(super) client: reqwest::Client,
    /// URL of the Snipe-IT REST API.
    pub(super) api_url: String,
    /// Access Token for the Snipe-IT REST API.
    pub(super) api_token: String,
}

impl SnipeItClient {
    pub(super) fn contains_username(&self, username: &str, users: &Vec<User>) -> bool {
        users.iter().any(|x| x.username.eq(username))
    }

    /// Performs a GET request on `/users`
    pub(super) async fn get_users(&self) -> crate::Result<Vec<User>> {
        let endpoint = format!("{}{}", self.api_url, "/users");
        let mut response = self
            .client
            .get(&endpoint)
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        let body = response.text().await?;
        println!("{}", body);

        response = self
            .client
            .get(&endpoint)
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        let users = response.json::<Users>().await?;
        Ok(users.rows)
    }

    /// Creates a POST request to `/users` to create a new user in Snipe-IT
    pub(super) async fn post_users(&self, user: &User) -> crate::Result<PostUsersResponse> {
        let endpoint = format!("{}{}", self.api_url, "/users");
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(&self.api_token)
            .json(&user)
            .send()
            .await?;

        Ok(response.json::<PostUsersResponse>().await?)
    }
}
