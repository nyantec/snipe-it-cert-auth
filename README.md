## X.509 Client Certificate Authentication for GitLab FOSS

Configure our reverse proxy to forward requests to `/cert-auth/` to `http://127.0.0.1:8123/`, and add the X-SSL-Client-Dn header. With nginx your configuration might look like this:

```
...
		ssl_client_certificate CA.pem;
		ssl_verify_client on;
		ssl_verify_depth 1;

		location /cert-auth/ {
			proxy_pass http://127.0.0.1:8123/;
			proxy_set_header X-SSL-Client-Dn $ssl_client_s_dn;
		}
...
```

Then, adjust the omniauth options in your `gitlab.yml`:
```
...
    "omniauth": {
      "allow_single_sign_on": [
        "jwt"
      ],
      "auto_sign_in_with_provider": "jwt",
      "block_auto_created_users": false,
      "enabled": true,
      "providers": [
        {
          "args": {
            "algorithm": "HS256",
            "auth_url": "/cert-auth/",
            "info_maps": {
              "email": "email",
              "name": "name"
            },
            "required_claims": [
              "name",
              "email"
            ],
            "secret": "xxx",
            "uid_claim": "email",
            "valid_within": 3600
          },
          "name": "jwt"
        }
      ]
    },
...
```
