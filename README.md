# Caddy Bot Barrier Plugin

The **Bot Barrier** plugin for [Caddy](https://caddyserver.com) enforces a browser-based computational challenge before granting access to HTTP resources. It helps mitigate bot traffic while imposing minimal delays on legitimate users.

[![Go Report Card](https://goreportcard.com/badge/github.com/steffenbusch/caddy-bot-barrier)](https://goreportcard.com/report/github.com/steffenbusch/caddy-bot-barrier)

## Features

This plugin introduces a middleware that:

- **Mitigates Bot Traffic**: Requires clients to solve a computational challenge before proceeding.
- **Stateless Design**: Operates without server-side session storage.
- **Customizable Complexity**: Adjust the difficulty of the challenge to balance security and user experience.
- **Custom Templates**: Use your own HTML templates for the challenge page.

### Key Capabilities

- **Automatic Verification**: The challenge is solved automatically by the browser using JavaScript.
- **Time-Limited Challenges**: Challenges expire after a configurable duration to prevent replay attacks.
- **Cookie-Based Validation**: Uses cryptographically signed cookies to verify challenge solutions.

## Request Flow

1. **Initial Request (No Cookies)**
   Client sends an HTTP request → Middleware detects missing or invalid challenge cookies.

2. **Challenge Page**
   Server returns an HTML page containing embedded JavaScript and a cryptographically signed challenge (seed + HMAC).

3. **Client Solves Challenge**
   JavaScript computes a nonce so that:
   `SHA512(seed || nonce)`
   has at least `N` leading zero bits (`complexity`).

4. **Cookies Set by Client**
   Once solved, the client sets:
   - `__challenge_seed`: The original challenge (hex-encoded).
   - `__challenge_solution`: The found nonce (hex-encoded).
   - `__challenge_mac`: HMAC(seed, secret) to authenticate seed origin.

5. **Page Reloads Automatically**
   Browser reloads → Middleware now verifies all three cookies.

6. **Access Granted**
   If the solution is valid and timely, the request proceeds to the next handler.

## Configuration Options

- **`secret`**: The secret key used to generate and validate HMACs for the challenge seed.
  - Default: A random secret is generated during provisioning if not explicitly provided.
  - *Usage Tip*: Use a long, random string for better security.
  - **Caddy Placeholder Support**: Placeholders like `{file./path/to/secret.txt}` are supported, but only during initialization. The resolved value is used for the lifetime of the module.

- **`complexity`**: Defines the number of leading zero bits required in the hash (`SHA512(seed || nonce)`) for the challenge to be considered solved.
  - Default: `16`.
  - Higher values increase the difficulty of the challenge, making it harder for bots to solve quickly.
  - **Caddy Placeholder Support**: You can use placeholders like `{vars.bot_barrier_complexity}` to dynamically set the complexity for each HTTP request.

- **`valid_for`**: Specifies the duration for which a challenge seed is valid.
  - Default: `10m` (10 minutes).
  - After this duration, the client must solve a new challenge.

- **`seed_cookie_name`**: The name of the cookie that stores the challenge seed.
  - Default: `__challenge_seed`.

- **`solution_cookie_name`**: The name of the cookie that stores the solution (nonce) found by the client.
  - Default: `__challenge_solution`.

- **`mac_cookie_name`**: The name of the cookie that stores the HMAC of the challenge seed.
  - Default: `__challenge_mac`.

- **`template`**: Path to a custom HTML template for the challenge page.
  - Default: A built-in embedded template is used if no custom template is specified.

### Example Configuration (Caddyfile)

```caddyfile
:443 {
  handle {

    @private {
      remote_ip private_ranges
    }
    vars bot_barrier_complexity 18
    vars @private bot_barrier_complexity 14

    bot_barrier {
      secret "{file./path/to/secret.txt}"
      complexity {vars.bot_barrier_complexity}
      valid_for 15m
      template /path/to/custom_template.html
    }

    respond "Welcome!"
  }
}
```

## Complexity (`complexity`)

The `complexity` parameter defines the number of leading zero bits required in the hash (`SHA512(seed || nonce)`) for the challenge to be considered solved. This directly controls the difficulty of the computational challenge.

### Estimated Durations

| Complexity | Approx. Attempts | Est. Time (Desktop) |
|------------|------------------|---------------------|
| 12         | ~4,000           | <50 ms              |
| 14         | ~16,000          | 100–200 ms          |
| 16         | ~65,000          | 300–500 ms          |
| 17         | ~130,000         | 600–800 ms          |
| 18         | ~260,000         | 1–2 seconds         |
| 20         | ~1 million       | 5–10 seconds        |
| 22         | ~4 million       | 20–40 seconds       |

⚠️ **Note**: These estimates depend on the performance of the client device. Older or less powerful devices may take significantly longer.

## Time Validity (`valid_for`)

The `valid_for` configuration determines how long a seed is considered valid.

Example:

```caddyfile
bot_barrier {
  secret "mysecret"
  complexity 18
  valid_for 30m
}
```

## Content Security Policy (CSP) and Custom Templates

By default, the challenge page is served with a strict Content-Security-Policy (CSP) header that uses a random nonce for each request. The CSP header is:

```text
default-src 'none'; script-src 'nonce-<nonce>' 'unsafe-inline'; style-src 'self' 'nonce-<nonce>'; base-uri 'none'; object-src 'none';
```

The nonce is available in the template context as `.CSPNonce` and is added to the `<script>` and `<style>` tags in the built-in template.

**If you use a custom template**, you must ensure that all `<script>` and `<style>` tags include the nonce attribute, for example:

```html
<style nonce="{{ .CSPNonce }}"> ... </style>
<script nonce="{{ .CSPNonce }}"> ... </script>
```

This is required for the CSP to allow inline scripts and styles.

If you want to disable the CSP header entirely (for example, for development or advanced customization), you can use the `disable_csp_header` option in your Caddyfile configuration:

```caddyfile
bot_barrier {
    # ...other options...
    disable_csp_header
}
```

## Custom Templates

You can provide a custom HTML template for the challenge page using the `template` option. If not specified, a default embedded template is used.

### Example

```caddyfile
bot_barrier {
  template /path/to/custom_template.html
}
```

The template must include a placeholder for the embedded JavaScript and the CSP nonce:

```html
<script nonce="{{ .CSPNonce }}">{{ .Script }}</script>
```

If you use inline styles, also add the nonce:

```html
<style nonce="{{ .CSPNonce }}"> ... </style>
```

---

## Example Use Cases

### Example 1: Default Configuration

```caddyfile
:8080 {
  bot_barrier
  respond "Hello, human!"
}
```

### Example 2: Whitelisting Private IPs

```caddyfile
:8080 {

  @private {
   remote_ip private_ranges
  }

  vars bot_barrier_complexity 18
  vars @private bot_barrier_complexity 0

  bot_barrier {
     complexity {vars.bot_barrier_complexity}
     valid_for 60m
     template ./custom_challenge_template.html
  }

  respond "Access granted!"
}
```

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Caddy](https://caddyserver.com) for providing a powerful and extensible web server.
