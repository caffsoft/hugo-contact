# hugo-contact

This is a small, self-hosted Go application that acts as a (mostly) drop-in replacement for services like Formspree or Airform. It accepts form submissions from static sites (like Hugo) and sends them to a configured SMTP endpoint.

## Features

- Formspree-compatible POST endpoint (`/f/contact`)
- Honeypot spam protection
- CORS support
- Structured JSON logging using Go's `slog` package
- Environment-configurable SMTP (Zoho, Gmail, Mailgun, etc.)
- Optional redirect with `_next` field
- Lightweight and Docker-ready
- No external dependencies beyond Go's standard library
- A small, self-contained JavaScript script (required) to prevent spam-bots

## Environment Variables

| Variable            | Description                                                                                                                                 |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `SMTP_HOST`         | SMTP server host (e.g., `smtp.example.com`)                                                                                                 |
| `SMTP_PORT`         | SMTP port (usually `587`)                                                                                                                   |
| `SMTP_USERNAME`     | SMTP login username                                                                                                                         |
| `SMTP_PASSWORD`     | SMTP login password or app key                                                                                                              |
| `SMTP_SENDER`       | SMTP sender, may need to be different from SMTP_USERNAME for certain providers                                                              |
| `RECIPIENT_EMAIL`   | Email address to receive form submissions                                                                                                   |
| `PORT`              | Port to run the server on (default: `8080`)                                                                                                 |
| `CORS_ALLOW_ORIGIN` | CORS allowed origin (default: `*`)                                                                                                          |
| `TOKEN_SECRET`      | (optional) a token secret to use for signing the generated anti-spam token, if not supplied an ephemeral token will be generated on startup |

## Example HTML Form

Note that the script needs to be *only* on the pages that have forms and not loaded on the entire site, and should be loaded after the form.
This script will load a signed timestamp-based token that will need to be included in the form that needs to be included in the submission.
It expires in 15 minutes. This could create some false positives, for example, if a visitor went to the site and took more than 15 minutes to make their comment.  
The time range can be adjusted in the code, or you could warn them on the page that the form expires in 15 minutes.
It also doesn't allow it to be posted within 2 seconds, as that will most likely be a bot.   

```html
<form action="https://contact.yourdomain.com/f/contact" method="POST">
  <input type="text" name="name" required>
  <input type="email" name="email" required>
  <textarea name="message" required></textarea>
  <input type="text" name="_gotcha" style="display:none">
  <button type="submit">Send</button>
</form>
<script>
    const s = document.createElement('script');
    s.src = 'https://contact.yourdomain.com/form-token.js';
    s.defer = true;
    document.body.appendChild(s);
</script>
```

This will load the form, then load the script. The script will append the signed token to the form to include it with the submission.

## Building and Running Locally

```sh
go build -o hugo-contact .
./hugo-contact
```

## Running with Docker

```sh
docker build -t hugo-contact .

# Run it
SMTP_HOST=smtp.example.com \
SMTP_PORT=587 \
SMTP_USERNAME=your@domain.com \
SMTP_PASSWORD=yourpassword \
SMTP_USERNAME=your@other-domain.com \
RECIPIENT_EMAIL=you@domain.com \
PORT=8080 \
CORS_ALLOW_ORIGIN=https://yourhugo.site \
docker run -p 8080:8080 --env-file .env hugo-contact
```

## Building and Pushing to Docker Hub

```sh
docker build -t yourrepository/hugo-contact:latest .
docker push yourrepository/hugo-contact:latest
```

## License

MIT

---
Maintained by [Marc Lewis](https://marclewis.com) - [@gottafixthat](https://mstdn.social/@gottafixthat)
