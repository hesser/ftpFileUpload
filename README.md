# Flask Audio FTP API

A secure RESTful API for capturing WAV audio files and uploading them to an FTP server, built with Flask and protected by OAuth 2.0 Client Credentials authentication.

## Features

- **Secure authentication** using OAuth 2.0 Client Credentials grant
- **Role-based access control** with admin and client roles
- **FTP integration** for reliable file storage
- **Token-based security** with access and refresh tokens
- **Client management** API for creating and managing API clients
- **Automatic credential generation** for easy setup

## Overview

This API allows client applications to securely upload WAV audio files to an FTP server. It uses the OAuth 2.0 Client Credentials grant type for authentication, which is ideal for server-to-server communication where a client application (not an end user) needs to access resources.

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)
- Access to an FTP server
- Basic knowledge of terminal/command line

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/flask-audio-ftp-api.git
   cd flask-audio-ftp-api
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install flask pyjwt werkzeug
   ```

4. Create uploads directory:
   ```bash
   mkdir uploads
   ```

5. Start the server:
   ```bash
   python app.py
   ```

6. **IMPORTANT**: When starting for the first time, the server will display admin credentials in the console. Save these credentials immediately as they will not be shown again.

7. Configure FTP settings by editing the generated `config.ini` file.

## Usage

### Authentication

To authenticate with the API, use the OAuth 2.0 Client Credentials flow:

```bash
curl -X POST \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET" \
  http://localhost:5000/api/oauth/token
```

This will return an access token and refresh token:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "access_token_expires_at": "2025-04-26T15:30:45"
}
```

### Uploading Files

Use the access token to upload WAV files:

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -F "audio_file=@/path/to/recording.wav" \
  http://localhost:5000/api/upload
```

### Using the Test Client

A Python test client is included for easy API interaction:

```bash
# Authenticate and upload a file
python test_client.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --file recording.wav

# Verify token
python test_client.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --verify

# For admin clients - list all clients
python test_client.py --client-id ADMIN_CLIENT_ID --client-secret ADMIN_CLIENT_SECRET --list-clients

# Create a new client (admin only)
python test_client.py --client-id ADMIN_CLIENT_ID --client-secret ADMIN_CLIENT_SECRET --create-client
```

## API Endpoints

### Authentication Endpoints

- **POST /api/oauth/token**: Get access token (client credentials grant)
- **POST /api/oauth/revoke**: Revoke a token
- **GET /api/token/verify**: Verify token validity

### File Upload Endpoint

- **POST /api/upload**: Upload a WAV file

### Client Management Endpoints (Admin only)

- **GET /api/clients**: List all API clients
- **POST /api/clients**: Create a new API client
- **DELETE /api/clients/{client_id}**: Delete an API client

### Other Endpoints

- **GET /api/health**: Health check endpoint
- **GET /api/config**: Get FTP configuration (authenticated)

## Security Features

- Secure OAuth 2.0 implementation
- Short-lived access tokens (1 hour by default)
- Longer-lived refresh tokens (7 days by default)
- Hashed storage of client secrets
- Role-based access control
- Token verification and revocation

## Configuration

The application uses a `config.ini` file for configuration, generated on first run:

```ini
[FTP]
host = ftp.example.com
port = 21
username = your_username
password = your_password
directory = /uploads

[API_CLIENTS]
client_12345abc = hashed_client_secret

[CLIENT_ROLES]
client_12345abc = admin
```

## Production Deployment

For production use:

1. Set a strong secret key:
   ```bash
   export SECRET_KEY=your-secure-random-key
   ```

2. Use a production WSGI server:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

3. Enable HTTPS:
   ```bash
   pip install pyopenssl
   ```
   
   And modify your app to use SSL:
   ```python
   app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')
   ```

4. Set up proper monitoring and logging

## Troubleshooting

### Common Issues

- **Authentication failures**: Verify client ID and secret
- **Permission issues**: Check client role (admin/client)
- **FTP errors**: Verify FTP server configuration
- **Token errors**: Check token expiration

### Lost Admin Credentials

If admin credentials are lost:
1. Delete `config.ini`
2. Restart the application
3. Save the newly generated credentials

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
