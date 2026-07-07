# Backend setup guide

This folder contains a simple Express backend that connects to a PostgreSQL database and handles user login requests.

## Files in this folder

- `index.js` – The main server file. It starts the Express app, connects to PostgreSQL, and defines the `/api/login` endpoint.
- `.env` – Stores secret environment values such as the database connection string. Do not commit this file to GitHub.
- `.gitignore` – Tells Git to ignore `node_modules/` and `.env` so they are not uploaded.
- `package.json` – Lists the backend dependencies and scripts such as `npm start`.
- `package-lock.json` – Automatically generated when you install packages. It locks the dependency versions.
- `node_modules/` – Created automatically after installing dependencies. This folder contains the installed packages.

## What this backend does

When a frontend app sends a login request, the backend:

1. Receives the email and password from the request body.
2. Looks up the user in the `users` table in PostgreSQL.
3. Checks whether the password matches the stored hashed password.
4. Returns a success or failure message.

## How to run it

1. Open a terminal in this folder.
2. Run `npm install`.
3. Run `npm start`.
4. The server will listen on port `5000` by default.

## Example login request

Send a `POST` request to `/api/login` with JSON like this:

```json
{
  "email": "user@example.com",
  "password": "your-password"
}
```

## Important database note

Your PostgreSQL table should include at least these fields in the `users` table:

- `email`
- `password_hash`
- `full_name`

The backend expects the password to be stored as a bcrypt hash.
