# 🛡️ Secure Auth System – Express.js + JWT + MongoDB

A production-ready authentication and authorization system built with **Node.js**, **Express.js**, **JWT**, **MongoDB**, and **CSRF protection**. Built for modern frontend-backend setups with cookie-based auth and refresh token rotation.

---

## 🚀 Features

* 🔐 **JWT Access + Refresh Token Flow**
* 🤁 **Token Rotation with Session Tracking**
* 🧼 **HttpOnly Cookies + SameSite Protection**
* 🛡️ **Anti-CSRF Token Verification**
* 🔒 **Role-Based Route Protection**
* 📧 **Password Reset with Secure Tokens**
* ❌ **Logout with Session Invalidation**
* 📈 Designed for **cross-origin** frontend (Next.js/React/Vue)
* 🧃 **Rate Limiting** to Throttle Abuse and Brute-force Attacks

---

## 📁 Project Structure

```
/auth-backend
├── models/
│   └── User.js
├── routes/
│   └── auth.js
├── utils/
│   ├── jwt.js
│   └── cookies.js
├── .env
├── server.js
└── README.md
```

---

## 🧠 Tech Stack

| Tool       | Purpose                          |
| ---------- | -------------------------------- |
| Express.js | Web server                       |
| MongoDB    | Database                         |
| Mongoose   | ODM for MongoDB                  |
| JWT        | Token-based authentication       |
| Bcrypt     | Password hashing                 |
| CSRF Token | Custom Anti-CSRF via JWT         |
| Cookies    | HttpOnly, Secure session storage |
| dotenv     | Environment variable config      |

---

## ⚙️ API Endpoints

### 📂 Signup

**POST** `/auth/signup`

Registers a new user.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "strongpass",
  "role": "user"
}
```

**Response:**

```json
{
  "message": "User created",
  "user": { "email": "user@example.com", "role": "user" }
}
```

---

### 🔐 Login

**POST** `/auth/login`

Logs the user in and returns CSRF token. Sets `accessToken` and `refreshToken` as HttpOnly cookies.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "strongpass"
}
```

**Response:**

```json
{
  "antiCsrfToken": "<token>"
}
```

---

### 🔄 Refresh Token

**POST** `/auth/refresh`

Generates a new access + refresh token pair and CSRF token.

**Headers:**

```
X-CSRF-Token: <antiCsrfToken>
```

**Cookies:**

* refreshToken (automatically sent)

**Response:**

```json
{
  "antiCsrfToken": "<new-token>"
}
```

---

### 🔓 Logout

**POST** `/auth/logout`

Logs out the user by invalidating session and clearing cookies.

**Response:**

```json
{
  "message": "Logout successful"
}
```

---

### 📧 Request Password Reset

**POST** `/auth/request-reset`

Generates a secure reset token and logs reset link in console.

**Request Body:**

```json
{
  "email": "user@example.com"
}
```

**Response:**

```json
{
  "message": "If an account with that email exists, a reset link has been sent."
}
```

---

### 🔄 Reset Password

**POST** `/auth/reset-password`

Updates password if a valid reset token is provided.

**Request Body:**

```json
{
  "token": "<reset-token>",
  "newPassword": "newStrongPassword"
}
```

**Response:**

```json
{
  "message": "Password reset successful"
}
```

---

## 🛠️ Setup

1. Clone the repo:

```bash
git clone https://github.com/yourusername/auth-backend
cd auth-backend
npm install
```

2. Create a `.env` file:

```env
PORT=5000
MONGO_URI=mongodb://localhost:27017/auth-db
ACCESS_TOKEN_SECRET=your_access_secret
REFRESH_TOKEN_SECRET=your_refresh_secret
FRONTEND_ORIGIN=http://localhost:3000
```

3. Start the server:

```bash
npm run dev
```

---

## 🔮 Future Enhancements

* [ ] Email sending with Nodemailer
* [ ] Admin dashboard with RBAC UI
* [ ] Dockerfile + Deployment guide
* [ ] OAuth / Google login

---

## 👌 Author

Made with ❤️ by [https://github.com/Dhruvil316]

If you found this helpful, star the repo ⭐ and share it!
