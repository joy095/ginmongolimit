# ginmongolimiter

A **highly-configurable rate limiting middleware** for [Gin](https://github.com/gin-gonic/gin) using **MongoDB** as persistent storage with optional **in-memory caching**. It supports single and multiple rate limits per route with TTL-based auto-cleanup.

---

## 🔧 Features

- 📦 MongoDB as persistent backend
- ⚡ In-memory cache (optional) for speed
- 🔁 TTL cleanup of expired keys
- 🔑 Custom key generators (IP, user ID, headers, etc.)
- 🧩 Combine multiple rate rules per route (`"5-1m"`, `"30-1h"`, etc.)
- 🧪 Easy debug mode + detailed headers
- 📤 Global registry for graceful shutdown

---

## 📦 Installation

```bash
go get github.com/joy095/mongolimiter
```
