const express = require("express")
const http = require("http")
const socketIo = require("socket.io")
const cors = require("cors")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const multer = require("multer")
const cloudinary = require("cloudinary").v2
const dotenv = require("dotenv")
const { neonConfig, Pool } = require('@neondatabase/serverless')

dotenv.config()

// Configure Neon
neonConfig.fetchConnectionCache = true

// Create connection pool
const pool = new Pool({
  connectionString: process.env.NEON_DATABASE_URL
})

const app = express()
const server = http.createServer(app)
const io = socketIo(server, {
  cors: { origin: process.env.FRONTEND_URL || "http://localhost:3000" },
})

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))
app.use(express.json())

// Request/body logger - helps trace incoming requests and payloads
app.use((req, res, next) => {
  try {
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.url} - body: ${JSON.stringify(req.body)}`,
    )
  } catch (e) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - body: <unserializable>`)
  }
  next()
})

app.use(express.urlencoded({ extended: true }))

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
})

// Database
// Support either NEON_DATABASE_URL or DATABASE_URL for flexibility.
// Test database connection
;(async () => {
  try {
    const res = await pool.query('SELECT 1')
    console.log('[startup] DB connectivity test OK')
  } catch (e) {
    console.warn('[startup] DB connectivity test failed:', e && e.message ? e.message : e)
  }
})()

// Multer config for file uploads
const upload = multer({ storage: multer.memoryStorage() })

// JWT Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]
  if (!token) return res.status(401).json({ message: "No token provided" })

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.userId = decoded.id
    next()
  } catch (error) {
    res.status(401).json({ message: "Invalid token" })
  }
}

// Socket.io Auth
io.use((socket, next) => {
  const token = socket.handshake.auth.token
  if (!token) return next(new Error("No token"))

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    socket.userId = decoded.id
    socket.username = decoded.username
    next()
  } catch (error) {
    next(new Error("Invalid token"))
  }
})

// ============ REST API Routes ============

// Auth Routes
app.post("/api/auth/signup", async (req, res) => {
  console.log('[signup] Received signup request')
  try {
    const { username, email, password } = req.body || {}
    console.log('[signup] Parsed body:', { username, email, passwordPresent: !!password })

    if (!username || !email || !password) {
      console.warn('[signup] Missing required fields', { usernamePresent: !!username, emailPresent: !!email, passwordPresent: !!password })
      return res.status(400).json({ message: 'username, email and password are required' })
    }

    // Check for existing user
    console.log('[signup] Checking for existing user by email or username')
    try {
      let existing = await sql.query('SELECT id, username, email FROM users WHERE email = $1 OR username = $2', [email, username])
      if (!Array.isArray(existing) && existing && existing.rows) existing = existing.rows
      console.log('[signup] Existing user query result length:', Array.isArray(existing) ? existing.length : 'unknown')
      if (existing && existing.length > 0) {
        console.warn('[signup] User already exists', existing)
        return res.status(409).json({ message: 'User already exists' })
      }
    } catch (qErr) {
      console.error('[signup] Error querying existing user:', qErr && qErr.stack ? qErr.stack : qErr)
      return res.status(500).json({ message: 'Database error while checking existing user' })
    }

    // Hash password
    console.log('[signup] Hashing password')
    const hashedPassword = await bcrypt.hash(password, 10)
    console.log('[signup] Password hashed')

    // Insert new user
    console.log('[signup] Inserting new user into DB')
    try {
      let result = await sql.query(
        'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
        [username, email, hashedPassword],
      )
      if (result && result.rows) result = result.rows
      console.log('[signup] Insert result:', result && result[0])
      return res.status(201).json({ message: 'User created successfully', user: result[0] })
    } catch (insErr) {
      console.error('[signup] Error inserting user:', insErr && insErr.stack ? insErr.stack : insErr)
      // handle unique constraint race condition
      if (insErr && insErr.message && insErr.message.toLowerCase().includes('unique')) {
        return res.status(409).json({ message: 'User already exists (unique constraint)' })
      }
      return res.status(500).json({ message: 'Database error while creating user' })
    }
  } catch (error) {
    console.error('[signup] Unexpected error:', error && error.stack ? error.stack : error)
    return res.status(500).json({ message: 'Internal server error' })
  }
})

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body

    let users = await sql.query("SELECT * FROM users WHERE email = $1", [email])
    if (!Array.isArray(users) && users && users.rows) {
      // some clients return { rows }
      users = users.rows
    }
    if (users.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" })
    }

    const user = users[0]
    const isValidPassword = await bcrypt.compare(password, user.password)

    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid credentials" })
    }

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET)

    res.json({
      token,
      user: { id: user.id, username: user.username, email: user.email },
    })
  } catch (error) {
    res.status(500).json({ message: error.message })
  }
})

// User Routes
app.get("/api/users/search", verifyToken, async (req, res) => {
  try {
    const { query } = req.query
    let users = await sql.query(
      "SELECT id, username, email FROM users WHERE username ILIKE $1 OR email ILIKE $1 LIMIT 10",
      [`%${query}%`],
    )
    if (!Array.isArray(users) && users && users.rows) users = users.rows
    res.json(users)
  } catch (error) {
    res.status(500).json({ message: error.message })
  }
})

// Development-only: public search endpoint (no auth) to make testing easier.
// Only enabled when NODE_ENV !== 'production'. Remove or protect in production.
app.get("/api/users/search-open", async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ message: 'Forbidden in production' })
  }

  try {
    const { query } = req.query
    if (!query) return res.json([])
    let users = await sql.query(
      "SELECT id, username, email FROM users WHERE username ILIKE $1 OR email ILIKE $1 LIMIT 20",
      [`%${query}%`],
    )
    if (!Array.isArray(users) && users && users.rows) users = users.rows
    res.json(users)
  } catch (error) {
    console.error('[search-open] Error:', error && error.stack ? error.stack : error)
    res.status(500).json({ message: 'Search error' })
  }
})

// File Upload
const fileUploadHandler = async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file provided" })

    const uploadStream = cloudinary.uploader.upload_stream(
      {
        resource_type: "auto",
        folder: "chatflow",
        max_bytes: 104857600, // 100MB limit
      },
      (error, result) => {
        if (error) {
          console.error("Cloudinary error:", error)
          return res.status(500).json({ message: "Upload failed", error: error.message })
        }
        res.json({
          url: result.secure_url,
          publicId: result.public_id,
          type: result.resource_type,
        })
      },
    )

    uploadStream.end(req.file.buffer)
  } catch (error) {
    console.error("Upload error:", error)
    res.status(500).json({ message: error.message })
  }
}

app.post("/api/upload", verifyToken, upload.single("file"), fileUploadHandler)

// n8n Webhook
const triggerN8nWebhook = async (event, data) => {
  if (!process.env.N8N_WEBHOOK_URL) return

  try {
    await fetch(process.env.N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, data, timestamp: new Date().toISOString() }),
    })
  } catch (error) {
    console.error("Webhook error:", error)
  }
}

// ============ Socket.io Events ============

io.on("connection", (socket) => {
  console.log(`User connected: ${socket.userId}`)

  // Put each socket into a personal room so we can target user-specific events
  try {
    socket.join(`user_${socket.userId}`)
  } catch (e) {
    console.warn('[socket] Failed to join personal room:', e && e.message ? e.message : e)
  }

  // Join the socket to all existing conversation rooms for this user so they receive messages
  ;(async () => {
    try {
      let convs = await sql.query(`SELECT id FROM conversations WHERE user1_id = $1 OR user2_id = $1`, [socket.userId])
      if (!Array.isArray(convs) && convs && convs.rows) convs = convs.rows
      if (Array.isArray(convs)) {
        for (const c of convs) {
          try {
            socket.join(c.id)
          } catch (e) {
            console.warn('[socket] Failed to join conversation room', c.id, e && e.message ? e.message : e)
          }
        }
      }
    } catch (e) {
      console.warn('[socket] Error fetching user conversations for room join:', e && e.message ? e.message : e)
    }
  })()

  // Get user conversations
  socket.on("get_conversations", async (callback) => {
    try {
      let conversations = await sql.query(
        `SELECT c.id, u.id as participant_id, u.username as participantName, u.email as participantEmail, m.content as lastMessage, m.created_at as lastMessageAt
         FROM conversations c 
         JOIN users u ON (CASE WHEN c.user1_id = $1 THEN c.user2_id ELSE c.user1_id END) = u.id
         LEFT JOIN LATERAL (
           SELECT content, created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1
         ) m ON true
         WHERE c.user1_id = $1 OR c.user2_id = $1
         ORDER BY m.created_at DESC NULLS LAST`,
        [socket.userId],
      )
      if (!Array.isArray(conversations) && conversations && conversations.rows) conversations = conversations.rows
      // Normalize conversation objects to always include participantName
      conversations = (conversations || []).map((r) => ({
        ...r,
        participantName:
          r.participant_name || r.participantName || r.username || r.participantemail || r.participantEmail || (r.participant_id ? `User ${r.participant_id}` : 'Unknown'),
      }))
      socket.emit("conversation_list", conversations)
    } catch (error) {
      console.error("Error fetching conversations:", error)
    }
  })

  // Create conversation
  socket.on("create_conversation", async (data, callback) => {
    try {
      const { userId } = data
      const conversationId = `${Math.min(socket.userId, userId)}_${Math.max(socket.userId, userId)}`

      await sql.query(`INSERT INTO conversations (id, user1_id, user2_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, [
        conversationId,
        Math.min(socket.userId, userId),
        Math.max(socket.userId, userId),
      ])

      callback(conversationId)

      // Ensure the creator's socket joins the new conversation room
      try {
        socket.join(conversationId)
      } catch (e) {
        console.warn('[create_conversation] Failed to join creator to convo room:', e && e.message ? e.message : e)
      }

      // Tell the other user (if connected) to join the conversation room and update their conversation list
      const recipientId = Math.max(socket.userId, userId) === Math.max(socket.userId, userId) ? (Math.min(socket.userId, userId) === socket.userId ? userId : Math.min(socket.userId, userId)) : userId
      try {
        // fetch sockets in the recipient's personal room and join them to the conversation
        const recipientSockets = await io.in(`user_${userId}`).fetchSockets()
        for (const rs of recipientSockets) {
          try {
            rs.join(conversationId)
          } catch (e) {
            console.warn('[create_conversation] Failed to join recipient socket to convo room:', e && e.message ? e.message : e)
          }
        }
      } catch (e) {
        console.warn('[create_conversation] could not fetch/join recipient sockets:', e && e.message ? e.message : e)
      }

      // Emit updated conversation lists to both users (creator and recipient)
      try {
        let convsForCreator = await sql.query(
          `SELECT c.id, u.id as participant_id, u.username as participantName, u.email as participantEmail, m.content as lastMessage, m.created_at as lastMessageAt
           FROM conversations c 
           JOIN users u ON (CASE WHEN c.user1_id = $1 THEN c.user2_id ELSE c.user1_id END) = u.id
           LEFT JOIN LATERAL (
             SELECT content, created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1
           ) m ON true
           WHERE c.user1_id = $1 OR c.user2_id = $1
           ORDER BY m.created_at DESC NULLS LAST`,
          [socket.userId],
        )
        if (!Array.isArray(convsForCreator) && convsForCreator && convsForCreator.rows) convsForCreator = convsForCreator.rows
        convsForCreator = (convsForCreator || []).map((r) => ({
          ...r,
          participantName:
            r.participant_name || r.participantName || r.username || r.participantemail || r.participantEmail || (r.participant_id ? `User ${r.participant_id}` : 'Unknown'),
        }))
        io.to(`user_${socket.userId}`).emit('conversation_list', convsForCreator || [])

        let convsForRecipient = await sql.query(
          `SELECT c.id, u.id as participant_id, u.username as participantName, u.email as participantEmail, m.content as lastMessage, m.created_at as lastMessageAt
           FROM conversations c 
           JOIN users u ON (CASE WHEN c.user1_id = $1 THEN c.user2_id ELSE c.user1_id END) = u.id
           LEFT JOIN LATERAL (
             SELECT content, created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1
           ) m ON true
           WHERE c.user1_id = $1 OR c.user2_id = $1
           ORDER BY m.created_at DESC NULLS LAST`,
          [userId],
        )
        if (!Array.isArray(convsForRecipient) && convsForRecipient && convsForRecipient.rows) convsForRecipient = convsForRecipient.rows
        convsForRecipient = (convsForRecipient || []).map((r) => ({
          ...r,
          participantName:
            r.participant_name || r.participantName || r.username || r.participantemail || r.participantEmail || (r.participant_id ? `User ${r.participant_id}` : 'Unknown'),
        }))
        io.to(`user_${userId}`).emit('conversation_list', convsForRecipient || [])
      } catch (e) {
        console.warn('[create_conversation] Failed to emit updated conversation lists:', e && e.message ? e.message : e)
      }
    } catch (error) {
      console.error("Error creating conversation:", error)
    }
  })

  // Get messages
  socket.on("get_messages", async (data, callback) => {
    try {
      const { conversationId, before, limit } = data || {}
      const pageSize = parseInt(limit) || 30

      let messages
      if (before) {
        // load messages older than `before` (cursor pagination) - return oldest->newest
        messages = await sql.query(
          `SELECT * FROM messages WHERE conversation_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3`,
          [conversationId, before, pageSize],
        )
        if (!Array.isArray(messages) && messages && messages.rows) messages = messages.rows
        // rows come newest->oldest, reverse to oldest->newest for UI
        if (Array.isArray(messages)) messages = messages.reverse()
        callback(messages)
      } else {
        // initial load: get latest `pageSize` messages
        messages = await sql.query(
          `SELECT * FROM messages WHERE conversation_id = $1 ORDER BY created_at DESC LIMIT $2`,
          [conversationId, pageSize],
        )
        if (!Array.isArray(messages) && messages && messages.rows) messages = messages.rows
        if (Array.isArray(messages)) messages = messages.reverse()
        callback(messages)
      }
    } catch (error) {
      console.error("Error fetching messages:", error)
      callback([])
    }
  })

  // Send message
  socket.on("send_message", async (data) => {
    try {
      const { conversationId, content, type, fileName } = data

      let result = await sql.query(
        `INSERT INTO messages (conversation_id, sender_id, content, type, file_name, created_at) 
         VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
        [conversationId, socket.userId, content, type, fileName || null],
      )
      if (result && result.rows) result = result.rows

      const message = {
        ...(Array.isArray(result) ? result[0] : result),
        senderName: socket.username,
      }

      console.log('[message] Created message:', { conversationId, senderId: socket.userId, type, content: typeof content === 'string' ? (content.length > 100 ? content.slice(0, 100) + '...' : content) : typeof content })

      // Emit only to the conversation, not globally
      io.to(conversationId).emit("new_message", message)

      // Trigger n8n webhook
      await triggerN8nWebhook("message_sent", {
        userId: socket.userId,
        conversationId,
        messageType: type,
        timestamp: new Date().toISOString(),
      })
    } catch (error) {
      console.error("Error sending message:", error)
    }
  })

  // Typing indicator: broadcast to other sockets in the conversation room
  socket.on('typing', (data) => {
    try {
      const { conversationId, typing } = data || {}
      if (!conversationId) return
      // broadcast to others in the room
      socket.to(conversationId).emit('typing', {
        conversationId,
        userId: socket.userId,
        username: socket.username,
        typing: !!typing,
      })
    } catch (e) {
      console.warn('[typing] error:', e && e.message ? e.message : e)
    }
  })

  // Call events
  socket.on("initiate_call", async (data) => {
    const { conversationId } = data
    let otherUser = await sql.query(`SELECT user1_id, user2_id FROM conversations WHERE id = $1`, [conversationId])
    if (!Array.isArray(otherUser) && otherUser && otherUser.rows) otherUser = otherUser.rows

    if (!otherUser || otherUser.length === 0) {
      console.error("Conversation not found")
      return
    }

    const recipientId = otherUser[0].user1_id === socket.userId ? otherUser[0].user2_id : otherUser[0].user1_id
    io.to(`user_${recipientId}`).emit("incoming_call", {
      callerId: socket.userId,
      callerName: socket.username,
      conversationId,
    })

    await triggerN8nWebhook("call_initiated", {
      callerId: socket.userId,
      callerName: socket.username,
      recipientId,
      conversationId,
      timestamp: new Date().toISOString(),
    })
  })

  socket.on("end_call", async (data) => {
    const { conversationId } = data
    // Emit only to the conversation room
    if (conversationId) io.to(conversationId).emit("call_ended", { conversationId })

    await triggerN8nWebhook("call_ended", {
      userId: socket.userId,
      conversationId,
      timestamp: new Date().toISOString(),
    })
  })

  socket.on('call_rejected', (data) => {
    try {
      const { conversationId } = data || {}
      if (conversationId) io.to(conversationId).emit('call_rejected', { conversationId })
    } catch (e) {
      console.warn('[call_rejected] error', e && e.message ? e.message : e)
    }
  })

  // WebRTC signaling
  // WebRTC signaling: relay only to sockets in the conversation room
  socket.on("webrtc_offer", (data) => {
    try {
      const conv = data && data.conversationId
      if (conv) io.to(conv).emit("webrtc_offer", data)
    } catch (e) {
      console.warn('[webrtc_offer] relay error', e && e.message ? e.message : e)
    }
  })

  socket.on("webrtc_answer", (data) => {
    try {
      const conv = data && data.conversationId
      if (conv) io.to(conv).emit("webrtc_answer", data)
    } catch (e) {
      console.warn('[webrtc_answer] relay error', e && e.message ? e.message : e)
    }
  })

  socket.on("webrtc_ice_candidate", (data) => {
    try {
      const conv = data && data.conversationId
      if (conv) io.to(conv).emit("webrtc_ice_candidate", data)
    } catch (e) {
      console.warn('[webrtc_ice_candidate] relay error', e && e.message ? e.message : e)
    }
  })

  socket.on("disconnect", () => {
    console.log(`User disconnected: ${socket.userId}`)
  })
})

const PORT = process.env.PORT || 5000

// Startup environment checks (useful for debugging)
console.log('[startup] FRONTEND_URL:', process.env.FRONTEND_URL || '[not set]')
console.log('[startup] JWT_SECRET:', process.env.JWT_SECRET ? '[provided]' : '[not set]')
console.log('[startup] CLOUDINARY configured:', process.env.CLOUDINARY_NAME ? '[provided]' : '[not set]')

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
