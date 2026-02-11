require("dotenv").config();
const express = require("express");
const http = require("http");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// serve views
app.use("/views", express.static(path.join(__dirname, "views")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "views", "login.html")));

// predefined rooms
const ROOMS = ["devops", "cloud computing", "covid19", "sports", "nodeJS", "news"];

// ------------------- Mongo + Schemas (in same file) -------------------
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((e) => console.error("Mongo error:", e.message));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  firstname: { type: String, required: true, trim: true },
  lastname: { type: String, required: true, trim: true },
  password: { type: String, required: true },
  createdon: { type: Date, default: Date.now }
});

const groupMsgSchema = new mongoose.Schema({
  from_user: { type: String, required: true },
  room: { type: String, required: true },
  message: { type: String, required: true, trim: true },
  date_sent: { type: Date, default: Date.now }
});

const privateMsgSchema = new mongoose.Schema({
  from_user: { type: String, required: true },
  to_user: { type: String, required: true },
  message: { type: String, required: true, trim: true },
  date_sent: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const GroupMessage = mongoose.model("GroupMessage", groupMsgSchema);
const PrivateMessage = mongoose.model("PrivateMessage", privateMsgSchema);

// ------------------- Helper: auth middleware -------------------
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // { id, username }
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ------------------- API -------------------
app.get("/api/rooms", (req, res) => res.json(ROOMS));

// signup
app.post("/api/signup", async (req, res) => {
  try {
    const { username, firstname, lastname, password } = req.body;
    if (!username || !firstname || !lastname || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ message: "Username already exists" });

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ username, firstname, lastname, password: hashed });

    res.json({ message: "Signup success" });
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

// login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Missing credentials" });

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: "Invalid username/password" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid username/password" });

    const token = jwt.sign(
      { id: user._id.toString(), username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login success",
      token,
      user: { username: user.username, firstname: user.firstname, lastname: user.lastname }
    });
  } catch (e) {
    res.status(500).json({ message: "Server error" });
  }
});

// list users (for private chat dropdown)
app.get("/api/users", auth, async (req, res) => {
  const users = await User.find({}, { username: 1, _id: 0 }).sort({ username: 1 });
  res.json(users.map(u => u.username));
});

// ------------------- Socket.io -------------------
const onlineUsers = new Map(); // username -> socketId

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("No token"));
  try {
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    next(new Error("Invalid token"));
  }
});

io.on("connection", (socket) => {
  const username = socket.user.username;
  onlineUsers.set(username, socket.id);
  io.emit("online_users", Array.from(onlineUsers.keys()));

  // join room
  socket.on("join_room", async ({ room }) => {
    if (!ROOMS.includes(room)) return;

    if (socket.currentRoom) socket.leave(socket.currentRoom);
    socket.join(room);
    socket.currentRoom = room;

    socket.emit("system", `Joined room: ${room}`);
    socket.to(room).emit("system", `${username} joined the room`);

    // load last 50 messages
    const last = await GroupMessage.find({ room }).sort({ date_sent: 1 }).limit(50);
    socket.emit("room_history", last);
  });

  // leave room
  socket.on("leave_room", () => {
    if (!socket.currentRoom) return;
    const r = socket.currentRoom;
    socket.leave(r);
    socket.to(r).emit("system", `${username} left the room`);
    socket.currentRoom = null;
    socket.emit("system", "You left the room");
  });

  // room message + store
  socket.on("room_message", async ({ message }) => {
    if (!socket.currentRoom || !message?.trim()) return;
    const doc = await GroupMessage.create({
      from_user: username,
      room: socket.currentRoom,
      message: message.trim()
    });
    io.to(socket.currentRoom).emit("room_message", doc);
  });

  // private message + store
  socket.on("private_message", async ({ to_user, message }) => {
    if (!to_user || !message?.trim()) return;
    const doc = await PrivateMessage.create({
      from_user: username,
      to_user,
      message: message.trim()
    });

    socket.emit("private_message", doc);

    const toSocket = onlineUsers.get(to_user);
    if (toSocket) io.to(toSocket).emit("private_message", doc);
  });

  // typing indicator (1-to-1)
  socket.on("typing_private", ({ to_user, isTyping }) => {
    const toSocket = onlineUsers.get(to_user);
    if (!toSocket) return;
    io.to(toSocket).emit("typing_private", { from_user: username, isTyping: !!isTyping });
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(username);
    io.emit("online_users", Array.from(onlineUsers.keys()));
  });
});

server.listen(process.env.PORT || 3000, () => {
  console.log("Server running on port", process.env.PORT || 3000);
});