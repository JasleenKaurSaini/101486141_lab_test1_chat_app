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

app.use("/views", express.static(path.join(__dirname, "views")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

const ROOMS = ["devops", "cloud computing", "covid19", "sports", "nodeJS", "news"];

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

function getTokenFromHeader(req) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice(7);
}

function auth(req, res, next) {
  const token = getTokenFromHeader(req);
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

app.get("/api/rooms", (req, res) => {
  res.json(ROOMS);
});

app.post("/api/signup", async (req, res) => {
  try {
    const { username, firstname, lastname, password } = req.body;

    if (!username || !firstname || !lastname || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ message: "Username already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({
      username,
      firstname,
      lastname,
      password: hashedPassword
    });

    res.json({ message: "Signup success" });
  } catch (e) {
    console.error("Signup error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Missing credentials" });
    }

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
      user: {
        username: user.username,
        firstname: user.firstname,
        lastname: user.lastname
      }
    });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/users", auth, async (req, res) => {
  try {
    const users = await User.find({}, { username: 1, _id: 0 }).sort({ username: 1 });
    res.json(users.map((u) => u.username));
  } catch (e) {
    console.error("Users list error:", e);
    res.status(500).json({ message: "Server error" });
  }
});

const onlineUsers = new Map();

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

  socket.on("join_room", async (data) => {
    const room = data?.room;
    if (!ROOMS.includes(room)) return;

    if (socket.currentRoom) socket.leave(socket.currentRoom);

    socket.join(room);
    socket.currentRoom = room;

    socket.emit("system", `Joined room: ${room}`);
    socket.to(room).emit("system", `${username} joined the room`);

    const last = await GroupMessage.find({ room }).sort({ date_sent: 1 }).limit(50);
    socket.emit("room_history", last);
  });

  socket.on("leave_room", () => {
    const current = socket.currentRoom;
    if (!current) return;

    socket.leave(current);
    socket.to(current).emit("system", `${username} left the room`);
    socket.currentRoom = null;

    socket.emit("system", "You left the room");
  });

  socket.on("room_message", async (data) => {
    const msg = data?.message;
    const room = socket.currentRoom;

    if (!room || !msg || !msg.trim()) return;

    const saved = await GroupMessage.create({
      from_user: username,
      room,
      message: msg.trim()
    });

    io.to(room).emit("room_message", saved);
  });

  socket.on("private_message", async (data) => {
    const to_user = data?.to_user;
    const msg = data?.message;

    if (!to_user || !msg || !msg.trim()) return;

    const saved = await PrivateMessage.create({
      from_user: username,
      to_user,
      message: msg.trim()
    });

    socket.emit("private_message", saved);

    const receiverSocketId = onlineUsers.get(to_user);
    if (receiverSocketId) io.to(receiverSocketId).emit("private_message", saved);
  });

  socket.on("typing_private", (data) => {
    const to_user = data?.to_user;
    const isTyping = !!data?.isTyping;

    const receiverSocketId = onlineUsers.get(to_user);
    if (!receiverSocketId) return;

    io.to(receiverSocketId).emit("typing_private", {
      from_user: username,
      isTyping
    });
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(username);
    io.emit("online_users", Array.from(onlineUsers.keys()));
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Server running on port", PORT);
});