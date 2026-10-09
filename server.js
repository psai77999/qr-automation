const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-to-a-long-random-secret";


// ==================================================
// MIDDLEWARE
// ==================================================

app.use(cors());
app.use(express.json({ limit: "10mb" }));


// ==================================================
// DIRECTORIES
// ==================================================

const DATA_DIR = path.join(__dirname, "data");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const DB_FILE = path.join(DATA_DIR, "db.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}


// ==================================================
// DATABASE
// ==================================================

function createEmptyDB() {
  return {
    events: [],
    attendees: [],
    volunteers: [],
    users: [],
    scans: []
  };
}

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(createEmptyDB(), null, 2)
  );
}

function readDB() {
  try {
    const data = fs.readFileSync(DB_FILE, "utf8");

    const db = JSON.parse(data);

    // Make sure older database files get the new arrays
    if (!Array.isArray(db.events)) db.events = [];
    if (!Array.isArray(db.attendees)) db.attendees = [];
    if (!Array.isArray(db.volunteers)) db.volunteers = [];
    if (!Array.isArray(db.users)) db.users = [];
    if (!Array.isArray(db.scans)) db.scans = [];

    return db;
  } catch (error) {
    console.error("Database read error:", error);
    return createEmptyDB();
  }
}

function writeDB(db) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(db, null, 2)
  );
}


// ==================================================
// ID GENERATOR
// ==================================================

function generateId(prefix) {
  return `${prefix}_${crypto.randomBytes(5).toString("hex")}`;
}


// ==================================================
// MULTER
// ==================================================

const upload = multer({
  dest: UPLOADS_DIR,
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});


// ==================================================
// AUTH HELPERS
// ==================================================

function createAuthToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      role: user.role,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}


function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        message: "Authentication required"
      });
    }

    const parts = authHeader.split(" ");

    if (
      parts.length !== 2 ||
      parts[0] !== "Bearer"
    ) {
      return res.status(401).json({
        message: "Invalid authorization format"
      });
    }

    const token = parts[1];

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    const db = readDB();

    const user = db.users.find(
      (item) => item.id === decoded.userId
    );

    if (!user) {
      return res.status(401).json({
        message: "User not found"
      });
    }

    if (!user.approved) {
      return res.status(403).json({
        message: "Your account is waiting for admin approval"
      });
    }

    req.user = user;

    next();

  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired authentication token"
    });
  }
}


function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      message: "Authentication required"
    });
  }

  if (req.user.role !== "admin") {
    return res.status(403).json({
      message: "Admin access required"
    });
  }

  next();
}


// ==================================================
// CREATE DEFAULT ADMIN
// ==================================================

function ensureAdminUser() {
  const db = readDB();

  const existingAdmin = db.users.find(
    (user) =>
      user.email.toLowerCase() ===
      "admin@aliettechpreneur.com"
  );

  if (!existingAdmin) {
    db.users.push({
      id: "admin_001",
      name: "Club Admin",
      email: "admin@aliettechpreneur.com",
      password: "admin123",
      role: "admin",
      approved: true,
      createdAt: new Date().toISOString()
    });

    writeDB(db);

    console.log(
      "Default admin created: admin@aliettechpreneur.com"
    );
  }
}

ensureAdminUser();


// ==================================================
// HEALTH CHECK
// ==================================================

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ALIET Smart QR Attendance Backend",
    timestamp: new Date().toISOString()
  });
});


// ==================================================
// AUTH - LOGIN
// ==================================================

app.post("/api/auth/login", (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const db = readDB();

    const user = db.users.find(
      (item) =>
        item.email.toLowerCase() ===
        email.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    if (user.password !== password) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    if (!user.approved) {
      return res.status(403).json({
        message:
          "Your volunteer account is waiting for admin approval"
      });
    }

    const token = createAuthToken(user);

    res.json({
      message: "Login successful",

      token,

      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        approved: user.approved
      }
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      message: "Login failed"
    });
  }
});


// ==================================================
// AUTH - VOLUNTEER REGISTER
// ==================================================

app.post("/api/auth/register", (req, res) => {
  try {
    const {
      name,
      email,
      password
    } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message:
          "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message:
          "Password must be at least 6 characters"
      });
    }

    const db = readDB();

    const normalizedEmail =
      email.trim().toLowerCase();

    const existingUser = db.users.find(
      (user) =>
        user.email.toLowerCase() ===
        normalizedEmail
    );

    if (existingUser) {
      return res.status(409).json({
        message: "Email already registered"
      });
    }

    const userId = generateId("user");

    const createdAt =
      new Date().toISOString();

    const user = {
      id: userId,
      name: name.trim(),
      email: normalizedEmail,
      password,
      role: "volunteer",
      approved: false,
      createdAt
    };

    db.users.push(user);

    db.volunteers.push({
      id: userId,
      name: user.name,
      email: user.email,
      approved: false,
      createdAt
    });

    writeDB(db);

    res.status(201).json({
      message:
        "Registration successful. Wait for admin approval.",

      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        approved: user.approved
      }
    });

  } catch (error) {
    console.error(
      "Registration error:",
      error
    );

    res.status(500).json({
      message: "Registration failed"
    });
  }
});


// ==================================================
// AUTH - GET CURRENT USER
// ==================================================

app.get(
  "/api/auth/me",
  requireAuth,
  (req, res) => {
    res.json({
      user: {
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        role: req.user.role,
        approved: req.user.approved
      }
    });
  }
);


// ==================================================
// ADMIN - GET VOLUNTEERS
// ==================================================

app.get(
  "/api/auth/volunteers",
  requireAuth,
  requireAdmin,
  (req, res) => {
    const db = readDB();

    const volunteers = db.users
      .filter(
        (user) => user.role === "volunteer"
      )
      .map((user) => ({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        approved: user.approved,
        createdAt: user.createdAt
      }));

    res.json({
      volunteers
    });
  }
);


// ==================================================
// ADMIN - CREATE VOLUNTEER
// ==================================================

app.post(
  "/api/auth/volunteers",
  requireAuth,
  requireAdmin,
  (req, res) => {
    try {
      const {
        name,
        email,
        password
      } = req.body;

      if (!name || !email || !password) {
        return res.status(400).json({
          message:
            "Name, email and password are required"
        });
      }

      const db = readDB();

      const normalizedEmail =
        email.trim().toLowerCase();

      const existing = db.users.find(
        (user) =>
          user.email.toLowerCase() ===
          normalizedEmail
      );

      if (existing) {
        return res.status(409).json({
          message: "Email already registered"
        });
      }

      const id = generateId("user");

      const volunteer = {
        id,
        name: name.trim(),
        email: normalizedEmail,
        password,
        role: "volunteer",
        approved: true,
        createdAt: new Date().toISOString()
      };

      db.users.push(volunteer);

      db.volunteers.push({
        id,
        name: volunteer.name,
        email: volunteer.email,
        approved: true,
        createdAt: volunteer.createdAt
      });

      writeDB(db);

      res.status(201).json({
        message: "Volunteer created successfully",

        volunteer: {
          id: volunteer.id,
          name: volunteer.name,
          email: volunteer.email,
          role: volunteer.role,
          approved: true
        }
      });

    } catch (error) {
      console.error(
        "Create volunteer error:",
        error
      );

      res.status(500).json({
        message:
          "Failed to create volunteer"
      });
    }
  }
);


// ==================================================
// ADMIN - APPROVE VOLUNTEER
// ==================================================

app.patch(
  "/api/auth/volunteers/:id/approve",
  requireAuth,
  requireAdmin,
  (req, res) => {
    const db = readDB();

    const user = db.users.find(
      (item) =>
        item.id === req.params.id &&
        item.role === "volunteer"
    );

    if (!user) {
      return res.status(404).json({
        message: "Volunteer not found"
      });
    }

    user.approved = true;

    const volunteer = db.volunteers.find(
      (item) => item.id === user.id
    );

    if (volunteer) {
      volunteer.approved = true;
    }

    writeDB(db);

    res.json({
      message: "Volunteer approved successfully",

      volunteer: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        approved: true
      }
    });
  }
);


// ==================================================
// ADMIN - REVOKE VOLUNTEER
// ==================================================

app.patch(
  "/api/auth/volunteers/:id/revoke",
  requireAuth,
  requireAdmin,
  (req, res) => {
    const db = readDB();

    const user = db.users.find(
      (item) =>
        item.id === req.params.id &&
        item.role === "volunteer"
    );

    if (!user) {
      return res.status(404).json({
        message: "Volunteer not found"
      });
    }

    user.approved = false;

    const volunteer = db.volunteers.find(
      (item) => item.id === user.id
    );

    if (volunteer) {
      volunteer.approved = false;
    }

    writeDB(db);

    res.json({
      message: "Volunteer access revoked"
    });
  }
);


// ==================================================
// CREATE EVENT
// ==================================================

app.post(
  "/api/events",
  requireAuth,
  requireAdmin,
  (req, res) => {
    try {
      const {
        name,
        date,
        venue
      } = req.body;

      if (!name) {
        return res.status(400).json({
          error: "Event name is required"
        });
      }

      const db = readDB();

      const event = {
        id: generateId("event"),
        name: name.trim(),
        date: date || null,
        venue: venue || null,
        createdAt: new Date().toISOString()
      };

      db.events.push(event);

      writeDB(db);

      res.status(201).json({
        message: "Event created successfully",
        event
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Failed to create event"
      });
    }
  }
);


// ==================================================
// GET ALL EVENTS
// ==================================================

app.get(
  "/api/events",
  requireAuth,
  (req, res) => {
    const db = readDB();

    res.json({
      events: db.events
    });
  }
);


// ==================================================
// GET SINGLE EVENT
// ==================================================

app.get(
  "/api/events/:eventId",
  requireAuth,
  (req, res) => {
    const db = readDB();

    const event = db.events.find(
      (item) =>
        item.id === req.params.eventId
    );

    if (!event) {
      return res.status(404).json({
        error: "Event not found"
      });
    }

    res.json({
      event
    });
  }
);


// ==================================================
// CSV PARSER
// ==================================================

function parseCSV(content) {
  const lines = content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length < 2) {
    return [];
  }

  const headers = lines[0]
    .split(",")
    .map((header) =>
      header.trim().toLowerCase()
    );

  const nameIndex =
    headers.indexOf("name");

  const emailIndex =
    headers.indexOf("email");

  const phoneIndex =
    headers.indexOf("phone");

  if (
    nameIndex === -1 ||
    emailIndex === -1
  ) {
    throw new Error(
      "CSV must contain name and email columns"
    );
  }

  return lines.slice(1).map((line) => {
    const values = line.split(",");

    return {
      name:
        values[nameIndex]?.trim() || "",

      email:
        values[emailIndex]?.trim() || "",

      phone:
        phoneIndex !== -1
          ? values[phoneIndex]?.trim() || ""
          : ""
    };
  });
}


// ==================================================
// UPLOAD ATTENDEES
// ==================================================

app.post(
  "/api/events/:eventId/attendees/upload",
  requireAuth,
  requireAdmin,
  upload.single("file"),
  (req, res) => {
    try {
      const {
        eventId
      } = req.params;

      const db = readDB();

      const event = db.events.find(
        (item) =>
          item.id === eventId
      );

      if (!event) {
        return res.status(404).json({
          error: "Event not found"
        });
      }

      if (!req.file) {
        return res.status(400).json({
          error: "CSV file is required"
        });
      }

      const content =
        fs.readFileSync(
          req.file.path,
          "utf8"
        );

      const rows =
        parseCSV(content);

      if (rows.length === 0) {
        return res.status(400).json({
          error: "No attendees found in CSV"
        });
      }

      const createdAttendees = [];

      for (const row of rows) {
        if (!row.name || !row.email) {
          continue;
        }

        const attendee = {
          id: generateId("attendee"),
          eventId,
          name: row.name,
          email: row.email,
          phone: row.phone || "",
          status: "Absent",
          qrGenerated: false,
          qrToken: null,
          qrDataUrl: null,
          qrGeneratedAt: null,
          checkedInAt: null,
          createdAt:
            new Date().toISOString()
        };

        db.attendees.push(attendee);

        createdAttendees.push(
          attendee
        );
      }

      writeDB(db);

      try {
        fs.unlinkSync(req.file.path);
      } catch {}

      res.status(201).json({
        message:
          "Attendees uploaded successfully",
        count: createdAttendees.length,
        attendees: createdAttendees
      });

    } catch (error) {
      console.error(
        "CSV upload error:",
        error
      );

      if (req.file?.path) {
        try {
          fs.unlinkSync(
            req.file.path
          );
        } catch {}
      }

      res.status(500).json({
        error:
          error.message ||
          "Failed to upload attendees"
      });
    }
  }
);


// ==================================================
// GET EVENT ATTENDEES
// ==================================================

app.get(
  "/api/events/:eventId/attendees",
  requireAuth,
  (req, res) => {
    const db = readDB();

    const attendees =
      db.attendees.filter(
        (attendee) =>
          attendee.eventId ===
          req.params.eventId
      );

    res.json({
      count: attendees.length,
      attendees
    });
  }
);


// ==================================================
// GENERATE SECURE QR CODES
// ==================================================

app.post(
  "/api/events/:eventId/generate-qrs",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const {
        eventId
      } = req.params;

      const db = readDB();

      const event = db.events.find(
        (item) =>
          item.id === eventId
      );

      if (!event) {
        return res.status(404).json({
          error: "Event not found"
        });
      }

      const attendees =
        db.attendees.filter(
          (attendee) =>
            attendee.eventId ===
            eventId
        );

      if (attendees.length === 0) {
        return res.status(400).json({
          error:
            "No attendees found for this event"
        });
      }

      let generated = 0;

      for (const attendee of attendees) {

        const token = jwt.sign(
          {
            attendeeId:
              attendee.id,

            eventId:
              eventId
          },

          JWT_SECRET,

          {
            expiresIn: "30d"
          }
        );

        const qrDataUrl =
          await QRCode.toDataURL(
            token,
            {
              errorCorrectionLevel:
                "H",

              margin: 2,

              width: 500
            }
          );

        attendee.qrToken =
          token;

        attendee.qrGenerated =
          true;

        attendee.qrGeneratedAt =
          new Date().toISOString();

        attendee.qrDataUrl =
          qrDataUrl;

        generated++;
      }

      writeDB(db);

      res.json({
        message:
          "QR codes generated successfully",

        eventId,

        generated
      });

    } catch (error) {
      console.error(
        "QR generation error:",
        error
      );

      res.status(500).json({
        error:
          "Failed to generate QR codes"
      });
    }
  }
);


// ==================================================
// DEVELOPMENT QR TOKEN HELPER
// REMOVE BEFORE PRODUCTION
// ==================================================

app.get(
  "/api/dev/qr-token/:attendeeId",
  requireAuth,
  requireAdmin,
  (req, res) => {
    const db = readDB();

    const attendee =
      db.attendees.find(
        (item) =>
          item.id ===
          req.params.attendeeId
      );

    if (!attendee) {
      return res.status(404).json({
        error: "Attendee not found"
      });
    }

    if (!attendee.qrToken) {
      return res.status(400).json({
        error:
          "QR has not been generated yet"
      });
    }

    res.json({
      attendeeId:
        attendee.id,

      token:
        attendee.qrToken
    });
  }
);


// ==================================================
// VERIFY QR + CHECK IN
// ==================================================

app.post(
  "/api/scan/verify",
  requireAuth,
  (req, res) => {
    try {
      const {
        token
      } = req.body;

      if (!token) {
        return res.status(400).json({
          code: "MISSING_QR",
          error:
            "QR token is required"
        });
      }

      let decoded;

      try {
        decoded = jwt.verify(
          token,
          JWT_SECRET
        );
      } catch (error) {
        return res.status(401).json({
          code: "INVALID_QR",
          error:
            "Invalid or expired QR code"
        });
      }

      const db = readDB();

      const attendee =
        db.attendees.find(
          (item) =>
            item.id ===
            decoded.attendeeId
        );

      if (!attendee) {
        return res.status(404).json({
          code:
            "ATTENDEE_NOT_FOUND",

          error:
            "Attendee not found"
        });
      }

      if (
        attendee.eventId !==
        decoded.eventId
      ) {
        return res.status(401).json({
          code:
            "EVENT_MISMATCH",

          error:
            "QR does not belong to this event"
        });
      }

      if (
        attendee.status ===
        "Present"
      ) {
        return res.status(409).json({
          code:
            "ALREADY_CHECKED_IN",

          message:
            "Attendee has already checked in",

          attendee: {
            id: attendee.id,
            name: attendee.name,
            email: attendee.email,
            checkedInAt:
              attendee.checkedInAt
          }
        });
      }

      const checkedInAt =
        new Date().toISOString();

      attendee.status =
        "Present";

      attendee.checkedInAt =
        checkedInAt;

      const scan = {
        id: generateId("scan"),

        attendeeId:
          attendee.id,

        eventId:
          attendee.eventId,

        scannedAt:
          checkedInAt,

        result:
          "SUCCESS",

        scannedBy:
          req.user.id
      };

      db.scans.push(scan);

      writeDB(db);

      res.json({
        code:
          "CHECK_IN_SUCCESS",

        message:
          "Attendance marked successfully",

        attendee: {
          id: attendee.id,

          name:
            attendee.name,

          email:
            attendee.email,

          status:
            attendee.status,

          checkedInAt:
            attendee.checkedInAt
        }
      });

    } catch (error) {
      console.error(
        "Scan verification error:",
        error
      );

      res.status(500).json({
        code:
          "SERVER_ERROR",

        error:
          "Unable to process QR scan"
      });
    }
  }
);


// ==================================================
// DASHBOARD STATS
// ==================================================

app.get(
  "/api/events/:eventId/stats",
  requireAuth,
  (req, res) => {
    const db = readDB();

    const attendees =
      db.attendees.filter(
        (attendee) =>
          attendee.eventId ===
          req.params.eventId
      );

    const total =
      attendees.length;

    const present =
      attendees.filter(
        (attendee) =>
          attendee.status ===
          "Present"
      ).length;

    const absent =
      total - present;

    const attendancePercentage =
      total === 0
        ? 0
        : Number(
            (
              (present / total) *
              100
            ).toFixed(2)
          );

    res.json({
      total,
      present,
      absent,
      attendancePercentage
    });
  }
);


// ==================================================
// START SERVER
// ==================================================

app.listen(
  PORT,
  () => {
    console.log("");
    console.log(
      "=========================================="
    );
    console.log(
      "   ALIET SMART QR ATTENDANCE BACKEND"
    );
    console.log(
      "=========================================="
    );
    console.log(
      `🚀 Backend running on http://localhost:${PORT}`
    );
    console.log(
      `❤️  Health: http://localhost:${PORT}/api/health`
    );
    console.log(
      `🔐 Login: http://localhost:${PORT}/api/auth/login`
    );
    console.log(
      `📝 Register: http://localhost:${PORT}/api/auth/register`
    );
    console.log(
      "=========================================="
    );
    console.log("");
  }
);
app.use(cors({
  origin: [
    "http://localhost:5173",
    "https://alietsmartqrr.netlify.app"
  ],
  credentials: true
}));