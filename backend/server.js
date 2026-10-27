
const express = require("express");
const cors = require("cors");
const { spawn } = require("child_process");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "SIEM Login Threat API"
  });
});

app.get("/api/threats", (req, res) => {
  const python = spawn("python", ["hive_query.py"], {
    cwd: __dirname
  });

  let stdout = "";
  let stderr = "";

  python.stdout.on("data", (data) => {
    stdout += data.toString();
  });

  python.stderr.on("data", (data) => {
    stderr += data.toString();
  });

  python.on("error", (error) => {
    res.status(500).json({
      error: "Could not start Python bridge",
      details: error.message
    });
  });

  python.on("close", (code) => {
    if (res.headersSent) return;

    if (code !== 0) {
      return res.status(502).json({
        error: "Hive query failed",
        details: (stderr || stdout).slice(-2000)
      });
    }

    try {
      res.json(JSON.parse(stdout));
    } catch {
      res.status(502).json({
        error: "Invalid response from Hive bridge",
        details: stdout.slice(-2000)
      });
    }
  });
});

app.listen(PORT, () => {
  console.log(`SIEM API running at http://localhost:${PORT}`);
});
