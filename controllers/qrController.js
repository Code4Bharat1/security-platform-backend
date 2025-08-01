import { spawn } from "child_process";
import path from "path";
import fs from "fs";

// ✅ Auto-handle OS Python command
const PYTHON = process.platform === "win32" ? "python" : "python3";

// ✅ Paths to Python scripts
const generatorPath = path.join(process.cwd(), "scripts", "qr_generator.py");
const detectorPath = path.join(process.cwd(), "scripts", "qr_detector.py");

// ✅ QR GENERATOR CONTROLLER
export const generateQRController = (req, res) => {
  const { url } = req.body;
  console.log("🔧 Incoming URL:", url);
  if (!url) return res.status(400).json({ error: "URL is required" });

  const outputsDir = path.join(process.cwd(), "outputs");
  console.log("📂 Output path:", outputsDir);

  if (!fs.existsSync(outputsDir)) {
    console.log("🛠 Creating outputs folder...");
    fs.mkdirSync(outputsDir, { recursive: true });
  }

  const filename = `qr_${Date.now()}.png`;
  const outputPath = path.join(outputsDir, filename);
  console.log("📦 Final QR file:", outputPath);

  const py = spawn(PYTHON, [generatorPath, url, "--save", outputPath], {
    env: { ...process.env, PYTHONIOENCODING: "utf-8" },
  });

  py.stdout.on("data", (data) => {
    console.log("[Python STDOUT]:", data.toString());
  });

  py.stderr.on("data", (err) => {
    console.error("[Python Generator Error]:", err.toString());
  });

  py.on("close", (code) => {
    console.log("🔚 Python exited with code:", code);
    const exists = fs.existsSync(outputPath);
    console.log("✅ File exists after Python?", exists);

    if (code !== 0 || !exists) {
      return res.status(500).json({ error: "QR generation failed." });
    }

    const image = fs.readFileSync(outputPath);
    res.set("Content-Type", "image/png");
    res.send(image);
    fs.unlinkSync(outputPath);
  });
};


// ✅ QR DETECTOR CONTROLLER
export const scanQRController = (req, res) => {
  if (!req.file) return res.status(400).json({ error: "QR image required" });

  const filePath = path.resolve(req.file.path);

  const py = spawn(PYTHON, [detectorPath, filePath], {
    env: { ...process.env, PYTHONIOENCODING: "utf-8" },
  });

  let result = "";

  py.stdout.on("data", (data) => {
    result += data.toString();
  });

  py.stderr.on("data", (err) => {
    console.error("[Python Detector Error]:", err.toString());
  });

  py.on("close", () => {
    fs.unlink(filePath, () => {}); // Cleanup uploaded file
    res.status(200).json({ report: result.trim() });
  });
};
