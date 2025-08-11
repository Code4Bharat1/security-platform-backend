// controllers/sourceCodeController.js
export const scanSourceCode = (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ message: "Code is required", issues: [] });
  }

  const issues = [];

  // XSS Detection
  if (code.includes("<script>") || code.includes("eval(") || code.includes("document.write")) {
    issues.push("⚠️ Potential XSS detected.");
  }

  // SQL Injection Detection
  if (code.toLowerCase().includes("select * from") || code.includes("' OR '1'='1")) {
    issues.push("⚠️ Potential SQL Injection pattern found.");
  }

  res.status(200).json({ issues });
};
