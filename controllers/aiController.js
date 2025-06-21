import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch'; // required if not globally available

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, '../.env') });

console.log("HUGGINGFACE_API_KEY Loaded?", process.env.HUGGINGFACE_API_KEY ? "Yes" : "No");

const HF_API_URL = 'https://api-inference.huggingface.co/models/HuggingFaceH4/zephyr-7b-beta';

export const explainVulnerability = async (req, res) => {
  const { vulnerabilityName, details } = req.body;

  try {
    const prompt = `Explain the vulnerability "${vulnerabilityName}" in simple terms. Details: ${details}. Also explain how to fix it.`;

    const response = await fetch('https://api-inference.huggingface.co/models/HuggingFaceH4/zephyr-7b-beta', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.HUGGINGFACE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ inputs: prompt, options: { wait_for_model: true } })
    });

    const resultText = await response.text();
    let result;
    try {
      result = JSON.parse(resultText);
    } catch (err) {
      console.error("❌ Invalid JSON from Hugging Face:", resultText);
      return res.status(500).json({ error: 'Invalid response from Hugging Face API' });
    }

    let aiResponse = 'No output';
    if (Array.isArray(result) && result[0]?.generated_text) {
      aiResponse = result[0].generated_text;
    }

    res.json({ explanation: aiResponse });
  } catch (error) {
    console.error('Hugging Face AI error:', error);
    res.status(500).json({ error: 'Failed to generate explanation' });
  }
};
