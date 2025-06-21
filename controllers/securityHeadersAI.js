import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const HF_API_URL = 'https://api-inference.huggingface.co/models/HuggingFaceH4/zephyr-7b-beta';

export const suggestSecurityHeaders = async (req, res) => {
  const { context } = req.body;

  try {
    const prompt = `
Suggest the recommended security HTTP headers for the following web app context: "${context}". 
Include proper example values for each header and a short explanation of why it's used.
`;

console.log("Hugging Face API URL:", HF_API_URL);
console.log(" Prompt:", prompt);

    const response = await fetch(HF_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.HUGGINGFACE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ inputs: prompt, options: { wait_for_model: true } })
    });

    
const resultText = await response.text();
console.log("📩 Raw HF response:", resultText);

    let result;

    try {
      result = JSON.parse(resultText);
    } catch (err) {
      console.error("❌ Invalid Hugging Face JSON:", resultText);
      return res.status(500).json({ error: 'Invalid response from Hugging Face API' });
    }

    let aiResponse = 'No output';
    if (Array.isArray(result) && result[0]?.generated_text) {
      aiResponse = result[0].generated_text;
    }

    res.json({ headers: aiResponse });
  } catch (error) {
    console.error('Security Headers AI error:', error);
    res.status(500).json({ error: 'Failed to generate security headers' });
  }
};
