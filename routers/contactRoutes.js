import express from 'express';
import Contact from '../models/contactModel.js'; // ye model banana hai niche

const router = express.Router();

// POST /api/contact
router.post('/', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    const newMessage = await Contact.create({ name, email, message });
    res.status(201).json(newMessage);
  } catch (error) {
    console.error('Contact form error:', error);
    res.status(500).json({ message: 'Something went wrong' });
  }
});

export default router;
