// const express = require("express");
// const router = express.Router();
// const {
//   encryptText,
//   decryptText,
// } = require("../controllers/securecryptController");

// router.post("/encrypt", encryptText);
// router.post("/decrypt", decryptText);

// module.exports = router;

// securecryptRouter.js
import express from 'express';
import {
  encryptText,
  decryptText,
} from '../controllers/secureCryptController.js';

const router = express.Router();

router.post('/encrypt', encryptText);
router.post('/decrypt', decryptText);

export default router;



// This router handles secure cryptographic operations such as encryption and decryption of text.
// It uses AES-256-CBC for encryption and decryption, ensuring secure handling of sensitive data.
// The router provides two endpoints:
// 1. POST /encrypt - Accepts a text input and returns the encrypted version.
// 2. POST /decrypt - Accepts an encrypted text input and returns the decrypted version.
// The encryption and decryption processes utilize a randomly generated secret key and initialization vector (IV) for enhanced security.
// The router is designed to be integrated into a larger Express application, allowing for secure cryptographic operations within the application.
// It is essential to handle errors gracefully, especially during decryption, to avoid exposing sensitive information in case of invalid inputs.
// The router can be extended to include additional cryptographic

