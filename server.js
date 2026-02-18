import express from "express";
import cors from "cors";
import formData from "form-data";
import Mailgun from "mailgun.js";

const app = express();

app.use(cors());
app.use(express.json());

/*
|--------------------------------------------------------------------------
| Mailgun Setup
|--------------------------------------------------------------------------
*/

const mailgun = new Mailgun(formData);

const mg = mailgun.client({
  username: "api",
  key: process.env.MAILGUN_API_KEY,
  url: process.env.MAILGUN_BASE_U
