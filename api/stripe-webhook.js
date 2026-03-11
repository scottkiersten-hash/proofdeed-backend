import Stripe from "stripe";
import bodyParser from "body-parser";
import { buffer } from "micro";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export const config = {
  api: {
    bodyParser: false
  }
};

export default async function handler(req, res) {

  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }

  const sig = req.headers["stripe-signature"];

  let event;

  try {

    const buf = await buffer(req);

    event = stripe.webhooks.constructEvent(
      buf,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );

  } catch (err) {

    console.log("Webhook signature failed.", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);

  }

  if (event.type === "checkout.session.completed") {

    const session = event.data.object;

    const email = session.customer_details.email;
    const customerId = session.customer;
    const subscriptionId = session.subscription;

    console.log("New subscriber:", email);

    /*
      CREATE USER IN DATABASE
    */

    await createUserIfNotExists({
      email,
      customerId,
      subscriptionId
    });

  }

  res.json({ received: true });

}


/*
  USER CREATION LOGIC
*/

async function createUserIfNotExists({ email, customerId, subscriptionId }) {

  // Example placeholder logic

  console.log("Creating ProofDeed user:", email);

  // TODO:
  // Insert user into database
  // set monthly_limit
  // store stripe_customer_id
  // store subscription_id

}
