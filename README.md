
# Deep Link Micro Pages

An IoT micro landing page platform that embeds digital identities in physical products. Each item gets a unique QR code linking to a customizable micro page where customers can add links, text, images, and connect with other owners. Built for a family-owned screen printing shop in Los Feliz, CA. Demo at [YQue.net](https://yque.net).

<p align="center">
  <img width="400" src="https://github.com/Tsangares/DLMP/blob/master/static/img/dlmp_example.jpg" alt="DLMP Example">
</p>

## Features

- **Identity-as-a-service for apparel** — bulk QR code generation linking to unique web pages
- **Customizable landing pages** — links, text, images, social media aggregation
- **Social graph** — friend requests and connections between product owners
- **Generative badges** — deterministic procedural artwork seeded from each identity hash
- **Web push & SMS notifications** — real-time engagement via VAPID protocol and Vonage/Sinch
- **Post-sale engagement** — brands maintain a digital channel with customers through their products
- **Privacy-first** — pages are anonymous and only accessible through physical interaction with the product

## How It Works

Three ingredients make a Deep Link Micro Page:

1. **Choose a physical object** — t-shirt, hat, sweater, mug
2. **Generate a unique identity** — QR code or RFID tag with a unique hash key
3. **Embed it** — heat-transfer printing or direct-to-garment (DTG)

When someone scans the QR code, they land on their own mobile-friendly page. The passkey to customize it ships inside the product packaging — the buyer owns their page.

## Background

My father owns a small business in Los Feliz selling screen printed t-shirts. We built this together to extend the life and utility of physical products, and to give his brick-and-mortar store a digital channel for post-sale engagement. We partnered with Y-Que Trading Post in Los Feliz to prototype the first batch.

## Stack

- **Backend**: Flask, Gunicorn
- **Database**: MongoDB (users, content, credentials)
- **QR Generation**: `qrcode` + `segno` with styled PIL rendering
- **Image Processing**: Pillow, NumPy (badge generation)
- **Auth**: Flask-Login with passkey/magic link system
- **Notifications**: Web Push (pywebpush + VAPID), SMS (Vonage/Sinch)
- **Rate Limiting**: Flask-Limiter backed by MongoDB
- **Deployment**: Heroku / Vercel

## Market Context

Competitors include Linktree ($45M Series B, 16M users), FlowCode (QR-to-landing-page, DTX Company), Carrd, and Beacons. DLMP differentiates on three axes:

1. **Physical-first** — identity is embedded in the product, not a social media bio link
2. **Ownership** — buyers get an anonymous page they control, not a brand-managed profile
3. **Social layer** — product owners can connect with each other through the platform

## Cost Structure

Low marginal cost. Server infrastructure supports thousands of identities at ~$15/month. QR code heat-transfer printing costs ~$0.25/unit at scale. The product sells identity endpoints with a service-level agreement — constant or positive returns to scale.
