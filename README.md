# Deep Link Micro Pages (DLMP)

A Flask web application that turns physical apparel into digital assets. Each garment gets a unique QR code linking to a customizable personal landing page. Live demo: [YQue.net](https://yque.net)

## What It Does

Apparel companies purchase batches of unique QR codes from DLMP. Each code is printed onto a garment and links to a unique webpage. The customer who owns the garment can claim and customize that page — adding links, text, images, and a minted NFT badge — without creating a traditional account. Their key is physically embedded in the clothing.

Pages can optionally be made **public**, allowing anyone who scans the QR to view and contribute content.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3 / Flask |
| Database | MongoDB (Flask-PyMongo) |
| Auth | Flask-Login + passkey-based login |
| Forms | WTForms / Flask-WTF |
| Templates | Jinja2 |
| NFT / Ledger | IOTA Shimmer |
| Server | Gunicorn |

## Features

- **QR-linked pages** — bulk identity generation tied to physical objects
- **Passwordless auth** — login via a passkey embedded in the garment
- **Customizable content** — links, text blocks, profile image, blurb
- **Public pages** — make your page discoverable; visitors can add links and text
- **NFT badge minting** — each identity deterministically generates a unique badge on the Shimmer ledger, verifiable via MetaMask
- **Social network** — friend connections between page owners
- **Push notifications** — Web Push support per page
- **Payment gateway** — IOTA cryptocurrency integration
- **QR code generation** — on-demand QR codes rendered server-side

## Project Structure

```
dlmp/
├── src/
│   ├── main.py              # Flask app: routes, User model, all logic
│   ├── badge.py             # NFT badge generation
│   └── templates/
│       ├── account/         # Public page view
│       ├── edit_account/    # Customize / admin panel
│       └── login.html
├── requirements.txt
└── .env                     # Not committed — see Environment below
```

## Access Control

| Route | Who can access |
|-------|---------------|
| `GET /<key>` | Anyone (public pages shown openly; unclaimed pages show login) |
| `GET /<key>/admin` | Owner (authenticated) or anyone if page is public (read-only for non-owners) |
| `POST /<key>/admin` | Owner for all edits; public visitors can add links, text, and images |
| `GET/POST /<key>/admin/add/link` | Owner or public visitors on public pages |
| `GET/POST /<key>/admin/add/text` | Owner or public visitors on public pages |
| `DELETE`-style routes (del, images, redirect, notifications) | Owner only |
| `/<key>/p/<passkey>` | Passkey login — claims and logs into the page |

## Running Locally

```bash
python -m venv env
source env/bin/activate
pip install -r requirements.txt
# Copy and fill in .env (see Environment section)
python src/main.py
```

The dev server runs on `localhost:8099`. In production it runs under Gunicorn on port 8988 via `dlmp.service`.

## Environment Variables (`.env`)

```
SECRET_KEY=...
MONGO_URI=...
SALT=...
VAPID_PUBLIC_KEY=...
VAPID_PRIVATE_KEY=...
VAPID_CLAIM_EMAIL=...
```

## Background

My father owns a small screen-printing business in Los Feliz. We built DLMP together to reduce clothing waste and help his brick-and-mortar store compete in the digital age. Our first deployment was in partnership with [Y-Que Trading Post](https://y-que.com) in Los Feliz.

<p align="center">
  <img width="400" src="https://github.com/Tsangares/DLMP/blob/master/static/img/dlmp_example.jpg" alt="DLMP example">
</p>

## Competition

Similar services include LinkTree, FlowCode, Carrd, Milkshake, and Beacons. DLMP differentiates on three axes: (1) the identity is physically embedded in clothing, making access anonymous and tied to a real object; (2) the page supports real-world functions like payment gateways and NFT-based membership; (3) the self-sovereign identity model lets users prove ownership without paperwork or personal information.
