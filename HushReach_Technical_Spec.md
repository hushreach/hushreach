# HushReach — Technical Architecture & Build Specification

**For:** Claude Code build sessions  
**Version:** 1.0  
**Date:** May 26, 2026  
**Companion to:** HushReach_Demo_PRD.md  

---

## 1. Red Team Findings — What the PRD Missed

These gaps will break your demo if not addressed during build.

### 1.1 Missing Pages (6)

| Page | Route | Why it's critical |
|---|---|---|
| **Sign In** | `/signin` | Returning users have no way to log in. PRD only designed signup. |
| **Forgot Password** | `/forgot-password` | Users WILL forget passwords. No reset = locked out permanently. |
| **Reset Password** | `/reset-password` | Landing page from Supabase reset email link. |
| **Email Verification** | `/auth/confirm` | Supabase sends verification by default. Need a page for the redirect. |
| **404 / Invalid QR** | `/c/[slug]` (invalid) | Scanner hits a deactivated or nonexistent card. Shows error, not a crash. |
| **Privacy + Terms** | `/privacy`, `/terms` | Listed in PRD as "template" but never designed. Need actual pages. |

### 1.2 Missing Database Tables (4)

| Table | Why |
|---|---|
| `profiles` | Extends `auth.users`. Stores `display_name` (dashboard says "Hi Sarah" — where does "Sarah" come from?), notification preferences. |
| `push_subscriptions` | PRD says web push notifications but has no table to store push subscription endpoints. |
| `notification_logs` | Need to track sent/delivered/failed per channel for reliability and the `notification_sent` analytics event. |
| `card_downloads` | Track which formats users download. Proves demand for car sticker + key ring in V1.1. |

### 1.3 Missing Fields on Existing Tables

| Table | Field | Why |
|---|---|---|
| `scan_events` | `status` (new/read/replied/resolved) | No way to mark a scan as handled. Dashboard can't show unread count. |
| `scan_events` | `is_flagged` (boolean) | Admin needs to flag suspicious scans without disabling the whole card. |
| `dependents` | `photo_url` (text) | Store the signed URL alongside `photo_path` to avoid regenerating it on every page load. |

### 1.4 Missing API Routes (5)

| Route | Method | Purpose |
|---|---|---|
| `/api/webhooks/twilio` | POST | **CRITICAL.** Twilio sends SMS replies here. Without it, two-way messaging doesn't work. The scanner replies to the masked number → Twilio POSTs to your webhook → you save the reply + notify the family. |
| `/api/push/subscribe` | POST | Store the browser push subscription object when user enables notifications. |
| `/api/cron/reassurance` | GET | Vercel Cron calls this monthly to send "your card is active" emails. |
| `/api/auth/callback` | GET | Supabase Auth redirect handler for email verification, password reset, and future OAuth. |
| `/api/card-pdf/[format]` | GET | PDF generation needs a format parameter (pocket_card vs door_tag). |

### 1.5 Missing Infrastructure

| Component | Impact |
|---|---|
| **`middleware.ts`** | Next.js middleware for auth guard. Without it, anyone can hit `/dashboard` directly. |
| **Rate limiting** | Scan form has reCAPTCHA, but API routes have zero rate limiting. A bot can spam notifications. |
| **HEIC photo handling** | iPhones shoot HEIC by default. Upload will fail or show nothing if you don't convert to JPEG/WebP. |
| **Error boundaries** | No error handling strategy. One Twilio failure crashes the scan flow. |
| **Environment variable spec** | 15+ env vars needed. None documented. |

### 1.6 Payment Gateway — NOT Needed for Demo

The PRD explicitly says "no payment system." Correct decision. Adding Stripe adds 2-3 build days and creates a billing support burden during pilot. Keep the demo free. Add Stripe in V1.1 after you have evidence that 25 families will pay.

**V1.1 payment plan (for future reference only):**
- Stripe Checkout (hosted payment page, not custom forms)
- Stripe Billing for subscriptions
- Pricing TBD after pilot data
- Webhook: `/api/webhooks/stripe` for payment events

### 1.7 LLM / AI Gateway — NOT Needed for Demo

The product's value is **relay-not-disclosure** — a communication mechanism, not intelligence. There is no feature in the demo that benefits from an LLM. reCAPTCHA v3 handles spam. The scanner's message is forwarded verbatim.

**Where AI could help in V1.1+ (future only):**
- Scan message urgency classification (is this "confused at pharmacy" or "wandering on highway"?)
- Smart notification priority (urgent = phone call, not just SMS)
- Safety note suggestions during setup

Skip AI entirely for demo. It adds latency, cost, and a dependency that can fail during your live presentation.

---

## 2. Complete Database Schema

### 2.1 Tables (10 total: 6 from PRD + 4 new)

```sql
-- ============================================
-- TABLE 1: profiles (NEW — extends auth.users)
-- ============================================
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name TEXT,
  phone TEXT,
  notification_prefs JSONB DEFAULT '{"sms": true, "email": true, "push": true}',
  timezone TEXT DEFAULT 'America/Halifax',
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Auto-create profile on signup via trigger
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, display_name)
  VALUES (NEW.id, split_part(NEW.email, '@', 1));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ============================================
-- TABLE 2: dependents
-- ============================================
CREATE TABLE public.dependents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID UNIQUE NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  first_name TEXT NOT NULL CHECK (char_length(first_name) <= 40),
  photo_path TEXT,
  photo_url TEXT,
  safety_notes TEXT CHECK (char_length(safety_notes) <= 200),
  qr_slug TEXT UNIQUE NOT NULL,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_dependents_qr_slug ON public.dependents(qr_slug);
CREATE INDEX idx_dependents_user_id ON public.dependents(user_id);

-- ============================================
-- TABLE 3: trusted_contacts
-- ============================================
CREATE TABLE public.trusted_contacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dependent_id UUID UNIQUE NOT NULL REFERENCES public.dependents(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) <= 60),
  phone_e164 TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- TABLE 4: scan_events (UPDATED with status + flagged)
-- ============================================
CREATE TABLE public.scan_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dependent_id UUID NOT NULL REFERENCES public.dependents(id) ON DELETE CASCADE,
  scanner_name TEXT NOT NULL,
  scanner_phone TEXT NOT NULL,
  message TEXT NOT NULL CHECK (char_length(message) <= 500),
  ip_address INET,
  city TEXT,
  status TEXT DEFAULT 'new' CHECK (status IN ('new', 'read', 'replied', 'resolved')),
  is_flagged BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_scan_events_dependent ON public.scan_events(dependent_id);
CREATE INDEX idx_scan_events_created ON public.scan_events(created_at DESC);

-- ============================================
-- TABLE 5: scan_replies
-- ============================================
CREATE TABLE public.scan_replies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_event_id UUID NOT NULL REFERENCES public.scan_events(id) ON DELETE CASCADE,
  direction TEXT NOT NULL CHECK (direction IN ('family_to_scanner', 'scanner_to_family')),
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- TABLE 6: twilio_proxy_sessions
-- ============================================
CREATE TABLE public.twilio_proxy_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_event_id UUID NOT NULL REFERENCES public.scan_events(id) ON DELETE CASCADE,
  twilio_session_sid TEXT NOT NULL,
  masked_number TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- TABLE 7: push_subscriptions (NEW)
-- ============================================
CREATE TABLE public.push_subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL,
  keys_p256dh TEXT NOT NULL,
  keys_auth TEXT NOT NULL,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(user_id, endpoint)
);

-- ============================================
-- TABLE 8: notification_logs (NEW)
-- ============================================
CREATE TABLE public.notification_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_event_id UUID REFERENCES public.scan_events(id) ON DELETE CASCADE,
  recipient_type TEXT NOT NULL CHECK (recipient_type IN ('user', 'trusted_contact')),
  recipient_id UUID NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('sms', 'email', 'push')),
  status TEXT DEFAULT 'sent' CHECK (status IN ('queued', 'sent', 'delivered', 'failed')),
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- TABLE 9: card_downloads (NEW)
-- ============================================
CREATE TABLE public.card_downloads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  dependent_id UUID NOT NULL REFERENCES public.dependents(id) ON DELETE CASCADE,
  format TEXT NOT NULL CHECK (format IN ('pocket_card', 'door_tag')),
  paper_size TEXT DEFAULT 'letter' CHECK (paper_size IN ('letter', 'a4')),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- ============================================
-- TABLE 10: rate_limits (NEW — simple IP-based)
-- ============================================
CREATE TABLE public.rate_limits (
  ip_address INET PRIMARY KEY,
  scan_count INTEGER DEFAULT 1,
  first_scan_at TIMESTAMPTZ DEFAULT now(),
  last_scan_at TIMESTAMPTZ DEFAULT now()
);
```

### 2.2 Row Level Security Policies

```sql
-- Profiles
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own profile" ON public.profiles FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users update own profile" ON public.profiles FOR UPDATE USING (auth.uid() = id);
CREATE POLICY "Users insert own profile" ON public.profiles FOR INSERT WITH CHECK (auth.uid() = id);

-- Dependents
ALTER TABLE public.dependents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users CRUD own dependents" ON public.dependents FOR ALL USING (auth.uid() = user_id);
-- Public read for scan page (via server-side function, not direct RLS)

-- Trusted contacts (via dependent ownership)
ALTER TABLE public.trusted_contacts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users manage own contacts" ON public.trusted_contacts FOR ALL
  USING (dependent_id IN (SELECT id FROM public.dependents WHERE user_id = auth.uid()));

-- Scan events
ALTER TABLE public.scan_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own scans" ON public.scan_events FOR SELECT
  USING (dependent_id IN (SELECT id FROM public.dependents WHERE user_id = auth.uid()));
CREATE POLICY "Public insert scans" ON public.scan_events FOR INSERT WITH CHECK (true);
-- ↑ Protected by reCAPTCHA + rate limiting at API level, not RLS

-- Scan replies
ALTER TABLE public.scan_replies ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own replies" ON public.scan_replies FOR SELECT
  USING (scan_event_id IN (
    SELECT se.id FROM public.scan_events se
    JOIN public.dependents d ON se.dependent_id = d.id
    WHERE d.user_id = auth.uid()
  ));
CREATE POLICY "Users insert replies" ON public.scan_replies FOR INSERT WITH CHECK (
  scan_event_id IN (
    SELECT se.id FROM public.scan_events se
    JOIN public.dependents d ON se.dependent_id = d.id
    WHERE d.user_id = auth.uid()
  ));

-- Push subscriptions
ALTER TABLE public.push_subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users manage own subs" ON public.push_subscriptions FOR ALL USING (auth.uid() = user_id);

-- Notification logs (read-only for users)
ALTER TABLE public.notification_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own notif logs" ON public.notification_logs FOR SELECT
  USING (scan_event_id IN (
    SELECT se.id FROM public.scan_events se
    JOIN public.dependents d ON se.dependent_id = d.id
    WHERE d.user_id = auth.uid()
  ));

-- Card downloads
ALTER TABLE public.card_downloads ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own downloads" ON public.card_downloads FOR ALL
  USING (dependent_id IN (SELECT id FROM public.dependents WHERE user_id = auth.uid()));
```

---

## 3. Complete Project File Structure

```
hushreach-demo/
├── app/
│   ├── layout.tsx                    # Root layout: Inter font, PWA meta, PostHog provider
│   ├── page.tsx                      # Page 1: Landing
│   ├── globals.css                   # Tailwind config + CSS vars
│   │
│   ├── (auth)/                       # Auth route group (no layout nesting)
│   │   ├── signin/page.tsx           # Sign-in form
│   │   ├── signup/page.tsx           # Page 2: Signup
│   │   ├── forgot-password/page.tsx  # Forgot password form
│   │   └── reset-password/page.tsx   # Reset password (from email link)
│   │
│   ├── auth/
│   │   └── callback/route.ts         # Supabase auth callback (email verify, pw reset)
│   │
│   ├── (protected)/                  # Route group: requires auth (middleware enforced)
│   │   ├── setup/page.tsx            # Page 3: Dependent profile setup
│   │   ├── dashboard/
│   │   │   ├── page.tsx              # Page 4: Dashboard
│   │   │   ├── card/page.tsx         # Page 5: Card download (4 formats)
│   │   │   ├── scan/[id]/page.tsx    # Page 6: Scan event detail + reply
│   │   │   └── profile/page.tsx      # Page 7: Edit dependent profile
│   │
│   ├── c/                            # Public scan routes (NO auth)
│   │   └── [slug]/
│   │       ├── page.tsx              # Page 8: Public scan landing
│   │       └── thanks/page.tsx       # Page 8b: Thank you
│   │
│   ├── admin/page.tsx                # Page 9: Admin (env-var password)
│   ├── privacy/page.tsx              # Privacy policy
│   ├── terms/page.tsx                # Terms of service
│   ├── not-found.tsx                 # Custom 404
│   │
│   └── api/
│       ├── scan/route.ts             # POST: handle scan form submission
│       ├── reply/route.ts            # POST: family sends reply via app
│       ├── card-pdf/route.ts         # GET: generate PDF (?format=pocket_card&size=letter)
│       ├── qr-regenerate/route.ts    # POST: regenerate QR slug
│       ├── push/
│       │   └── subscribe/route.ts    # POST: store push subscription
│       ├── webhooks/
│       │   └── twilio/route.ts       # POST: Twilio SMS reply webhook
│       └── cron/
│           └── reassurance/route.ts  # GET: monthly reassurance emails (Vercel Cron)
│
├── components/
│   ├── ui/
│   │   ├── button.tsx                # Primary + secondary button variants
│   │   ├── input.tsx                 # Text input with error state
│   │   ├── textarea.tsx              # Textarea with char counter
│   │   ├── card.tsx                  # White card component
│   │   ├── modal.tsx                 # Confirmation modal
│   │   ├── status-dot.tsx            # Green/gray status indicator
│   │   └── loading-spinner.tsx       # Loading state
│   ├── forms/
│   │   ├── signup-form.tsx
│   │   ├── signin-form.tsx
│   │   ├── setup-form.tsx
│   │   ├── edit-profile-form.tsx
│   │   ├── scan-form.tsx             # Public scan form
│   │   └── reply-input.tsx           # Sticky reply input
│   └── layouts/
│       ├── app-shell.tsx             # Authenticated app wrapper
│       └── public-shell.tsx          # Public page wrapper
│
├── lib/
│   ├── supabase/
│   │   ├── client.ts                 # createBrowserClient()
│   │   ├── server.ts                 # createServerClient() for server components
│   │   ├── admin.ts                  # Service role client (for webhooks, cron)
│   │   └── middleware.ts             # Auth helper for middleware.ts
│   ├── twilio.ts                     # Twilio client: sendSMS(), createProxySession()
│   ├── resend.ts                     # Resend client: sendScanEmail(), sendWelcome()
│   ├── qr.ts                        # QR code generation: generateQR(slug) → PNG buffer
│   ├── pdf.ts                        # PDF generation: generateCardPDF(format, dependent)
│   ├── push.ts                       # Web push: sendPushNotification(subscription, payload)
│   ├── posthog.ts                    # PostHog client + event helpers
│   ├── rate-limit.ts                 # IP-based rate limiting for scan form
│   ├── recaptcha.ts                  # reCAPTCHA v3 verification
│   └── utils.ts                      # formatPhone(), timeAgo(), generateSlug()
│
├── emails/                           # React Email templates
│   ├── scan-notification.tsx         # "[Name] was found" email
│   ├── welcome.tsx                   # Post-signup welcome
│   └── monthly-reassurance.tsx       # "Your card is active"
│
├── middleware.ts                     # Route protection: redirect unauthed users
│
├── public/
│   ├── manifest.json                 # PWA manifest
│   ├── sw.js                         # Service worker
│   ├── icons/                        # PWA icons (192, 512)
│   └── og-image.png                  # Social share image
│
├── supabase/
│   └── migrations/
│       ├── 00001_initial_schema.sql  # All tables + indexes
│       └── 00002_rls_policies.sql    # All RLS policies + triggers
│
├── .env.local.example                # Documented env vars (see section 6)
├── middleware.ts                      # Auth middleware
├── next.config.js                    # PWA headers, image domains
├── tailwind.config.ts                # Design system tokens
├── tsconfig.json
├── package.json
└── vercel.json                       # Cron job config
```

---

## 4. Complete API Route Map

### 4.1 Page Routes

| Route | Auth | Type | Description |
|---|---|---|---|
| `/` | Public | Server | Landing page |
| `/signin` | Public | Client | Sign-in form |
| `/signup` | Public | Client | Signup form |
| `/forgot-password` | Public | Client | Request password reset |
| `/reset-password` | Public | Client | Set new password (from email) |
| `/auth/callback` | Public | Route | Supabase redirect handler |
| `/setup` | Protected | Client | First-time dependent setup |
| `/dashboard` | Protected | Server+Client | Main dashboard |
| `/dashboard/card` | Protected | Client | Card format picker + download |
| `/dashboard/scan/[id]` | Protected | Client | Scan detail + reply thread |
| `/dashboard/profile` | Protected | Client | Edit dependent profile |
| `/c/[slug]` | Public | Server | Public scan landing |
| `/c/[slug]/thanks` | Public | Server | Thank you confirmation |
| `/admin` | Password-gated | Client | Admin dashboard |
| `/privacy` | Public | Server | Privacy policy |
| `/terms` | Public | Server | Terms of service |

### 4.2 API Routes

| Route | Method | Auth | Input | Output |
|---|---|---|---|---|
| `/api/scan` | POST | Public (reCAPTCHA) | `{scanner_name, scanner_phone, message, qr_slug, recaptcha_token}` | `{success: true}` + triggers SMS/email/push |
| `/api/reply` | POST | Authenticated | `{scan_event_id, body}` | `{reply_id}` + sends SMS via Twilio Proxy |
| `/api/card-pdf` | GET | Authenticated | `?format=pocket_card&size=letter` | PDF stream (application/pdf) |
| `/api/qr-regenerate` | POST | Authenticated | `{dependent_id}` | `{new_slug}` + deactivates old |
| `/api/push/subscribe` | POST | Authenticated | `{endpoint, keys: {p256dh, auth}}` | `{success: true}` |
| `/api/webhooks/twilio` | POST | Twilio signature | Twilio SMS webhook payload | TwiML response |
| `/api/cron/reassurance` | GET | Vercel Cron secret | — | Sends monthly emails to all active users |
| `/api/auth/callback` | GET | Public | Supabase auth code | Redirect to /dashboard or /setup |

---

## 5. Authentication Flows

### 5.1 Signup Flow

```
User → /signup → enters email + password → Supabase Auth createUser()
  → Supabase sends verification email
  → User clicks link → /auth/callback → exchanges code for session
  → Check: has dependent? → No → redirect to /setup
                           → Yes → redirect to /dashboard
```

### 5.2 Sign-In Flow

```
User → /signin → enters email + password → Supabase Auth signInWithPassword()
  → Success → Check: has dependent? → redirect to /setup or /dashboard
  → Failure → show "Invalid email or password" error
```

### 5.3 Password Reset Flow

```
User → /signin → clicks "Forgot password?"
  → /forgot-password → enters email → Supabase Auth resetPasswordForEmail()
  → Supabase sends reset email with link
  → User clicks link → /auth/callback?type=recovery → sets session
  → Redirect to /reset-password → enters new password
  → Supabase Auth updateUser({password}) → redirect to /dashboard
```

### 5.4 Middleware Route Protection

```typescript
// middleware.ts
import { createServerClient } from '@supabase/ssr'
import { NextResponse, type NextRequest } from 'next/server'

const PROTECTED_ROUTES = ['/setup', '/dashboard']
const AUTH_ROUTES = ['/signin', '/signup', '/forgot-password', '/reset-password']

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  
  // Create Supabase client with cookie handling
  const supabase = createServerClient(/* env vars, cookie config */)
  const { data: { user } } = await supabase.auth.getUser()
  
  // Unauthenticated user hitting protected route → redirect to /signin
  if (!user && PROTECTED_ROUTES.some(r => pathname.startsWith(r))) {
    return NextResponse.redirect(new URL('/signin', request.url))
  }
  
  // Authenticated user hitting auth routes → redirect to /dashboard
  if (user && AUTH_ROUTES.some(r => pathname.startsWith(r))) {
    return NextResponse.redirect(new URL('/dashboard', request.url))
  }
  
  return NextResponse.next()
}

export const config = {
  matcher: ['/setup/:path*', '/dashboard/:path*', '/signin', '/signup', '/forgot-password', '/reset-password']
}
```

---

## 6. Environment Variables

```bash
# .env.local.example — ALL required env vars for HushReach Demo

# ── Supabase ──
NEXT_PUBLIC_SUPABASE_URL=https://xxxxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbG...
SUPABASE_SERVICE_ROLE_KEY=eyJhbG...        # Server-only, never expose

# ── Twilio ──
TWILIO_ACCOUNT_SID=ACxxxxx
TWILIO_AUTH_TOKEN=xxxxx
TWILIO_PHONE_NUMBER=+1902xxxxxxx           # Canadian number
TWILIO_PROXY_SERVICE_SID=KSxxxxx           # Create in Twilio console

# ── Resend ──
RESEND_API_KEY=re_xxxxx
RESEND_FROM_EMAIL=notify@hushreach.com     # Verified domain

# ── reCAPTCHA ──
NEXT_PUBLIC_RECAPTCHA_SITE_KEY=6Lxxxxx
RECAPTCHA_SECRET_KEY=6Lxxxxx

# ── Web Push (VAPID keys) ──
NEXT_PUBLIC_VAPID_PUBLIC_KEY=BLxxxxx
VAPID_PRIVATE_KEY=xxxxx

# ── PostHog ──
NEXT_PUBLIC_POSTHOG_KEY=phc_xxxxx
NEXT_PUBLIC_POSTHOG_HOST=https://app.posthog.com

# ── Admin ──
ADMIN_PASSWORD=xxxxx                       # Single password for /admin

# ── Vercel Cron ──
CRON_SECRET=xxxxx                          # Protects cron endpoint

# ── App ──
NEXT_PUBLIC_APP_URL=https://hushreach.com
NEXT_PUBLIC_APP_NAME=HushReach
```

**Total: 17 environment variables.** Set these in Vercel dashboard → Settings → Environment Variables before deploying.

---

## 7. Core Data Flows

### 7.1 Scan → Notify → Reply (the money flow)

```
1. Scanner submits form at /c/[slug]
   ↓
2. POST /api/scan
   ├── Verify reCAPTCHA v3 token (reject if score < 0.5)
   ├── Check rate limit (max 5 scans per IP per hour)
   ├── Look up dependent by qr_slug (reject if !is_active)
   ├── Get IP city via Vercel request.geo
   ├── INSERT into scan_events
   ├── Look up user + trusted_contact for this dependent
   ├── Create Twilio Proxy session (masked numbers for both sides)
   ├── PARALLEL:
   │   ├── Send SMS to user via Twilio → log to notification_logs
   │   ├── Send SMS to trusted_contact via Twilio → log
   │   ├── Send email to user via Resend → log
   │   ├── Send email to trusted_contact via Resend → log
   │   └── Send web push to user (best effort) → log
   ├── Track PostHog events: scan_form_submitted, notification_sent (×5)
   └── Redirect to /c/[slug]/thanks
   ↓
3. User opens /dashboard/scan/[id] (from SMS link or push tap)
   ├── Mark scan_event.status = 'read'
   ├── Display message + scanner info
   ↓
4. User types reply or taps "Call via masked number"
   ├── Reply: POST /api/reply → INSERT scan_replies → Twilio sends SMS via proxy
   ├── Call: opens tel: URL with Twilio masked number
   ↓
5. Scanner replies via SMS to masked number
   ├── Twilio POSTs to /api/webhooks/twilio
   ├── INSERT scan_replies (direction: scanner_to_family)
   ├── Push notification to user: "New reply from [scanner_name]"
```

### 7.2 QR Regeneration Flow

```
1. User taps "Regenerate QR" → confirmation modal → confirms
2. POST /api/qr-regenerate
   ├── Generate new UUID slug
   ├── UPDATE dependents SET qr_slug = new_slug, updated_at = now()
   ├── Old slug immediately returns 404 on /c/[old_slug]
   ├── Generate new signed photo URL if photo exists
   └── Return new_slug
3. Dashboard updates. User must download new PDF and reprint.
```

### 7.3 PDF Generation Flow

```
1. User taps "Download PDF" on /dashboard/card → selects format
2. GET /api/card-pdf?format=pocket_card&size=letter
   ├── Auth check (must be logged in)
   ├── Fetch dependent (name, qr_slug, photo_url)
   ├── Generate QR code PNG from slug → hushreach.com/c/[slug]
   ├── Build PDF layout based on format:
   │   ├── pocket_card: 3.375" × 2.125" front + back on one page
   │   └── door_tag: 3.5" × 8.5" with hole punch mark
   ├── INSERT into card_downloads (analytics)
   ├── Track PostHog: pdf_downloaded
   └── Return PDF as application/pdf stream
```

---

## 8. Twilio Webhook Configuration

This is the piece most likely to break your demo.

### 8.1 Twilio Console Setup

1. Buy a Canadian phone number (+1 902 or +1 782 for Halifax).
2. Create a **Proxy Service** in Twilio Console → Proxy → Services.
3. Add the phone number to the Proxy Service's number pool.
4. Set the **Callback URL** for the Proxy Service to: `https://hushreach.com/api/webhooks/twilio`
5. Also set the phone number's **SMS webhook** to the same URL as a fallback.

### 8.2 Webhook Handler

```typescript
// app/api/webhooks/twilio/route.ts
import { NextRequest, NextResponse } from 'next/server'
import twilio from 'twilio'

export async function POST(req: NextRequest) {
  // 1. Verify Twilio signature (CRITICAL — prevents spoofed webhooks)
  const signature = req.headers.get('x-twilio-signature')
  const body = await req.formData()
  const isValid = twilio.validateRequest(
    process.env.TWILIO_AUTH_TOKEN!,
    signature!,
    `${process.env.NEXT_PUBLIC_APP_URL}/api/webhooks/twilio`,
    Object.fromEntries(body)
  )
  if (!isValid) return new NextResponse('Forbidden', { status: 403 })

  // 2. Extract message details
  const from = body.get('From') as string
  const messageBody = body.get('Body') as string
  const proxySession = body.get('outboundResourceSid') as string

  // 3. Look up scan_event by twilio_proxy_sessions.twilio_session_sid
  // 4. INSERT into scan_replies (direction: 'scanner_to_family', body: messageBody)
  // 5. Send push notification to user: "New reply from scanner"
  // 6. Return empty TwiML (Twilio expects a response)

  return new NextResponse(
    '<?xml version="1.0" encoding="UTF-8"?><Response></Response>',
    { headers: { 'Content-Type': 'text/xml' } }
  )
}
```

---

## 9. Vercel Configuration

### 9.1 vercel.json (Cron job)

```json
{
  "crons": [
    {
      "path": "/api/cron/reassurance",
      "schedule": "0 9 1 * *"
    }
  ]
}
```

This runs the reassurance email on the 1st of each month at 9 AM UTC.

### 9.2 next.config.js

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '*.supabase.co',
        pathname: '/storage/v1/object/**',
      },
    ],
  },
  headers: async () => [
    {
      source: '/api/webhooks/:path*',
      headers: [
        { key: 'Access-Control-Allow-Origin', value: '*' },
      ],
    },
  ],
}

module.exports = nextConfig
```

---

## 10. Premortem — 15 Ways the Demo Dies

| # | Failure | Probability | Prevention |
|---|---|---|---|
| 1 | Twilio number not provisioned for Canadian SMS | HIGH | Test SMS to a real Canadian number on Day 1. |
| 2 | Supabase free tier hits 500MB storage limit with photos | MEDIUM | Compress photos to 200KB max on upload. |
| 3 | reCAPTCHA false-positive blocks demo scanner | HIGH | Add a bypass token for demo presentations (env var). |
| 4 | PDF crashes on Safari (iOS) | MEDIUM | Test PDF download on iPhone Safari explicitly on Day 14. |
| 5 | Web push fails on investor's iPhone (iOS <16.4) | HIGH | SMS + email are guaranteed. Push is best-effort. Label it. |
| 6 | QR code prints too small to scan | MEDIUM | Test print at actual credit-card size. QR must be ≥20mm. |
| 7 | HEIC photo upload fails silently | HIGH | Convert HEIC to JPEG on upload using `sharp` or `heic-convert`. |
| 8 | Twilio Proxy session expires during demo | MEDIUM | Set expiry to 7 days. Verify sessions aren't auto-purged. |
| 9 | Welcome email lands in spam | HIGH | Set up SPF + DKIM + DMARC for hushreach.com. Test with Gmail. |
| 10 | Phone number validation rejects "+1 (902)" format | MEDIUM | Parse all formats → E.164 before validation. Use `libphonenumber`. |
| 11 | Password reset email never arrives | MEDIUM | Verify Supabase email templates are configured. Test Day 3. |
| 12 | Scan form submits but notification fails silently | HIGH | notification_logs table catches failures. Add error toast on scan page. |
| 13 | Rate limiter locks out legitimate scanner at demo | MEDIUM | Set generous limits (10/hour/IP). Whitelist demo IPs. |
| 14 | Photo signed URL expires during demo | LOW | Set to 1-year expiry. Verify on regenerate. |
| 15 | Multiple browser tabs cause session conflicts | LOW | Supabase handles this. Test multi-tab on Day 14. |

---

## 11. NPM Packages (Complete List)

```json
{
  "dependencies": {
    "next": "^14.2",
    "@supabase/supabase-js": "^2.39",
    "@supabase/ssr": "^0.1",
    "twilio": "^5.0",
    "resend": "^3.0",
    "@react-email/components": "^0.0.14",
    "react-email": "^2.0",
    "qrcode": "^1.5",
    "@react-pdf/renderer": "^3.3",
    "web-push": "^3.6",
    "posthog-js": "^1.96",
    "sharp": "^0.33",
    "lucide-react": "^0.383",
    "tailwindcss": "^3.4",
    "zod": "^3.22",
    "libphonenumber-js": "^1.10"
  },
  "devDependencies": {
    "typescript": "^5.3",
    "@types/node": "^20",
    "@types/react": "^18",
    "eslint": "^8",
    "eslint-config-next": "^14"
  }
}
```

**Key additions not in the PRD:**
- `sharp` — image compression + HEIC conversion
- `zod` — input validation schemas for all forms and API routes
- `libphonenumber-js` — phone number parsing and E.164 formatting
- `@supabase/ssr` — server-side auth for Next.js App Router

---

## 12. Component Inventory

| Component | File | Used By |
|---|---|---|
| `<Button>` | `components/ui/button.tsx` | All pages |
| `<Input>` | `components/ui/input.tsx` | All forms |
| `<Textarea>` | `components/ui/textarea.tsx` | Setup, edit, scan form |
| `<Card>` | `components/ui/card.tsx` | All pages |
| `<Modal>` | `components/ui/modal.tsx` | Dashboard (regenerate QR) |
| `<StatusDot>` | `components/ui/status-dot.tsx` | Dashboard |
| `<LoadingSpinner>` | `components/ui/loading-spinner.tsx` | All async operations |
| `<PhotoUpload>` | `components/forms/photo-upload.tsx` | Setup, edit profile |
| `<ChatBubble>` | `components/ui/chat-bubble.tsx` | Scan detail |
| `<FormatCard>` | `components/ui/format-card.tsx` | Card download page |
| `<SignupForm>` | `components/forms/signup-form.tsx` | Signup page |
| `<SigninForm>` | `components/forms/signin-form.tsx` | Sign-in page |
| `<SetupForm>` | `components/forms/setup-form.tsx` | Setup page |
| `<ScanForm>` | `components/forms/scan-form.tsx` | Public scan page |
| `<ReplyInput>` | `components/forms/reply-input.tsx` | Scan detail page |
| `<AppShell>` | `components/layouts/app-shell.tsx` | Protected pages |
| `<PublicShell>` | `components/layouts/public-shell.tsx` | Public pages |

---

## 13. Testing Checklist (Day 14)

### End-to-End Test Script

Run with 3 real people on 3 real devices:

**Person A (Adult Child — iPhone):**
1. Open hushreach.com on iPhone Safari
2. Tap "Get started" → signup with real email → verify email
3. Complete setup: enter parent name, upload photo, add trusted contact (Person C)
4. Download pocket card PDF → print at actual size
5. Add to Home Screen (PWA install)
6. Wait for scan...

**Person B (Scanner — Android):**
1. Scan the printed QR code with phone camera
2. Verify public scan page loads in <3 seconds
3. Enter name, phone number, message → submit
4. Verify thank-you page appears
5. Wait for phone call or SMS from Person A

**Person C (Trusted Contact — any device):**
1. Wait for SMS notification (should arrive <10 seconds)
2. Wait for email notification (should arrive <30 seconds)
3. Verify message content is correct

**Person A (continued):**
1. Verify SMS received
2. Verify email received
3. Verify push notification appeared (if PWA installed)
4. Open scan detail from notification link
5. Tap "Call back via masked number" → verify call connects
6. Type a reply → send → verify Person B receives SMS
7. Edit profile → change safety notes → verify scan page updates
8. Regenerate QR → verify old QR returns error → download new PDF

**Verify pass/fail for each step. Any failure = fix before launch.**

---

**End of Technical Specification.**
