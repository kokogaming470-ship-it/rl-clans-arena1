1. افتح discord-config.js واملأ القيم.
2. Discord Developer Portal → OAuth2 → Redirects: SITE_URL + /api/callback
3. ارفع المجلد على GitHub (Private) → Vercel → Import.
4. Vercel → Storage → أضف Upstash Redis واربطه (ضروري لحفظ البيانات).
5. Redeploy.
