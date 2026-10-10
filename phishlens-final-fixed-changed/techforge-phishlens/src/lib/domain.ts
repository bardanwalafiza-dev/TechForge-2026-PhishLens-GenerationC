/**
 * Domain Verification & Phishing Intelligence Engine (v2)
 *
 * What changed vs v1 (why genuine sites like paypal.com / youtube.com showed "Caution"):
 *  - Matching is now done on the REGISTRABLE DOMAIN, so www.paypal.com, m.youtube.com,
 *    accounts.google.com, consent.youtube.com ... are all recognised as official.
 *  - The verified registry grew from ~45 to 200+ well-known brands (YouTube, Wikipedia,
 *    GitHub, Flipkart, Zomato ...). Government / education TLDs that only qualified
 *    bodies can register (.gov.in, .nic.in, .ac.in, .edu, .gov ...) are verified too.
 *  - Brand-impersonation checks are TOKEN based, not raw substring based, so innocent
 *    domains such as "applebees.com", "purchase.com" or "panasonic.com" are no longer
 *    flagged as phishing.
 *  - Real URL parsing (userinfo tricks, ports, trailing dots, IDN/punycode decoding,
 *    zero-width characters) instead of string splitting.
 *
 * Zero-trust is preserved: only a domain in the verified registry can be SAFE.
 * Anything unknown stays CAUTION, never SAFE.
 */

export interface OfficialBrand {
  brand: string;
  officialDomain: string;
  category:
    | 'Banking' | 'Payment' | 'Tech' | 'Government' | 'Social' | 'Crypto' | 'E-Commerce'
    | 'Media' | 'Travel' | 'Food & Delivery' | 'Telecom' | 'Insurance & Investing' | 'Education & Reference' | 'Developer';
  aliases?: string[];
  keywords?: string[]; // Extra impersonation triggers (the brand's own name is added automatically)
}

type Cat = OfficialBrand['category'];

// [brand, category, officialDomain, otherDomains, extraKeywords]
type Row = [string, Cat, string, string[]?, string[]?];

const ROWS: Row[] = [
  // ---- Global tech, social & media -------------------------------------------------
  ['Google', 'Tech', 'google.com', ['gmail.com', 'googlemail.com', 'g.co', 'google.co.in', 'google.co.uk', 'google.com.au', 'google.ca', 'google.de', 'google.fr', 'google.co.jp', 'google.com.sg', 'google.com.br', 'google.ae', 'android.com', 'chrome.com', 'withgoogle.com', 'googleblog.com'], ['gmail', 'g00gle']],
  ['YouTube', 'Media', 'youtube.com', ['youtu.be', 'youtube-nocookie.com', 'ytimg.com']],
  ['PayPal', 'Payment', 'paypal.com', ['paypal.me', 'paypal.in', 'paypal.co.uk', 'paypalobjects.com'], ['paypa1']],
  ['Apple', 'Tech', 'apple.com', ['icloud.com', 'me.com', 'mzstatic.com', 'cdn-apple.com'], ['icloud', 'appleid', 'applepay']],
  ['Microsoft', 'Tech', 'microsoft.com', ['live.com', 'office.com', 'office365.com', 'outlook.com', 'hotmail.com', 'msn.com', 'bing.com', 'skype.com', 'xbox.com', 'microsoftonline.com', 'windows.com', 'azure.com', 'visualstudio.com', 'onedrive.com', 'sharepointonline.com'], ['outlook', 'office365', 'onedrive', 'hotmail']],
  ['Amazon', 'E-Commerce', 'amazon.com', ['amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.ca', 'amazon.com.au', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ae', 'amazon.sg', 'amazonpay.in', 'amzn.to', 'amzn.in', 'aws.com', 'a2z.com'], ['amazonpay', 'amzn']],
  ['Meta / Facebook', 'Social', 'facebook.com', ['fb.com', 'fb.me', 'messenger.com', 'meta.com', 'fbcdn.net'], ['facebook']],
  ['Instagram', 'Social', 'instagram.com', ['cdninstagram.com', 'ig.me']],
  ['WhatsApp', 'Social', 'whatsapp.com', ['wa.me', 'whatsapp.net']],
  ['Netflix', 'Media', 'netflix.com', ['nflxvideo.net']],
  ['Twitter / X', 'Social', 'x.com', ['twitter.com', 't.co', 'twimg.com'], ['twitter']],
  ['Telegram', 'Social', 'telegram.org', ['t.me', 'telegram.me', 'telegram.dog']],
  ['LinkedIn', 'Social', 'linkedin.com', ['lnkd.in', 'licdn.com']],
  ['Reddit', 'Social', 'reddit.com', ['redd.it', 'redditmedia.com', 'redditstatic.com']],
  ['Pinterest', 'Social', 'pinterest.com', ['pin.it', 'pinimg.com']],
  ['Snapchat', 'Social', 'snapchat.com', ['snap.com']],
  ['TikTok', 'Social', 'tiktok.com', ['tiktokv.com']],
  ['Discord', 'Social', 'discord.com', ['discord.gg', 'discordapp.com', 'discord.media']],
  ['Twitch', 'Media', 'twitch.tv', ['twitchcdn.net']],
  ['Spotify', 'Media', 'spotify.com', ['spoti.fi', 'scdn.co']],
  ['Zoom', 'Tech', 'zoom.us', ['zoom.com']],
  ['Slack', 'Tech', 'slack.com', ['slack-edge.com']],
  ['Dropbox', 'Tech', 'dropbox.com', ['dropboxusercontent.com']],
  ['Adobe', 'Tech', 'adobe.com', ['acrobat.com', 'creativecloud.com']],
  ['Yahoo', 'Tech', 'yahoo.com', ['yahoo.co.in', 'yahoo.co.uk', 'ymail.com']],
  ['DuckDuckGo', 'Tech', 'duckduckgo.com'],
  ['Mozilla', 'Tech', 'mozilla.org', ['firefox.com']],
  ['OpenAI / ChatGPT', 'Tech', 'openai.com', ['chatgpt.com', 'chat.com']],
  ['Anthropic / Claude', 'Tech', 'anthropic.com', ['claude.ai', 'claude.com']],
  ['Cloudflare', 'Tech', 'cloudflare.com'],
  ['Samsung', 'Tech', 'samsung.com'],
  ['Intel', 'Tech', 'intel.com'],
  ['Cisco', 'Tech', 'cisco.com'],
  ['IBM', 'Tech', 'ibm.com'],
  ['Oracle', 'Tech', 'oracle.com'],
  ['Salesforce', 'Tech', 'salesforce.com', ['force.com']],
  ['Tesla', 'Tech', 'tesla.com'],
  ['GitHub', 'Developer', 'github.com', ['githubusercontent.com', 'githubassets.com']],
  ['GitLab', 'Developer', 'gitlab.com'],
  ['Stack Overflow', 'Developer', 'stackoverflow.com', ['stackexchange.com', 'stackoverflow.blog']],
  ['npm', 'Developer', 'npmjs.com', ['npmjs.org']],
  ['Python', 'Developer', 'python.org', ['pypi.org']],
  ['Wikipedia', 'Education & Reference', 'wikipedia.org', ['wikimedia.org', 'wiktionary.org', 'wikidata.org']],
  ['Medium', 'Media', 'medium.com'],
  ['BBC', 'Media', 'bbc.com', ['bbc.co.uk']],
  ['The New York Times', 'Media', 'nytimes.com'],
  ['Times of India', 'Media', 'timesofindia.com', ['timesofindia.indiatimes.com', 'indiatimes.com']],
  ['NDTV', 'Media', 'ndtv.com'],
  ['The Hindu', 'Media', 'thehindu.com'],

  // ---- Commerce, travel, food ------------------------------------------------------
  ['eBay', 'E-Commerce', 'ebay.com', ['ebay.in', 'ebay.co.uk']],
  ['Walmart', 'E-Commerce', 'walmart.com'],
  ['Shopify', 'E-Commerce', 'shopify.com'],
  ['AliExpress', 'E-Commerce', 'aliexpress.com', ['alibaba.com']],
  ['Flipkart', 'E-Commerce', 'flipkart.com', ['fkrt.it']],
  ['Myntra', 'E-Commerce', 'myntra.com'],
  ['Ajio', 'E-Commerce', 'ajio.com'],
  ['Meesho', 'E-Commerce', 'meesho.com'],
  ['Nykaa', 'E-Commerce', 'nykaa.com'],
  ['Tata Neu / Tata', 'E-Commerce', 'tataneu.com', ['tata.com', 'tatadigital.com', 'tataplay.com', 'tatacliq.com', '1mg.com', 'bigbasket.com']],
  ['Reliance / JioMart', 'E-Commerce', 'jiomart.com', ['ril.com', 'relianceretail.com', 'reliancedigital.in']],
  ['Zomato', 'Food & Delivery', 'zomato.com'],
  ['Swiggy', 'Food & Delivery', 'swiggy.com'],
  ['Blinkit', 'Food & Delivery', 'blinkit.com'],
  ['Zepto', 'Food & Delivery', 'zepto.com', ['zeptonow.com']],
  ['Uber', 'Travel', 'uber.com'],
  ['Ola', 'Travel', 'olacabs.com', ['olaelectric.com']],
  ['Airbnb', 'Travel', 'airbnb.com', ['airbnb.co.in']],
  ['Booking.com', 'Travel', 'booking.com'],
  ['Expedia', 'Travel', 'expedia.com'],
  ['MakeMyTrip', 'Travel', 'makemytrip.com', ['goibibo.com']],
  ['Cleartrip', 'Travel', 'cleartrip.com'],
  ['EaseMyTrip', 'Travel', 'easemytrip.com'],
  ['redBus', 'Travel', 'redbus.in', ['redbus.com']],
  ['BookMyShow', 'Media', 'bookmyshow.com'],
  ['Disney+ Hotstar', 'Media', 'hotstar.com', ['jiohotstar.com', 'disneyplus.com']],
  ['JioCinema', 'Media', 'jiocinema.com'],
  ['Prime Video', 'Media', 'primevideo.com'],
  ['SonyLIV', 'Media', 'sonyliv.com'],
  ['Zee5', 'Media', 'zee5.com'],

  // ---- Telecom ---------------------------------------------------------------------
  ['Jio', 'Telecom', 'jio.com', ['myjio.com']],
  ['Airtel', 'Telecom', 'airtel.in', ['airtel.com']],
  ['Vodafone Idea (Vi)', 'Telecom', 'myvi.in', ['vodafoneidea.com', 'vi.in']],
  ['BSNL', 'Telecom', 'bsnl.co.in'],

  // ---- Indian banks ----------------------------------------------------------------
  ['State Bank of India', 'Banking', 'sbi.co.in', ['onlinesbi.sbi', 'onlinesbi.com', 'sbi.bank', 'bank.sbi', 'sbicard.com', 'sbilife.co.in', 'sbimf.com'], ['sbi', 'onlinesbi']],
  ['HDFC Bank', 'Banking', 'hdfcbank.com', ['hdfc.com', 'hdfcbank.net', 'hdfcsec.com', 'hdfclife.com', 'hdfcfund.com', 'hdfcergo.com'], ['hdfc', 'hdfcbank']],
  ['ICICI Bank', 'Banking', 'icicibank.com', ['icicidirect.com', 'iciciprulife.com', 'icicipruamc.com', 'icicilombard.com'], ['icici', 'icicibank']],
  ['Axis Bank', 'Banking', 'axisbank.com', ['axismf.com', 'axismaxlife.com'], ['axisbank', 'axis-bank']],
  ['Kotak Mahindra Bank', 'Banking', 'kotak.com', ['kotakmf.com', 'kotaksecurities.com'], ['kotak', 'kotak811']],
  ['Punjab National Bank', 'Banking', 'pnbindia.in', ['pnb.bank', 'netpnb.com', 'pnbnet.in'], ['pnb', 'pnbindia']],
  ['Bank of Baroda', 'Banking', 'bankofbaroda.in', ['bobworld.com', 'bankofbaroda.com', 'bobibanking.com'], ['bankofbaroda', 'bobworld']],
  ['Canara Bank', 'Banking', 'canarabank.com', ['canarabank.in']],
  ['Union Bank of India', 'Banking', 'unionbankofindia.co.in', ['unionbankofindia.bank.in'], ['unionbank', 'uboi']],
  ['Bank of India', 'Banking', 'bankofindia.co.in'],
  ['IDBI Bank', 'Banking', 'idbibank.in', ['idbibank.com']],
  ['Indian Bank', 'Banking', 'indianbank.in', ['indianbank.co.in']],
  ['Central Bank of India', 'Banking', 'centralbankofindia.co.in'],
  ['Indian Overseas Bank', 'Banking', 'iob.in'],
  ['UCO Bank', 'Banking', 'ucobank.com'],
  ['IDFC FIRST Bank', 'Banking', 'idfcfirstbank.com', [], ['idfc', 'idfcfirst']],
  ['IndusInd Bank', 'Banking', 'indusind.com', ['indusindbank.com'], ['indusind']],
  ['Federal Bank', 'Banking', 'federalbank.co.in', [], ['federalbank']],
  ['Yes Bank', 'Banking', 'yesbank.in', ['yesbank.com'], ['yesbank']],
  ['Bandhan Bank', 'Banking', 'bandhanbank.com'],
  ['RBL Bank', 'Banking', 'rblbank.com'],
  ['AU Small Finance Bank', 'Banking', 'aubank.in'],
  ['South Indian Bank', 'Banking', 'southindianbank.com'],
  ['Karnataka Bank', 'Banking', 'karnatakabank.com'],
  ['Standard Chartered', 'Banking', 'sc.com', ['standardchartered.com', 'standardchartered.co.in'], ['standardchartered']],
  ['HSBC', 'Banking', 'hsbc.com', ['hsbc.co.in', 'hsbc.co.uk']],
  ['Reserve Bank of India', 'Government', 'rbi.org.in'],

  // ---- Indian fintech, payments, investing ------------------------------------------
  ['Paytm', 'Payment', 'paytm.com', ['paytmbank.com', 'paytmmoney.com']],
  ['PhonePe', 'Payment', 'phonepe.com', ['phon.pe']],
  ['Razorpay', 'Payment', 'razorpay.com', ['rzp.io']],
  ['CRED', 'Payment', 'cred.club'],
  ['BHIM / NPCI', 'Payment', 'npci.org.in', ['bhimupi.org.in', 'upichalo.com'], ['npci', 'bhimupi']],
  ['MobiKwik', 'Payment', 'mobikwik.com'],
  ['Zerodha', 'Insurance & Investing', 'zerodha.com'],
  ['Groww', 'Insurance & Investing', 'groww.in'],
  ['Upstox', 'Insurance & Investing', 'upstox.com'],
  ['Angel One', 'Insurance & Investing', 'angelone.in', ['angelbroking.com']],
  ['NSE India', 'Insurance & Investing', 'nseindia.com'],
  ['BSE India', 'Insurance & Investing', 'bseindia.com'],
  ['NSDL', 'Insurance & Investing', 'nsdl.co.in', ['nsdl.com']],
  ['CIBIL', 'Insurance & Investing', 'cibil.com'],
  ['LIC of India', 'Insurance & Investing', 'licindia.in', ['licindia.com']],
  ['PolicyBazaar', 'Insurance & Investing', 'policybazaar.com'],

  // ---- Indian government & utilities (explicit; *.gov.in / *.nic.in are also auto-verified) ---
  ['Income Tax Dept India', 'Government', 'incometax.gov.in', ['incometaxindia.gov.in', 'incometaxindiaefiling.gov.in'], ['incometax', 'incometaxindia']],
  ['UIDAI (Aadhaar)', 'Government', 'uidai.gov.in', ['myaadhaar.uidai.gov.in'], ['uidai', 'aadhaar']],
  ['IRCTC Railway', 'Government', 'irctc.co.in', ['irctc.com', 'indianrail.gov.in'], ['irctc']],
  ['EPFO (Provident Fund)', 'Government', 'epfindia.gov.in', ['epfindia.com'], ['epfindia', 'epfo']],
  ['Passport Seva', 'Government', 'passportindia.gov.in', [], ['passportindia']],
  ['DigiLocker', 'Government', 'digilocker.gov.in'],
  ['GST Portal', 'Government', 'gst.gov.in'],
  ['India.gov.in', 'Government', 'india.gov.in'],

  // ---- Global finance & crypto ------------------------------------------------------
  ['Chase Bank', 'Banking', 'chase.com', ['jpmorgan.com', 'jpmorganchase.com']],
  ['Bank of America', 'Banking', 'bankofamerica.com', ['bofa.com'], ['bankofamerica']],
  ['Wells Fargo', 'Banking', 'wellsfargo.com', [], ['wellsfargo']],
  ['Citibank', 'Banking', 'citi.com', ['citibank.com', 'citibank.co.in', 'citigroup.com'], ['citibank', 'citi']],
  ['Capital One', 'Banking', 'capitalone.com'],
  ['Barclays', 'Banking', 'barclays.co.uk', ['barclays.com']],
  ['Visa', 'Payment', 'visa.com', ['visa.co.in']],
  ['Mastercard', 'Payment', 'mastercard.com', ['mastercard.co.in']],
  ['American Express', 'Payment', 'americanexpress.com', ['amex.com', 'aexp.com']],
  ['Stripe', 'Payment', 'stripe.com'],
  ['Wise', 'Payment', 'wise.com', ['transferwise.com']],
  ['Western Union', 'Payment', 'westernunion.com'],
  ['Venmo', 'Payment', 'venmo.com'],
  ['Cash App', 'Payment', 'cash.app', ['cashapp.com']],
  ['Revolut', 'Banking', 'revolut.com'],
  ['Binance', 'Crypto', 'binance.com', ['binance.us', 'binance.org']],
  ['Coinbase', 'Crypto', 'coinbase.com'],
  ['Kraken', 'Crypto', 'kraken.com'],
  ['WazirX', 'Crypto', 'wazirx.com'],
  ['CoinDCX', 'Crypto', 'coindcx.com'],
  ['MetaMask', 'Crypto', 'metamask.io'],
];

export const OFFICIAL_BRANDS: OfficialBrand[] = ROWS.map(([brand, category, officialDomain, others, keywords]) => ({
  brand,
  officialDomain,
  category,
  aliases: others && others.length ? others : undefined,
  keywords,
}));

/**
 * Brand names that are also ordinary words. Seeing one inside an unrelated domain
 * ("apple-orchard.com", "axis-fitness.in") is only a weak signal, so it needs extra
 * phishing context to become DANGER.
 */
const WEAK_BRANDS = new Set([
  'Apple', 'Chase Bank', 'Axis Bank', 'Citibank', 'CRED', 'Kraken', 'Wise', 'Ola', 'Slack', 'Zoom', 'Visa',
  'Uber', 'Oracle', 'Intel', 'Medium', 'Jio', 'Booking.com', 'Yes Bank', 'Federal Bank', 'Indian Bank',
  'Central Bank of India', 'Bank of India', 'Union Bank of India', 'Python', 'Discord', 'Twitch', 'Mozilla',
  'Reddit', 'Express', 'Stripe', 'Cash App', 'Snapchat', 'Pinterest', 'Reserve Bank of India', 'India.gov.in',
  'Tata Neu / Tata', 'BBC', 'Reliance / JioMart', 'Disney+ Hotstar', 'Prime Video', 'Meta / Facebook',
]);

export const RISKY_TLDS = new Set([
  'xyz', 'top', 'click', 'buzz', 'gq', 'cf', 'ml', 'tk', 'ga', 'cam', 'country', 'stream', 'download',
  'accountant', 'date', 'faith', 'racing', 'win', 'bid', 'loan', 'review', 'sbs', 'icu', 'monster', 'cfd',
  'quest', 'pw', 'rest', 'zip', 'mov', 'lol', 'bond', 'beauty', 'hair', 'skin', 'makeup',
  // Legitimate sites use these too, so they weigh less (see DUAL_USE_TLDS), but they are abused often.
  'live', 'space', 'fit', 'work', 'support',
]);
const DUAL_USE_TLDS = new Set(['live', 'space', 'fit', 'work', 'support']);

export const BLOCKLIST_DOMAINS = new Set([
  'g00gle.com',
  'paypa1.com',
  'sbi-login.xyz',
  'secure-hdfc-kyc.com',
  'icici-kycupdate.top',
  'paytm-cashback2026.click',
  'free-crypto-giveaway.buzz',
  'apple-id-verify.support',
  'update-pan-aadhaar.live',
  'axis-kyc-unblock.xyz',
  'pnb-pan-verification.top',
  'kotak-card-rewards.click',
  'falseqr.com',
  'fake-qr.com',
  'fakebank.com',
  'scam-portal.com',
  'false-qr-code.com',
]);

// Characters that look identical to Latin letters (Cyrillic / Greek / a few Latin-lookalikes).
export const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', '\u0410': 'A', '\u0435': 'e', '\u0415': 'E', '\u043E': 'o', '\u041E': 'O',
  '\u0440': 'p', '\u0420': 'P', '\u0441': 'c', '\u0421': 'C', '\u0443': 'y', '\u0423': 'Y',
  '\u0445': 'x', '\u0425': 'X', '\u0456': 'i', '\u0406': 'I', '\u0458': 'j', '\u0455': 's',
  '\u03BF': 'o', '\u039F': 'O', '\u03B1': 'a', '\u03C1': 'p', '\u03BD': 'v',
  '\u04BB': 'h', '\u0501': 'd', '\u051B': 'q', '\u051D': 'w', '\u0261': 'g', '\u0131': 'i',
  '\u0269': 'i', '\u1D0F': 'o', '\u03B9': 'i', '\u0442': 't', '\u043D': 'h', '\u043A': 'k', '\u043C': 'm',
};
// Of the lookalikes above, these are only confusable with Latin when mixed in or when the whole word is lookalikes.
// (Cyrillic т, н, к, м are less visually identical, so they never trigger alone.)
const WEAK_LOOKALIKES = new Set(['\u0442', '\u043D', '\u043A', '\u043C', '\u03B9']);

// Multi-label public suffixes (no full Public Suffix List needed).
const MULTI_LABEL_SUFFIXES = new Set([
  'co.in', 'org.in', 'net.in', 'gov.in', 'ac.in', 'edu.in', 'res.in', 'nic.in', 'firm.in', 'gen.in', 'ind.in', 'bank.in',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.za', 'com.br', 'com.cn', 'com.sg', 'com.my', 'co.id', 'com.pk', 'com.bd',
  'com.np', 'co.ke', 'com.ng', 'com.hk', 'com.tr', 'com.mx', 'com.ar', 'com.eg', 'com.sa', 'co.il', 'co.kr', 'com.tw',
  'com.vn', 'com.ph', 'co.th', 'com.ua', 'com.ru', 'org.ru', 'gov.au', 'gc.ca',
]);
const SLD_LIKE = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'ne', 'or', 'go', 'nic', 'mil']);

/** eTLD+1 (registered domain) of a host. */
export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  const last = labels[labels.length - 1];
  const second = labels[labels.length - 2];
  if (last.length === 2 && SLD_LIKE.has(second)) return labels.slice(-3).join('.');
  return lastTwo;
}

/** Suffixes only qualifying bodies can register: a name here is itself a strong trust signal. */
const RESTRICTED_SUFFIXES: { suffix: string; label: string }[] = [
  { suffix: 'gov.in', label: 'Government of India' },
  { suffix: 'nic.in', label: 'Government of India (NIC)' },
  { suffix: 'ac.in', label: 'Indian academic institution' },
  { suffix: 'edu.in', label: 'Indian academic institution' },
  { suffix: 'res.in', label: 'Indian research institution' },
  { suffix: 'gov.uk', label: 'UK Government' },
  { suffix: 'ac.uk', label: 'UK academic institution' },
  { suffix: 'gov.au', label: 'Australian Government' },
  { suffix: 'edu.au', label: 'Australian academic institution' },
  { suffix: 'gc.ca', label: 'Government of Canada' },
  { suffix: 'gov', label: 'US Government' },
  { suffix: 'mil', label: 'US Military' },
  { suffix: 'edu', label: 'US accredited institution' },
];

/** Genuine platforms where ANYONE can publish a page. The platform is real, the page may not be. */
const USER_CONTENT_HOSTS = [
  'sites.google.com', 'docs.google.com', 'forms.google.com', 'drive.google.com', 'script.google.com',
  'onedrive.live.com', 'sharepoint.com', 'storage.googleapis.com',
];

/** Free hosting / tunnelling platforms: the platform's own name must not be treated as a brand. */
const SHARED_PLATFORMS = new Set([
  'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'herokuapp.com',
  'firebaseapp.com', 'web.app', 'appspot.com', 'blogspot.com', 'blogspot.in', 'wordpress.com', 'wixsite.com',
  'weebly.com', 'webflow.io', 'glitch.me', 'repl.co', 'replit.app', 'replit.dev', 'onrender.com', 'azurewebsites.net',
  'cloudfront.net', 'amazonaws.com', 'googleusercontent.com', 'trycloudflare.com', 'ngrok.io', 'ngrok-free.app',
  'duckdns.org', 'no-ip.org', 'ddns.net', '000webhostapp.com', 'infinityfreeapp.com', 'framer.website', 'carrd.co',
  'godaddysites.com', 'mystrikingly.com', 'square.site', 'myshopify.com', 'notion.site', 'canva.site', 'my.canva.site',
  'surge.sh', 'fly.dev', 'railway.app', 'netlify.com', 'azurestaticapps.net', 'cloudapp.azure.com', 'r2.dev',
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'goo.gl', 'ow.ly', 'rb.gy', 'rebrand.ly', 'shorturl.at',
  'tiny.cc', 'bl.ink', 'buff.ly', 'lnkd.in', 'qrco.de', 'qr.link', 'l.ead.me', 'v.gd', 'shorturl.com',
]);

// ---------------------------------------------------------------------------------------
// Punycode (RFC 3492) so that xn-- hosts can be turned back into the characters people see
// ---------------------------------------------------------------------------------------

function adaptBias(delta: number, numPoints: number, first: boolean): number {
  delta = first ? Math.floor(delta / 700) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > 455) {
    delta = Math.floor(delta / 35);
    k += 36;
  }
  return Math.floor(k + (36 * delta) / (delta + 38));
}

function decodePunycode(input: string): string {
  const output: number[] = [];
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    if (input.charCodeAt(j) >= 0x80) throw new Error('bad punycode');
    output.push(input.charCodeAt(j));
  }
  let n = 128;
  let i = 0;
  let bias = 72;
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (idx >= input.length) throw new Error('bad punycode');
      const cp = input.charCodeAt(idx++);
      let digit: number;
      if (cp >= 48 && cp <= 57) digit = cp - 22;
      else if (cp >= 65 && cp <= 90) digit = cp - 65;
      else if (cp >= 97 && cp <= 122) digit = cp - 97;
      else throw new Error('bad punycode');
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= 36 - t;
    }
    const len = output.length + 1;
    bias = adaptBias(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Turn an ASCII (punycode) hostname into the Unicode form a human would see. */
export function toUnicodeHost(host: string): string {
  return host
    .split('.')
    .map((label) => {
      if (!label.startsWith('xn--')) return label;
      try {
        return decodePunycode(label.slice(4));
      } catch {
        return label;
      }
    })
    .join('.');
}

// ---------------------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------------------

export interface ParsedTarget {
  /** Lower-case host in Unicode form (punycode decoded). */
  hostname: string;
  /** Host exactly as the network will see it (punycode). */
  asciiHost: string;
  protocol: string;
  username: string;
  password: string;
  port: string;
  /** Path + query + fragment, lower-cased and URL-decoded where possible. */
  pathAndQuery: string;
  isIp: boolean;
  /** Zero-width / control characters were present in the input. */
  hasInvisibleChars: boolean;
  explicitScheme: boolean;
}

const INVISIBLE = /[\u0000-\u001f\u007f\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g;

export function parseTarget(input: string): ParsedTarget | null {
  if (!input || typeof input !== 'string') return null;
  let s = input.trim().replace(/^[<"'`\s]+|[>"'`\s]+$/g, '');
  const hasInvisibleChars = INVISIBLE.test(s);
  INVISIBLE.lastIndex = 0;
  s = s.replace(INVISIBLE, '');
  if (!s) return null;

  const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s);
  if (!explicitScheme) s = 'https://' + s.replace(/^\/\//, '');

  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  const asciiHost = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!asciiHost) return null;
  let rest = u.pathname + u.search + u.hash;
  try {
    rest = decodeURIComponent(rest);
  } catch {
    /* keep raw */
  }
  return {
    hostname: toUnicodeHost(asciiHost),
    asciiHost,
    protocol: u.protocol.toLowerCase(),
    username: u.username,
    password: u.password,
    port: u.port,
    pathAndQuery: rest.toLowerCase(),
    isIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(asciiHost) || asciiHost.startsWith('['),
    hasInvisibleChars,
    explicitScheme,
  };
}

export function extractHostname(input: string): string {
  const p = parseTarget(input);
  if (p) return p.hostname;
  return (input || '').replace(/^https?:\/\//i, '').split(/[/?#]/)[0].split(':')[0].toLowerCase();
}

// ---------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------

export function computeLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// Words that, glued to a brand name, make a classic phishing token ("paypal-secure", "sbibank", "applesupport").
const PHISH_AFFIX = new Set([
  'secure', 'security', 'login', 'signin', 'logon', 'support', 'verify', 'verification', 'account', 'accounts', 'id',
  'pay', 'payment', 'payments', 'help', 'care', 'update', 'service', 'services', 'kyc', 'bank', 'banking', 'online',
  'official', 'wallet', 'refund', 'reward', 'rewards', 'offer', 'offers', 'customer', 'customercare', 'app', 'web',
  'india', 'in', 'portal', 'netbanking', 'card', 'cards', 'upi', 'cashback', 'alert', 'alerts', 'recovery', 'unlock',
  'auth', 'center', 'centre', 'helpdesk', 'billing', 'invoice', 'team', 'mail', 'cloud', 'store', 'shop', 'prime',
]);

const SEVERE_TOKENS = new Set([
  'fake', 'false', 'phish', 'phishing', 'scam', 'scammer', 'hack', 'hacked', 'fraud', 'clone', 'rogue', 'spoofer',
  'steal', 'stealer', 'kyc', 'aadhaar', 'aadhar', 'unblock', 'suspend', 'suspended', 'deactivate', 'lottery',
  'cashback', 'winner', 'prize', 'otp', 'giveaway', 'airdrop', 'freebitcoin', 'dummy',
]);
const MEDIUM_TOKENS = new Set(['update', 'claim', 'bonus', 'reward', 'rewards', 'gift', 'pan', 'free', 'urgent', 'refund', 'lucky', 'offer']);
const CREDENTIAL_TOKENS = new Set(['login', 'signin', 'secure', 'verify', 'verification', 'support', 'account', 'accounts', 'banking', 'portal', 'auth', 'wallet', 'password', 'recover', 'recovery']);

function tokensOf(label: string): string[] {
  const raw = label.split(/[^a-z0-9\u0080-\uffff]+/).filter(Boolean);
  const out = new Set<string>(raw);
  for (const r of raw) for (const m of r.match(/[a-z]+|\d+/g) || []) out.add(m);
  return [...out];
}

/** Digit / look-alike-letter variants ("paypa1" -> paypal, "g00gle" -> google, "arnazon" -> amazon). */
function leetVariants(s: string): string[] {
  const base = s.replace(/0/g, 'o').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/\$/g, 's').replace(/vv/g, 'w').replace(/rn/g, 'm');
  return [...new Set([s, base.replace(/1/g, 'l'), base.replace(/1/g, 'i')])];
}

function foldHomoglyphs(s: string): string {
  let out = '';
  for (const ch of s) out += HOMOGLYPH_MAP[ch] ? HOMOGLYPH_MAP[ch].toLowerCase() : ch;
  return out;
}

function tokenMatchesKeyword(token: string, kw: string): boolean {
  for (const v of leetVariants(token)) {
    if (v === kw) return true;
    if (v.startsWith(kw) && PHISH_AFFIX.has(v.slice(kw.length))) return true;
    if (v.endsWith(kw) && PHISH_AFFIX.has(v.slice(0, v.length - kw.length))) return true;
  }
  return false;
}

interface BrandIndex {
  brand: OfficialBrand;
  sld: string;
  keywords: string[];
  weak: boolean;
}

const BRAND_INDEX: BrandIndex[] = OFFICIAL_BRANDS.map((brand) => {
  const sld = brand.officialDomain.split('.')[0];
  const kws = new Set<string>();
  for (const k of [sld, ...(brand.keywords || [])]) if (k && k.length >= 3) kws.add(k.toLowerCase());
  return { brand, sld, keywords: [...kws], weak: WEAK_BRANDS.has(brand.brand) };
});

// domain -> brand, for suffix lookups like youtube.com / www.youtube.com / m.youtube.com
const DOMAIN_MAP = new Map<string, OfficialBrand>();
for (const b of OFFICIAL_BRANDS) {
  for (const d of [b.officialDomain, ...(b.aliases || [])]) DOMAIN_MAP.set(d.toLowerCase(), b);
}

/** Find the official brand owning this host (the host itself or any parent domain of it). */
export function findOfficialBrand(host: string): { brand: OfficialBrand; matchedDomain: string } | null {
  const labels = host.toLowerCase().split('.');
  for (let i = 0; i <= labels.length - 2; i++) {
    const cand = labels.slice(i).join('.');
    const hit = DOMAIN_MAP.get(cand);
    if (hit) return { brand: hit, matchedDomain: cand };
  }
  return null;
}

function hostMatches(host: string, domain: string): boolean {
  return host === domain || host.endsWith('.' + domain);
}

export interface DomainAnalysisResult {
  hostname: string;
  originalInput: string;
  isOfficial: boolean;
  officialBrand?: OfficialBrand;
  isTyposquat: boolean;
  targetBrand?: OfficialBrand;
  detectedHomoglyphs: { char: string; codePoint: string; replaces: string }[];
  normalizedHost: string;
  hasRiskyTld: boolean;
  isBlocked: boolean;
  isIpAddress: boolean;
  hasSuspiciousSubdomain: boolean;
  subdomainDeceptionBrand?: string;
  verdict: 'SAFE' | 'DANGEROUS' | 'SUSPICIOUS' | 'UNVERIFIED';
  score: number;
  reasons: string[];
  /** Registered (eTLD+1) domain of the host. */
  registrableDomain?: string;
  /** Genuine platform whose pages anyone can create (Google Sites / Docs, GitHub Pages ...). */
  isUserContentHost?: boolean;
}

function emptyResult(rawInput: string, hostname: string, reasons: string[], score: number, verdict: DomainAnalysisResult['verdict']): DomainAnalysisResult {
  return {
    hostname,
    originalInput: rawInput,
    isOfficial: false,
    isTyposquat: false,
    detectedHomoglyphs: [],
    normalizedHost: hostname,
    hasRiskyTld: false,
    isBlocked: false,
    isIpAddress: false,
    hasSuspiciousSubdomain: false,
    verdict,
    score,
    reasons,
  };
}

// ---------------------------------------------------------------------------------------
// Main analysis
// ---------------------------------------------------------------------------------------

export function analyzeDomain(rawInput: string): DomainAnalysisResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return emptyResult('', '', ['No target provided.'], 50, 'UNVERIFIED');
  }

  const parsed = parseTarget(rawInput);
  if (!parsed) {
    const fallbackHost = extractHostname(rawInput);
    return emptyResult(rawInput, fallbackHost, ['This text could not be read as a valid web address.', 'Unverified third-party link. Treat it with suspicion.'], 60, 'SUSPICIOUS');
  }

  const host = parsed.hostname;
  const labels = host.split('.');
  const reasons: string[] = [];
  let score = 0;

  // 1. Blocklist (host or its registered domain)
  const reg = registrableDomain(host);
  const regAscii = registrableDomain(parsed.asciiHost);
  const isBlocked = BLOCKLIST_DOMAINS.has(host) || BLOCKLIST_DOMAINS.has(reg) || BLOCKLIST_DOMAINS.has(regAscii);
  if (isBlocked) {
    const matchedBrand = BRAND_INDEX.find((bi) => bi.keywords.some((k) => host.includes(k)))?.brand;
    return {
      ...emptyResult(rawInput, host, ['CRITICAL: Domain is flagged on cybercrime threat lists as a malicious phishing host.'], 100, 'DANGEROUS'),
      isTyposquat: true,
      targetBrand: matchedBrand,
      isBlocked: true,
      registrableDomain: reg,
    };
  }

  // 2. Hidden characters / userinfo trick (https://paypal.com@evil.com)
  const userinfo = parsed.username || parsed.password;
  let deceptiveUserinfo = false;
  if (parsed.hasInvisibleChars) {
    score += 60;
    reasons.push('HIDDEN CHARACTERS: The link contains invisible characters, a trick used to disguise the real address.');
  }
  if (userinfo) {
    const looksLikeDomain = /[a-z0-9-]+\.[a-z]{2,}/i.test(`${parsed.username}${parsed.password}`);
    if (looksLikeDomain) {
      deceptiveUserinfo = true;
      score += 95;
      reasons.push(`DECEPTIVE LINK: The text before the "@" ("${parsed.username}") looks like a website, but the link really goes to ${host}.`);
    } else {
      score += 50;
      reasons.push('The link embeds a username/password before the host name, which legitimate sites almost never do.');
    }
  }

  // 3. Official registry (zero-trust: the ONLY path to SAFE)
  const isUserContent = USER_CONTENT_HOSTS.some((h) => hostMatches(host, h));
  const official = !userinfo && !parsed.hasInvisibleChars && !isUserContent ? findOfficialBrand(host) : null;
  if (official) {
    const sub = host !== official.matchedDomain && host !== official.brand.officialDomain;
    const okReasons = [
      `Verified official domain of ${official.brand.brand} (${official.brand.category}). ${host} belongs to ${official.matchedDomain}${sub ? ', which owns this subdomain' : ''}.`,
    ];
    if (parsed.explicitScheme && parsed.protocol === 'http:') okReasons.push('Note: this link uses plain http (not encrypted). The real site normally switches to https automatically.');
    return {
      hostname: host,
      originalInput: rawInput,
      isOfficial: true,
      officialBrand: official.brand,
      isTyposquat: false,
      detectedHomoglyphs: [],
      normalizedHost: host,
      hasRiskyTld: false,
      isBlocked: false,
      isIpAddress: false,
      hasSuspiciousSubdomain: false,
      verdict: 'SAFE',
      score: 0,
      reasons: okReasons,
      registrableDomain: reg,
    };
  }

  // Government / education suffixes that only qualifying bodies can register.
  if (!userinfo && !parsed.hasInvisibleChars && !parsed.isIp && !isUserContent) {
    const restricted = RESTRICTED_SUFFIXES.find((r) => host.endsWith('.' + r.suffix));
    if (restricted && labels.length > restricted.suffix.split('.').length) {
      const synth: OfficialBrand = { brand: restricted.label, officialDomain: reg, category: restricted.suffix.startsWith('ac.') || restricted.suffix.startsWith('edu') ? 'Education & Reference' : 'Government' };
      return {
        hostname: host,
        originalInput: rawInput,
        isOfficial: true,
        officialBrand: synth,
        isTyposquat: false,
        detectedHomoglyphs: [],
        normalizedHost: host,
        hasRiskyTld: false,
        isBlocked: false,
        isIpAddress: false,
        hasSuspiciousSubdomain: false,
        verdict: 'SAFE',
        score: 0,
        reasons: [`Verified: .${restricted.suffix} domains can only be registered by qualifying organisations (${restricted.label}).`],
        registrableDomain: reg,
      };
    }
  }

  // 4. Homoglyph / IDN inspection (on the decoded, human-visible host)
  const detectedHomoglyphs: DomainAnalysisResult['detectedHomoglyphs'] = [];
  let normalizedHost = '';
  for (const label of labels) {
    const chars = Array.from(label);
    const hasLatin = chars.some((c) => /[a-z]/.test(c));
    const lookalikes = chars.filter((c) => HOMOGLYPH_MAP[c]);
    const everyCharLookalike = chars.length > 0 && chars.every((c) => HOMOGLYPH_MAP[c] || /[0-9-]/.test(c));
    const strong = lookalikes.filter((c) => !WEAK_LOOKALIKES.has(c));
    const flagged = (hasLatin && lookalikes.length > 0) || (everyCharLookalike && strong.length > 0);
    for (const c of chars) {
      if (flagged && HOMOGLYPH_MAP[c]) {
        detectedHomoglyphs.push({ char: c, codePoint: `U+${(c.codePointAt(0) as number).toString(16).toUpperCase().padStart(4, '0')}`, replaces: HOMOGLYPH_MAP[c] });
      }
    }
    normalizedHost += (normalizedHost ? '.' : '') + (flagged ? foldHomoglyphs(label) : label);
  }
  if (detectedHomoglyphs.length > 0) {
    score += 95;
    reasons.push(`PUNYCODE / HOMOGLYPH ATTACK: Contains ${detectedHomoglyphs.length} look-alike character(s) (e.g. Cyrillic or Greek) disguising Latin letters.`);
  } else if (/[^\x00-\x7f]/.test(host)) {
    score += 30;
    reasons.push('Internationalised (non-English) domain name. Genuine in many cases, but double-check the exact spelling.');
  }
  if (parsed.asciiHost.includes('xn--') && detectedHomoglyphs.length === 0 && !/[^\x00-\x7f]/.test(host)) {
    score += 30;
    reasons.push('Contains Punycode (xn--) encoding that could not be decoded, often used to disguise counterfeit characters.');
  }

  // 5. IP address
  const isIpAddress = parsed.isIp;
  if (isIpAddress) {
    score += 90;
    reasons.push('Raw numeric IP address used instead of a registered domain name (common vector for credential harvesting).');
  }

  // 6. TLD
  const tld = labels[labels.length - 1] || '';
  const hasRiskyTld = !isIpAddress && RISKY_TLDS.has(tld);
  if (hasRiskyTld) {
    const dual = DUAL_USE_TLDS.has(tld);
    score += dual ? 25 : 50;
    reasons.push(dual ? `Uses the .${tld} extension, which is common on legitimate sites but also frequently abused for phishing.` : `Uses high-risk top-level domain (.${tld}) heavily abused in automated phishing campaigns.`);
  }

  // 7. Which labels do we inspect for brand names? Skip the TLD, and skip the platform name on shared hosts.
  const regLabels = reg.split('.');
  const subLabels = labels.slice(0, Math.max(0, labels.length - regLabels.length));
  const onSharedPlatform = SHARED_PLATFORMS.has(reg) || SHARED_PLATFORMS.has(regAscii) || [...SHARED_PLATFORMS].some((p) => hostMatches(host, p));
  const sldLabel = regLabels[0] || '';
  const inspected = onSharedPlatform ? subLabels : [...subLabels, sldLabel];
  const allTokens = new Set<string>();
  for (const l of inspected) for (const t of tokensOf(foldHomoglyphs(l))) allTokens.add(t);
  const compactLabels = inspected.map((l) => foldHomoglyphs(l).replace(/[^a-z0-9]/g, ''));

  const hasSevere = [...allTokens].filter((t) => SEVERE_TOKENS.has(t));
  const hasMedium = [...allTokens].filter((t) => MEDIUM_TOKENS.has(t));
  const hasCredential = [...allTokens].filter((t) => CREDENTIAL_TOKENS.has(t));

  // 8. Brand impersonation (token based)
  let isTyposquat = false;
  let hasSuspiciousSubdomain = false;
  let subdomainDeceptionBrand: string | undefined;
  let targetBrand: OfficialBrand | undefined;
  let weakBrandNote: string | undefined;

  // On a user-content page of a genuine platform (docs.google.com ...), the platform's own name is not an impersonation.
  const ownerBrand = isUserContent ? findOfficialBrand(host)?.brand : undefined;

  const phishContext = hasSevere.length > 0 || hasMedium.length > 0 || hasCredential.length > 0 || hasRiskyTld || deceptiveUserinfo;

  outer: for (const bi of BRAND_INDEX) {
    if (ownerBrand && bi.brand === ownerBrand) continue;
    for (const kw of bi.keywords) {
      let matchedInSub = false;
      let matched = false;
      for (let idx = 0; idx < inspected.length; idx++) {
        const toks = tokensOf(foldHomoglyphs(inspected[idx]));
        const tokenHit = toks.some((t) => tokenMatchesKeyword(t, kw));
        const substrHit = kw.length >= 6 && leetVariants(compactLabels[idx]).some((v) => v.includes(kw));
        if (tokenHit || substrHit) {
          matched = true;
          if (!(idx === inspected.length - 1 && !onSharedPlatform)) matchedInSub = true;
        }
      }
      if (!matched) continue;

      if (bi.weak && !matchedInSub && !phishContext) {
        weakBrandNote = `The name "${bi.brand.brand}" appears in this address, but the site is not ${bi.brand.officialDomain}. It may be an unrelated business, so verify before trusting it.`;
        score += 30;
        continue; // keep looking; a stronger brand may still match
      }
      hasSuspiciousSubdomain = true;
      subdomainDeceptionBrand = bi.brand.brand;
      isTyposquat = true;
      targetBrand = bi.brand;
      score += 95;
      reasons.push(`SPOOFING ALERT: This address imitates ${bi.brand.brand} (${bi.brand.officialDomain}) but its real domain is ${reg}.`);
      break outer;
    }
  }
  if (weakBrandNote && !targetBrand) reasons.push(weakBrandNote);

  // 9. Typosquatting by edit distance on the registered name
  if (!targetBrand && !onSharedPlatform && sldLabel) {
    const sldVariants = new Set<string>([foldHomoglyphs(sldLabel), ...leetVariants(foldHomoglyphs(sldLabel))]);
    for (const bi of BRAND_INDEX) {
      if (ownerBrand && bi.brand === ownerBrand) continue;
      const target = bi.sld;
      if (target.length < 5 || sldLabel === target) continue;
      let hit = false;
      for (const v of sldVariants) {
        if (v === target) { hit = true; break; }
        if (bi.weak || target.length < 6) continue;
        const maxDist = target.length >= 9 ? 2 : 1;
        if (Math.abs(v.length - target.length) <= maxDist && computeLevenshtein(v, target) <= maxDist) { hit = true; break; }
      }
      if (hit) {
        isTyposquat = true;
        targetBrand = bi.brand;
        score += 90;
        reasons.push(`TYPOSQUATTING: "${sldLabel}" is a look-alike of "${target}" (${bi.brand.brand}).`);
        break;
      }
    }
  }

  // 10. Scam keywords (whole words only, so "hackerrank", "panasonic", "speedtest" are NOT flagged)
  if (hasSevere.length > 0) {
    score += 85;
    reasons.push(`MALICIOUS TRIGGER: Domain contains words typical of scam campaigns: "${hasSevere.join(', ')}".`);
  }
  if (hasMedium.length > 0) {
    score += 45;
    reasons.push(`Contains words often used in bait links: "${hasMedium.join(', ')}".`);
  }
  if (hasCredential.length > 0 && !targetBrand) {
    score += 45;
    reasons.push(`Contains high-value credential capture keywords: "${hasCredential.join(', ')}".`);
  }

  // 11. Brand in the URL path of an unrelated site (evil.com/paypal/login)
  if (!targetBrand && parsed.pathAndQuery.length > 1) {
    const pathBrand = BRAND_INDEX.find((bi) => bi.keywords.some((k) => k.length >= 6 && parsed.pathAndQuery.includes(k)));
    if (pathBrand && /(login|signin|verify|update|secure|account|kyc|otp|password|wallet)/.test(parsed.pathAndQuery)) {
      score += 40;
      reasons.push(`The page path mentions ${pathBrand.brand.brand} and a login/verification step, but the site is not ${pathBrand.brand.officialDomain}.`);
    }
  }

  // 12. Structure
  const hyphens = (sldLabel.match(/-/g) || []).length;
  if (hyphens >= 3) {
    score += 20;
    reasons.push('Domain name is stitched together from many hyphenated words, a common pattern in throw-away phishing domains.');
  }
  if (subLabels.length >= 4) {
    score += 20;
    reasons.push('Unusually deep chain of subdomains, sometimes used to push the real domain out of view.');
  }
  if (host.length > 60) {
    score += 15;
    reasons.push('Unusually long host name.');
  }
  if (parsed.explicitScheme && parsed.protocol === 'http:') {
    score += 15;
    reasons.push('Link is not encrypted (http instead of https).');
  }
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    score += 20;
    reasons.push(`Uses a non-standard port (${parsed.port}).`);
  }

  // 13. Shared-hosting / user-content notes
  if (isUserContent) {
    reasons.push(`This is a genuine ${reg} address, but it is a page anyone can create. The platform is real; the content may not be.`);
  } else if (onSharedPlatform) {
    reasons.push(`Hosted on a free public hosting platform (${reg}) where anyone can publish a page under any name.`);
  }
  if (SHORTENERS.has(reg) || SHORTENERS.has(host)) {
    reasons.push('Link shortener: the real destination is hidden until the link is followed.');
  }

  // Verdict. Only the registry can produce SAFE.
  let verdict: DomainAnalysisResult['verdict'] = 'UNVERIFIED';
  if (score >= 65 || isTyposquat || detectedHomoglyphs.length > 0 || isIpAddress || hasSevere.length > 0 || deceptiveUserinfo) {
    verdict = 'DANGEROUS';
    score = Math.max(score, 85);
  } else if (score >= 30 || hasRiskyTld || hasCredential.length > 0 || hasMedium.length > 0) {
    verdict = 'SUSPICIOUS';
    score = Math.max(score, 60);
  } else {
    verdict = 'UNVERIFIED';
    score = Math.max(55, score);
    reasons.push('Unverified third-party domain. It is not in the verified registry of official sites, and no phishing signals were found in the address itself.');
  }

  return {
    hostname: host,
    originalInput: rawInput,
    isOfficial: false,
    isTyposquat,
    targetBrand,
    detectedHomoglyphs,
    normalizedHost,
    hasRiskyTld,
    isBlocked,
    isIpAddress,
    hasSuspiciousSubdomain,
    subdomainDeceptionBrand,
    verdict,
    score: Math.min(100, Math.max(0, score)),
    reasons,
    registrableDomain: reg,
    isUserContentHost: isUserContent || undefined,
  };
}
