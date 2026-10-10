import { verifyUpi } from '../src/lib/upi.ts';
import { analyzeDomain } from '../src/lib/domain.ts';
import { analyzeTarget, anonymizeUrlParameters, applyFinalDestination, applyDomainAge } from '../src/lib/engine.ts';

console.log('--- Testing NPCI UPI Verification ---');
const validUpi = verifyUpi('merchant@oksbi');
console.log('Valid SBI:', validUpi.verdict, validUpi.bankName);
if (validUpi.verdict !== 'SAFE') throw new Error('Valid UPI failed');

const fakeHandle = verifyUpi('test@nonexistentbankhandle');
console.log('Fake Handle:', fakeHandle.verdict, fakeHandle.reasons[0]);
if (fakeHandle.verdict !== 'DANGEROUS') throw new Error('Fake handle not caught');

const blockedUpi = verifyUpi('lotterywinner@okhdfcbank');
console.log('Blocked UPI:', blockedUpi.verdict, blockedUpi.score);
if (blockedUpi.verdict !== 'DANGEROUS') throw new Error('Blocked UPI not flagged dangerous');

console.log('\n--- Testing Domain & Homoglyph Engine ---');
const realGoogle = analyzeDomain('google.com');
console.log('Real Google:', realGoogle.verdict, realGoogle.score);
if (realGoogle.verdict !== 'SAFE') throw new Error('Real Google failed');

const typosquat = analyzeDomain('secure-hdfc-kyc.com');
console.log('Typosquat:', typosquat.verdict, typosquat.targetBrand?.brand);
if (typosquat.verdict !== 'DANGEROUS') throw new Error('Typosquat not caught');

const homoglyph = analyzeDomain('g\u043E\u043Egle.com');
console.log('Homoglyph attack:', homoglyph.verdict, homoglyph.detectedHomoglyphs.length);
if (homoglyph.detectedHomoglyphs.length === 0) throw new Error('Homoglyph not detected');

console.log('\n--- Testing Zero-Trust False QR Protection ---');
// 1. False QR code must NEVER be SAFE
const falseQr1 = analyzeTarget('https://false-qr.com/pay');
console.log('False QR (false-qr.com):', falseQr1.verdict, 'Score:', falseQr1.riskScore);
if (falseQr1.verdict === 'SAFE') throw new Error('False QR code was incorrectly marked SAFE!');

const falseQr2 = analyzeTarget('https://fake-login-bank.xyz');
console.log('False QR (fake-login-bank.xyz):', falseQr2.verdict, 'Score:', falseQr2.riskScore);
if (falseQr2.verdict !== 'DANGER') throw new Error('Fake login bank was not marked DANGER!');

const unverifiedSite = analyzeTarget('https://random-unknown-domain-123.com');
console.log('Unverified domain:', unverifiedSite.verdict, 'Score:', unverifiedSite.riskScore);
if (unverifiedSite.verdict === 'SAFE') throw new Error('Unverified domain was marked SAFE! Must be CAUTION.');

// 2. Anti-Collect trick
const collectScam = analyzeTarget('upi://pay?pa=scammer@oksbi&am=5000&tn=Receive%20Cashback%20Reward');
console.log('Collect Scam Verdict:', collectScam.verdict, 'Collect Trick:', collectScam.isCollectTrick);
if (!collectScam.isCollectTrick || collectScam.verdict !== 'DANGER') throw new Error('Anti-Collect trick failed to trigger');

// 3. SHA-256 parameter hashing anonymization
const sensitiveUrl = 'https://portal.bank.com/reset?token=secret123&phone=9876543210';
const anonymized = anonymizeUrlParameters(sensitiveUrl);
console.log('Anonymized URL:', anonymized);
if (anonymized.includes('secret123') || anonymized.includes('9876543210')) throw new Error('Sensitive query parameters not anonymized');

// 4. Shortener unroller graph
const shortened = analyzeTarget('https://bit.ly/sbi-urgent-update');
console.log('Shortened Hops:', shortened.redirectChain.length, 'Flagged:', shortened.hasRedirectChain);
if (!shortened.hasRedirectChain) throw new Error('Shortener redirect unroller failed');

// 5. Plain-English 1-Sentence Output check
console.log('Plain English Sentence:', shortened.plainEnglishVerdict);
if (!shortened.plainEnglishVerdict || typeof shortened.plainEnglishVerdict !== 'string') throw new Error('Missing plain-English verdict');

// 6. Existing verified UPI IDs and QR codes must be SAFE
const verifiedUpi = analyzeTarget('upi://pay?pa=store@oksbi&pn=Official%20Store');
console.log('Verified UPI QR (store@oksbi):', verifiedUpi.verdict, 'Score:', verifiedUpi.riskScore);
if (verifiedUpi.verdict !== 'SAFE') throw new Error('Existing verified UPI QR failed to show SAFE!');

const verifiedGPay = analyzeTarget('user@okhdfcbank');
console.log('Verified GPay (user@okhdfcbank):', verifiedGPay.verdict, 'Score:', verifiedGPay.riskScore);
if (verifiedGPay.verdict !== 'SAFE') throw new Error('Verified GPay handle failed to show SAFE!');

// 7. False UPI QR with unauthorized handle must be DANGER
const falseUpiQr = analyzeTarget('upi://pay?pa=scam@unauthorizedbank&pn=Fake');
console.log('False UPI QR with rogue handle:', falseUpiQr.verdict, 'Score:', falseUpiQr.riskScore);
if (falseUpiQr.verdict !== 'DANGER') throw new Error('False UPI QR was not flagged DANGER!');

// 8. Raw unknown QR code text must NEVER be marked SAFE
const rawTextQr = analyzeTarget('QR-CODE-RANDOM-PAYLOAD-99281');
console.log('Raw unknown QR payload:', rawTextQr.verdict, 'Score:', rawTextQr.riskScore);
if (rawTextQr.verdict === 'SAFE') throw new Error('Raw unknown QR payload was incorrectly marked SAFE!');

console.log('\nAll PhishLens security & Zero-Trust tests PASSED successfully!');

console.log('\n--- Testing Final Destination Scoring ---');
const shortLink = analyzeTarget('https://bit.ly/abc123');
const toPhish = applyFinalDestination(shortLink, {
  hops: [
    { url: 'https://bit.ly/abc123', status: 301 },
    { url: 'https://secure-hdfc-kyc.com/login', status: 200 },
  ],
  final: 'https://secure-hdfc-kyc.com/login',
});
console.log('Short link -> phishing page:', toPhish.verdict, toPhish.finalDestination?.verdict);
if (toPhish.verdict !== 'DANGER') throw new Error('Dangerous final destination not escalated');

const officialSite = analyzeTarget('https://sbi.co.in');
const officialToEvil = applyFinalDestination(officialSite, {
  hops: [
    { url: 'https://sbi.co.in', status: 302 },
    { url: 'https://evil-login.xyz/x', status: 200 },
  ],
  final: 'https://evil-login.xyz/x',
});
if (officialToEvil.verdict === 'SAFE') throw new Error('Safe link hiding a bad destination stayed SAFE');

const direct = applyFinalDestination(officialSite, { hops: [{ url: 'https://sbi.co.in', status: 200 }], final: 'https://sbi.co.in' });
if (direct.verdict !== 'SAFE' || direct.hasRedirectChain) throw new Error('Direct official link should stay SAFE');
console.log('Final destination scoring OK');

console.log('\n--- Testing Newly Registered Domain Detection ---');
const unknownSite = analyzeTarget('https://fresh-offers-portal.xyz/claim');
const fresh = applyDomainAge(unknownSite, [
  { host: 'fresh-offers-portal.xyz', domain: 'fresh-offers-portal.xyz', registeredAt: new Date(Date.now() - 3 * 86400000).toISOString(), ageDays: 3 },
]);
console.log('3-day-old domain:', fresh.verdict, fresh.isFreshDomain, fresh.domainAge?.tier);
if (fresh.verdict !== 'DANGER' || !fresh.isFreshDomain) throw new Error('Newly registered domain not escalated');

const recent = applyDomainAge(unknownSite, [
  { host: 'fresh-offers-portal.xyz', domain: 'fresh-offers-portal.xyz', registeredAt: new Date(Date.now() - 50 * 86400000).toISOString(), ageDays: 50 },
]);
if (recent.domainAge?.tier !== 'RECENT' || recent.verdict === 'SAFE') throw new Error('Recent domain tier wrong');

const oldOfficial = applyDomainAge(officialSite, [
  { host: 'sbi.co.in', domain: 'sbi.co.in', registeredAt: new Date(Date.now() - 20 * 86400000).toISOString(), ageDays: 20 },
]);
if (oldOfficial.verdict !== 'SAFE') throw new Error('Official brand must not be escalated on age');

const unknownAge = applyDomainAge(unknownSite, [{ host: 'x.xyz', domain: 'x.xyz', error: 'RDAP unreachable' }]);
if (unknownAge.domainAgeDays !== undefined) throw new Error('Unverified age must stay undefined, never guessed');
console.log('Domain age detection OK');

console.log('\n--- Testing UPI Payee vs Shop Name ---');
const swapped = analyzeTarget('upi://pay?pa=sharmasweets@okicici&pn=Rahul%20Verma&cu=INR', { shopName: 'Sharma Sweets' });
console.log('Payee != shop:', swapped.verdict, swapped.payeeCheck?.level, swapped.payeeCheck?.similarity);
if (swapped.verdict !== 'DANGER' || swapped.payeeCheck?.level !== 'MISMATCH') throw new Error('Payee/shop mismatch not flagged');

const genuine = analyzeTarget('upi://pay?pa=sharmasweets@okicici&pn=Sharma%20Sweet%20Mart&cu=INR', { shopName: 'Sharma Sweets' });
if (genuine.verdict !== 'SAFE' || genuine.payeeCheck?.level !== 'MATCH') throw new Error('Matching payee wrongly flagged');

const partial = analyzeTarget('upi://pay?pa=sharmasweets@okicici&pn=Sharma%20Rahul&cu=INR', { shopName: 'Sharma Sweets' });
if (partial.payeeCheck?.level !== 'PARTIAL' || partial.verdict !== 'CAUTION') throw new Error('Partial payee match should be CAUTION');

const appName = analyzeTarget('sharmasweets@okicici', { shopName: 'Sharma Sweets', shownPayeeName: 'RAHUL VERMA' });
if (appName.verdict !== 'DANGER' || appName.payeeCheck?.source !== 'PAYMENT_APP') throw new Error('Name shown by the payment app not compared');

const noName = analyzeTarget('sharmasweets@okicici', { shopName: 'Sharma Sweets' });
if (!noName.payeeCheckSkipped || noName.verdict === 'DANGER') throw new Error('Missing payee name should skip the check, not fail it');

const noShop = analyzeTarget('upi://pay?pa=sharmasweets@okicici&pn=Rahul%20Verma&cu=INR');
if (noShop.payeeCheck) throw new Error('No shop name given: payee check must not run');
console.log('Payee vs shop name OK');

console.log('\n--- Testing Verified Official Sites (regression: paypal.com / youtube.com showed Caution) ---');
const mustBeSafe = [
  'paypal.com', 'www.paypal.com', 'https://www.paypal.com/in/home', 'youtube.com', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
  'm.youtube.com', 'youtu.be/abc', 'https://accounts.google.com/signin', 'google.co.in', 'mail.google.com', 'github.com',
  'en.wikipedia.org/wiki/Phishing', 'www.amazon.in', 'www.flipkart.com', 'www.sbi.co.in', 'netbanking.hdfcbank.com',
  'www.icicibank.com/personal', 'https://www.incometax.gov.in', 'https://uidai.gov.in', 'https://irctc.co.in', 'https://www.nic.in',
  'https://pmindia.gov.in', 'https://www.iitb.ac.in', 'HTTPS://WWW.YOUTUBE.COM', 'https://youtube.com:443/', 'youtube.com.', 'www.instagram.com',
  'web.whatsapp.com', 'open.spotify.com', 'www.linkedin.com/in/someone', 'zoom.us/j/123', 'login.microsoftonline.com', 'www.zomato.com',
];
for (const u of mustBeSafe) {
  const r = analyzeTarget(u);
  if (r.verdict !== 'SAFE') throw new Error(`Official site ${u} was not SAFE: ${r.verdict} - ${r.plainEnglishVerdict}`);
}
console.log(`${mustBeSafe.length} official sites -> SAFE`);

// Official site that redirects to another official host (paypal.com -> www.paypal.com) must stay SAFE.
const ppBase = analyzeTarget('https://paypal.com');
const ppRedirected = applyFinalDestination(ppBase, {
  hops: [{ url: 'https://paypal.com/', status: 301 }, { url: 'https://www.paypal.com/in/home', status: 200 }],
  final: 'https://www.paypal.com/in/home',
});
if (ppRedirected.verdict !== 'SAFE') throw new Error('paypal.com -> www.paypal.com redirect must stay SAFE, got ' + ppRedirected.verdict);
const ytRedirected = applyFinalDestination(analyzeTarget('youtube.com'), {
  hops: [{ url: 'https://youtube.com/', status: 301 }, { url: 'https://www.youtube.com/', status: 200 }],
  final: 'https://www.youtube.com/',
});
if (ytRedirected.verdict !== 'SAFE') throw new Error('youtube.com redirect must stay SAFE');
const consent = applyFinalDestination(analyzeTarget('https://www.youtube.com'), {
  hops: [{ url: 'https://www.youtube.com/', status: 302 }, { url: 'https://consent.youtube.com/m?continue=x', status: 200 }],
  final: 'https://consent.youtube.com/m?continue=x',
});
if (consent.verdict !== 'SAFE') throw new Error('consent.youtube.com must be SAFE');
console.log('Redirects between official hosts stay SAFE');

console.log('\n--- Testing Impersonation Is Still Caught ---');
const mustBeDanger = [
  'paypal.com.evil.xyz', 'https://paypal.com@evil.com/login', 'paypa1.com', 'paypal-secure-login.com', 'paypall.com', 'youtube-login.xyz',
  'www.youtube.com.verify-account.top', 'amazonn.in', 'g\u043E\u043Egle.com', 'xn--ggle-55da.com', 'sbi.co.in.kyc-update.in', 'hdfc-netbanking-login.com',
  'apple-id-verify.in', 'http://192.168.1.5/login', 'secure-hdfc-kyc.com', 'paytm-cashback2026.click', 'login-microsoft.com', 'faceb00k.com',
  'whatsapp-gold-download.com', 'paypal-login.github.io', 'github.com.login-verify.com', 'www.google.com.account-recovery.xyz', 'netflix-payment-update.com',
];
for (const u of mustBeDanger) {
  const r = analyzeTarget(u);
  if (r.verdict !== 'DANGER') throw new Error(`Impersonation ${u} was not DANGER: ${r.verdict} - ${r.plainEnglishVerdict}`);
}
console.log(`${mustBeDanger.length} impersonation links -> DANGER`);

console.log('\n--- Testing Innocent Look-alikes Are NOT Flagged As Phishing ---');
const mustNotBeDanger = [
  'applebees.com', 'purchase.com', 'panasonic.com', 'hackerrank.com', 'speedtest.net', 'chaseandco.com', 'creditkarma.com',
  'citiesskylines.com', 'espn.com', 'example.com', 'stackoverflow.blog', 'amazonaws.com', 'random-unknown-domain-123.com', 'sites.google.com/view/my-site',
  'docs.google.com/forms/d/abc',
];
for (const u of mustNotBeDanger) {
  const r = analyzeTarget(u);
  if (r.verdict === 'DANGER') throw new Error(`Innocent domain ${u} wrongly DANGER: ${r.plainEnglishVerdict}`);
}
// ...but unknown / user-content hosts must never be SAFE (zero-trust)
for (const u of ['example.com', 'random-unknown-domain-123.com', 'sites.google.com/view/my-site', 'docs.google.com/forms/d/abc', 'amazonaws.com', 'someone.github.io']) {
  if (analyzeTarget(u).verdict === 'SAFE') throw new Error(`${u} must not be SAFE`);
}
console.log('Innocent look-alikes -> not DANGER');

console.log('\n--- Testing Category Detection ---');
if (analyzeTarget('hello there, free money.com').category !== 'TEXT') throw new Error('Sentence must be TEXT');
if (analyzeTarget('javascript:alert(1)').verdict !== 'DANGER') throw new Error('javascript: URI must be DANGER');
if (analyzeTarget('support@paypal.com').category === 'UPI_VPA') throw new Error('E-mail address must not be treated as UPI');
if (analyzeTarget('youtube.com').category !== 'URL') throw new Error('Bare domain must be URL');
if (analyzeTarget('youtube.com/watch?v=1').category !== 'URL') throw new Error('Domain with path must be URL');
console.log('Category detection OK');
console.log('\nAll v2 verification tests PASSED');
