import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Copy,
  CheckCircle2,
  X,
  Building2,
  Globe,
  ArrowRight,
  Layers,
  Zap,
  ChevronDown,
  ChevronUp,
  Sparkles,
  AlertOctagon,
  CalendarClock,
  Bot
} from 'lucide-react';
import { ThreatAnalysisResult, formatDomainAge } from '../lib/engine.ts';
import { Translations, TRANSLATIONS } from '../lib/translations.ts';

interface ResultModalProps {
  result: ThreatAnalysisResult | null;
  isOpen: boolean;
  onClose: () => void;
  t?: Translations;
}

export const ResultModal: React.FC<ResultModalProps> = ({
  result,
  isOpen,
  onClose,
  t = TRANSLATIONS.en,
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);

  if (!isOpen || !result) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(result.target);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isDanger = result.verdict === 'DANGER';
  const isCaution = result.verdict === 'CAUTION';
  const isSafe = result.verdict === 'SAFE';

  // Formatted timestamp
  const formattedTime = new Date(result.timestamp).toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  const m = t.resultModal;

  // One card per registrable domain, never the same domain twice.
  const domainAges = (result.domainAges ?? []).filter(
    (a, i, arr) => arr.findIndex((b) => (b.domain || b.host) === (a.domain || a.host)) === i
  );

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/75 backdrop-blur-xs animate-fade-in"
    >
      {/* Reduced compact modal container */}
      <div
        className={`relative w-full max-w-lg bg-white rounded-2xl sm:rounded-3xl shadow-2xl overflow-hidden border transition-all transform scale-100 ${
          isDanger
            ? 'animate-danger-vibrate border-red-500 shadow-[0_0_50px_rgba(220,38,38,0.4)]'
            : isCaution
              ? 'animate-caution-pulse border-amber-400 shadow-[0_0_30px_rgba(217,119,6,0.3)]'
              : 'animate-safe-radiance border-emerald-400 shadow-[0_0_30px_rgba(5,150,105,0.25)]'
        }`}
      >
        {/* Top Header Banner - Sleeker, tighter padding */}
        <div
          className={`p-4 sm:p-5 text-white transition-colors relative overflow-hidden ${
            isDanger
              ? 'bg-gradient-to-r from-[#dc2626] via-[#b91c1c] to-[#991b1b]'
              : isCaution
                ? 'bg-gradient-to-r from-[#d97706] to-[#b45309]'
                : 'bg-gradient-to-r from-[#059669] to-[#047857]'
          }`}
        >
          {isDanger && (
            <div className="absolute -top-10 -right-10 w-36 h-36 rounded-full bg-white/10 animate-pulse-ring pointer-events-none" />
          )}

          {/* Top Row: Icon, Badges, Close Button */}
          <div className="flex items-center justify-between gap-2.5 mb-3 relative z-10">
            <div className="flex items-center gap-2">
              <div className="w-9 h-9 rounded-xl bg-white/20 backdrop-blur-xs flex items-center justify-center text-white border border-white/30 shadow-inner shrink-0">
                {isDanger && <ShieldAlert className="w-5 h-5 animate-pulse text-white" />}
                {isCaution && <AlertTriangle className="w-5 h-5 text-white" />}
                {isSafe && <ShieldCheck className="w-5 h-5 text-white" />}
              </div>

              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-black/30 backdrop-blur-xs text-white shadow-2xs">
                  {m.threatScore}: {result.riskScore}/100
                </span>
                <span className="text-[11px] font-bold px-2.5 py-0.5 rounded-full bg-black/30 backdrop-blur-xs text-white uppercase shadow-2xs">
                  {result.category === 'UPI_VPA' ? 'UPI' : result.category === 'UPI_DEEP_LINK' ? 'UPI QR' : 'URL'}
                </span>
                <span className="hidden sm:inline-flex text-[10px] font-mono px-2 py-0.5 rounded-md bg-black/20 text-white/90">
                  <Zap className="w-3 h-3 inline mr-1 text-amber-300" />
                  {result.executionTimeMs}ms
                </span>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1 rounded-full hover:bg-white/25 text-white transition-transform active:scale-95 cursor-pointer shrink-0"
              aria-label="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Verdict Title */}
          <div className="relative z-10">
            <h2 className="text-xl sm:text-2xl font-black tracking-tight mb-1.5 drop-shadow-xs flex items-center gap-2">
              {isDanger ? m.dangerousTitle : isCaution ? m.cautionTitle : m.safeTitle}
            </h2>

            {/* Plain-Language Verdict */}
            <p className="text-xs sm:text-sm font-medium text-white/95 leading-snug">
              {result.plainEnglishVerdict}
            </p>
          </div>

          {/* Score Bar */}
          <div className="w-full bg-black/25 rounded-full h-1.5 mt-3 overflow-hidden relative z-10">
            <div
              className={`h-full transition-all duration-700 ease-out rounded-full ${
                isDanger ? 'bg-red-200' : isCaution ? 'bg-amber-200' : 'bg-emerald-200'
              }`}
              style={{ width: `${Math.max(6, result.riskScore)}%` }}
            />
          </div>
        </div>

        {/* Modal Body - Compact, sleek scroll container */}
        <div className="p-4 sm:p-5 space-y-3.5 max-h-[58vh] overflow-y-auto">
          {/* Inspected Target Box */}
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl transition-all hover:border-slate-300">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] font-bold uppercase tracking-wider text-rose-600 flex items-center gap-1">
                <span>{m.inspectedTarget}</span>
              </span>
              <button
                onClick={handleCopy}
                className="inline-flex items-center gap-1 text-[11px] text-rose-600 hover:text-rose-700 font-semibold transition-colors cursor-pointer px-1.5 py-0.5 rounded hover:bg-rose-50"
              >
                {copied ? <CheckCircle2 className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? m.copied : m.copy}</span>
              </button>
            </div>
            <p className="font-mono text-xs sm:text-sm font-bold text-slate-900 break-all select-all">
              {result.target}
            </p>
          </div>

          {/* Metric Badges Row */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold border border-rose-200 text-rose-700 bg-rose-50">
              <Building2 className="w-3 h-3" />
              <span>{result.category.startsWith('UPI') ? 'NPCI Protocol' : 'SSL Protocol'}</span>
            </span>

            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold border border-emerald-300 text-emerald-700 bg-emerald-50">
              <CheckCircle2 className="w-3 h-3" />
              <span>{result.upiDetails?.bankName || result.domainDetails?.officialBrand?.brand || 'Verified Safe Check'}</span>
            </span>
          </div>

          {/* LLM WARNING: for every DANGER / CAUTION link, say which site it is pretending to be or referring to */}
          {(isDanger || isCaution) && result.category === 'URL' && (() => {
            const llm = result.llmImpersonation;
            const rule = result.domainDetails;
            const llmRan = !!llm && llm.available;
            const fakeOfLlm = !!(llm?.isImpersonation && llm.officialDomain);
            const refOfLlm = !fakeOfLlm && !!llm?.referencedDomain;
            const fakeOfRule = !fakeOfLlm && !refOfLlm && !!rule && !rule.isOfficial && !!rule.targetBrand;

            const fakeHost = llm?.host || rule?.hostname || result.target;
            let kind: 'FAKE' | 'REFERS' | 'RULE' | 'NONE';
            let realSite = '';
            let brand: string | undefined;
            if (fakeOfLlm) { kind = 'FAKE'; realSite = llm!.officialDomain!; brand = llm!.impersonatedBrand; }
            else if (refOfLlm) { kind = 'REFERS'; realSite = llm!.referencedDomain!; brand = llm!.referencedBrand; }
            else if (fakeOfRule) { kind = 'RULE'; realSite = rule!.targetBrand!.officialDomain; brand = rule!.targetBrand!.brand; }
            else kind = 'NONE';

            const red = kind === 'FAKE' || kind === 'RULE';
            // Only call it an "LLM" warning when the LLM actually produced the finding.
            const byLlm = kind === 'FAKE' || kind === 'REFERS' || (kind === 'NONE' && llmRan);
            const title =
              kind === 'FAKE' ? 'LLM WARNING: fake link'
              : kind === 'REFERS' ? 'LLM WARNING: link refers to another site'
              : kind === 'RULE' ? 'WARNING: fake link (rule-based, LLM did not confirm)'
              : llmRan ? 'LLM WARNING: unverified link'
              : 'WARNING: unverified link (LLM check unavailable)';

            return (
              <div className={`rounded-xl overflow-hidden border-2 ${red ? 'border-red-500 shadow-[0_0_18px_rgba(220,38,38,0.35)]' : 'border-amber-500 shadow-[0_0_18px_rgba(217,119,6,0.3)]'}`}>
                <div className={`px-3 py-2 text-white flex items-center justify-between gap-2 ${red ? 'bg-gradient-to-r from-red-600 to-red-800' : 'bg-gradient-to-r from-amber-500 to-amber-700'}`}>
                  <span className="text-[11px] font-black uppercase tracking-wider flex items-center gap-1.5">
                    <Bot className="w-4 h-4 shrink-0" />
                    <span>{title}</span>
                  </span>
                  <span className={`text-[10px] font-black px-2 py-0.5 rounded-full bg-white shrink-0 ${red ? 'text-red-700' : 'text-amber-700'}`}>
                    {byLlm ? 'LLM' : 'AUTO'}
                    {byLlm && typeof llm?.confidence === 'number' ? ` · ${Math.round(llm.confidence * 100)}%` : ''}
                  </span>
                </div>
                <div className={`p-3 ${red ? 'bg-rose-50' : 'bg-amber-50'}`}>
                  {kind !== 'NONE' ? (
                    <>
                      <p className="text-sm font-bold text-slate-900 mb-2">
                        {kind === 'REFERS' ? 'This link refers to ' : 'This link is pretending to be '}
                        <mark className={`px-1.5 py-0.5 rounded font-black ${red ? 'bg-red-200 text-red-900' : 'bg-amber-200 text-amber-900'}`}>
                          {brand ? `${brand} (${realSite})` : realSite}
                        </mark>
                        {kind === 'REFERS' ? '' : '!'}
                      </p>
                      <div className="flex flex-wrap items-center gap-2 mb-2">
                        <div className="px-2.5 py-1.5 bg-white rounded-lg border-2 border-red-400">
                          <span className="text-[9px] font-black uppercase text-red-600 block">{kind === 'REFERS' ? 'This link' : 'Fake link'}</span>
                          <span className="font-mono text-sm font-black text-red-700 break-all">{fakeHost}</span>
                        </div>
                        <ArrowRight className="w-4 h-4 text-red-500 shrink-0" />
                        <div className="px-2.5 py-1.5 bg-emerald-100 rounded-lg border-2 border-emerald-500">
                          <span className="text-[9px] font-black uppercase text-emerald-700 block">Real official site</span>
                          <span className="font-mono text-sm font-black text-emerald-800 break-all">{realSite}</span>
                        </div>
                      </div>
                      {byLlm && llm?.explanation && <p className="text-xs text-slate-700">{llm.explanation}</p>}
                      <p className={`text-[11px] font-semibold mt-1.5 ${red ? 'text-red-700' : 'text-amber-800'}`}>
                        Do not trust this link. Type <span className="font-mono">{realSite}</span> yourself instead.
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-sm font-bold text-slate-900 mb-1">
                        {llmRan ? 'The LLM could not match this link to any known site.' : 'The LLM check could not run for this link.'}
                      </p>
                      <p className="font-mono text-sm font-black text-amber-800 break-all mb-1">{fakeHost}</p>
                      <p className="text-[11px] font-semibold text-amber-800">
                        {isDanger ? 'Other checks flagged this link as dangerous. Do not open it.' : 'This link could not be verified as official. Open it only if you trust the sender.'}
                      </p>
                    </>
                  )}
                </div>
              </div>
            );
          })()}

          {/* Domain age for every host on the path (live registry data) */}
          {domainAges.length > 0 && (
            <div className="rounded-xl overflow-hidden border-2 border-indigo-400 shadow-[0_0_14px_rgba(79,70,229,0.2)]">
              <div className="px-3 py-1.5 bg-gradient-to-r from-indigo-600 to-indigo-800 text-white text-[11px] font-black uppercase tracking-wider flex items-center gap-1.5">
                <CalendarClock className="w-4 h-4" />
                <span>Domain age</span>
              </div>
              <div className="p-2 bg-indigo-50 space-y-1.5">
                {domainAges.map((a, i) => {
                  const known = typeof a.ageDays === 'number' && !!a.registeredAt;
                  const tier = !known ? 'UNKNOWN' : a.ageDays! < 30 ? 'NEW' : a.ageDays! < 90 ? 'RECENT' : a.ageDays! < 365 ? 'YOUNG' : 'ESTABLISHED';
                  const tone =
                    tier === 'NEW'
                      ? 'bg-rose-100 border-rose-400'
                      : tier === 'ESTABLISHED'
                        ? 'bg-emerald-50 border-emerald-400'
                        : 'bg-amber-50 border-amber-400';
                  const badge =
                    tier === 'NEW'
                      ? ['bg-rose-600', 'NEWLY REGISTERED']
                      : tier === 'RECENT'
                        ? ['bg-amber-500', 'RECENT']
                        : tier === 'YOUNG'
                          ? ['bg-amber-500', 'UNDER 1 YEAR']
                          : tier === 'ESTABLISHED'
                            ? ['bg-emerald-600', 'ESTABLISHED']
                            : ['bg-slate-500', 'NOT AVAILABLE'];
                  const dateText = known
                    ? (() => {
                        const d = new Date(a.registeredAt!);
                        const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getUTCMonth()];
                        return `${String(d.getUTCDate()).padStart(2, '0')} ${mon} ${d.getUTCFullYear()}`;
                      })()
                    : '';
                  return (
                    <div key={i} className={`p-2.5 rounded-lg border-2 ${tone}`}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-bold text-slate-800 break-all">{a.domain || a.host}</span>
                        <span className={`text-[9px] font-black px-2 py-0.5 rounded-full text-white shrink-0 ${badge[0]}`}>{badge[1]}</span>
                      </div>
                      {known ? (
                        <div className="mt-1 flex flex-wrap items-baseline gap-x-3">
                          <span className="text-lg font-black text-slate-900">{formatDomainAge(a.registeredAt!)} old</span>
                          <span className="text-xs text-slate-700">
                            Registered on <span className="font-bold">{dateText}</span> ({a.ageDays!.toLocaleString()} days)
                          </span>
                        </div>
                      ) : (
                        <p className="text-xs text-slate-700 mt-1">
                          {a.notFound ? 'No registration record found: this domain may not exist.' : 'Registration date could not be retrieved right now.'}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Homoglyph Character Highlighter Card if Cyrillic or Spoofed glyphs present */}
          {result.domainDetails?.detectedHomoglyphs && result.domainDetails.detectedHomoglyphs.length > 0 && (
            <div className="p-3 bg-rose-50 border border-red-300 rounded-xl">
              <div className="flex items-center gap-1.5 mb-1.5 text-red-700 font-bold text-[11px] uppercase tracking-wider">
                <AlertOctagon className="w-3.5 h-3.5 text-red-600 animate-pulse" />
                <span>Punycode &amp; Homoglyph Spoofing Detected</span>
              </div>
              <p className="text-[11px] text-slate-700 mb-2">
                This URL replaces standard Latin letters with identical-looking Cyrillic characters:
              </p>
              <div className="flex flex-wrap gap-1.5">
                {result.domainDetails.detectedHomoglyphs.map((h, i) => (
                  <div
                    key={i}
                    className="p-1.5 bg-white rounded-lg border border-red-200 shadow-2xs flex items-center gap-1.5 text-[11px]"
                  >
                    <span className="px-1.5 py-0.5 bg-red-100 text-red-700 font-mono font-bold rounded text-xs border border-red-300">
                      {h.char}
                    </span>
                    <ArrowRight className="w-2.5 h-2.5 text-red-400" />
                    <span className="px-1 py-0.5 bg-emerald-100 text-emerald-800 font-mono font-bold rounded">
                      '{h.replaces}'
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Decoded Parameters Section (UPI or Domain) */}
          {result.upiDetails ? (
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-rose-600 flex items-center gap-1">
                  <Building2 className="w-3 h-3" />
                  <span>{m.decodedParamsUpi}</span>
                </span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    result.upiDetails.isRecognizedPsp
                      ? 'border-emerald-300 text-emerald-700 bg-emerald-50'
                      : 'border-rose-300 text-rose-700 bg-rose-50'
                  }`}
                >
                  {result.upiDetails.isRecognizedPsp ? m.recognizedPartner : m.unauthorizedHandle}
                </span>
              </div>

              {/* 2x2 Grid */}
              <div className="grid grid-cols-2 gap-2">
                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[9px] font-bold uppercase text-rose-600 block mb-0.5">
                    {m.payeeUsername}
                  </span>
                  <span className="font-mono text-xs font-bold text-slate-800 break-all line-clamp-1">
                    {result.upiDetails.username}
                  </span>
                </div>

                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[9px] font-bold uppercase text-rose-600 block mb-0.5">
                    {m.bankHandle}
                  </span>
                  <span
                    className={`font-mono text-xs font-bold break-all line-clamp-1 ${
                      result.upiDetails.isRecognizedPsp ? 'text-emerald-700' : 'text-rose-700'
                    }`}
                  >
                    @{result.upiDetails.handle}
                  </span>
                </div>

                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[9px] font-bold uppercase text-rose-600 block mb-0.5">
                    {m.bankPartner}
                  </span>
                  <span className="text-xs font-bold text-slate-800 line-clamp-1">
                    {result.upiDetails.bankName || 'Unknown Bank'}
                  </span>
                </div>

                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[9px] font-bold uppercase text-rose-600 block mb-0.5">
                    {m.syntaxCheck}
                  </span>
                  <span className="text-xs font-bold text-emerald-700 line-clamp-1">
                    NPCI Syntax OK
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-rose-600 flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  <span>{m.decodedParamsUrl}</span>
                </span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                    isSafe
                      ? 'border-emerald-300 text-emerald-700 bg-emerald-50'
                      : isDanger
                        ? 'border-rose-300 text-rose-700 bg-rose-50'
                        : 'border-amber-300 text-amber-700 bg-amber-50'
                  }`}
                >
                  {isSafe ? 'Authentic Domain' : isDanger ? 'Phishing Vector' : 'Unverified'}
                </span>
              </div>

              {/* 2x2 Grid for URL */}
              <div className="grid grid-cols-2 gap-2">
                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[9px] font-bold uppercase text-rose-600 block mb-0.5">
                    {m.targetDomain}
                  </span>
                  <span className="font-mono text-xs font-bold text-slate-800 break-all line-clamp-1">
                    {result.domainDetails?.hostname || result.target}
                  </span>
                </div>

                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[9px] font-bold uppercase text-rose-600 block mb-0.5">
                    {m.domainReputation}
                  </span>
                  <span
                    className={`text-xs font-bold line-clamp-1 ${
                      isSafe ? 'text-emerald-700' : isDanger ? 'text-rose-700' : 'text-amber-700'
                    }`}
                  >
                    {isSafe ? 'Verified Official' : isDanger ? 'Counterfeit' : 'Unrated'}
                  </span>
                </div>

                <div className={`p-2.5 bg-slate-50 border border-slate-200 rounded-xl ${domainAges.length > 0 ? 'col-span-2' : ''}`}>
                  <span className="text-[9px] font-bold uppercase text-rose-600 block mb-0.5">
                    {m.homoglyphCheck}
                  </span>
                  <span className="text-xs font-bold text-slate-800 line-clamp-1">
                    {result.domainDetails?.detectedHomoglyphs.length
                      ? `${result.domainDetails.detectedHomoglyphs.length} Cyrillic Char`
                      : 'Clean ASCII'}
                  </span>
                </div>

                {domainAges.length === 0 && (
                <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-xl">
                  <span className="text-[9px] font-bold uppercase text-rose-600 block mb-0.5">
                    {m.domainAge}
                  </span>
                  <span className="text-xs font-bold text-slate-800 line-clamp-1">
                    {result.domainAge
                      ? formatDomainAge(result.domainAge.registeredAt)
                      : result.domainAgeDays !== undefined
                        ? `${result.domainAgeDays} Day${result.domainAgeDays === 1 ? '' : 's'} Old`
                        : 'Not verified'}
                  </span>
                </div>
                )}
              </div>
            </div>
          )}

          {/* UPI payee name vs shop name */}
          {result.payeeCheck && (
            <div
              className={`p-3 rounded-xl border ${
                result.payeeCheck.level === 'MISMATCH'
                  ? 'bg-rose-50 border-rose-300'
                  : result.payeeCheck.level === 'PARTIAL'
                    ? 'bg-amber-50 border-amber-300'
                    : 'bg-emerald-50 border-emerald-300'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1">
                  <Building2 className="w-3 h-3" />
                  <span>Payee name vs shop name</span>
                </span>
                <span
                  className={`text-[10px] font-black px-2 py-0.5 rounded-full text-white ${
                    result.payeeCheck.level === 'MISMATCH'
                      ? 'bg-rose-600'
                      : result.payeeCheck.level === 'PARTIAL'
                        ? 'bg-amber-500'
                        : 'bg-emerald-600'
                  }`}
                >
                  {result.payeeCheck.level === 'MISMATCH'
                    ? 'DOES NOT MATCH'
                    : result.payeeCheck.level === 'PARTIAL'
                      ? 'PARTIAL MATCH'
                      : 'MATCHES'}{' '}
                  · {result.payeeCheck.similarity}%
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2 bg-white/80 border border-slate-200 rounded-lg">
                  <span className="text-[9px] font-bold uppercase text-slate-500 block">Shop (board)</span>
                  <span className="font-bold text-slate-800 break-words">{result.payeeCheck.shopName}</span>
                </div>
                <div className="p-2 bg-white/80 border border-slate-200 rounded-lg">
                  <span className="text-[9px] font-bold uppercase text-slate-500 block">
                    Payee ({result.payeeCheck.source === 'QR' ? 'from QR' : 'from your UPI app'})
                  </span>
                  <span className="font-bold text-slate-800 break-words">{result.payeeCheck.payeeName}</span>
                </div>
              </div>
            </div>
          )}
          {result.payeeCheckSkipped && (
            <div className="p-3 rounded-xl border border-amber-300 bg-amber-50 text-xs text-amber-900">
              <span className="font-black uppercase tracking-wider block text-[10px]">Shop name check incomplete</span>
              This QR carries no payee name. Type the name your UPI app shows after scanning into the “Name shown in your UPI app” box and verify again.
            </div>
          )}

          {/* Final destination score: where the link actually lands */}
          {result.finalDestination && (
            <div
              className={`p-3 rounded-xl border ${
                result.finalDestination.verdict === 'DANGER'
                  ? 'bg-rose-50 border-rose-300'
                  : result.finalDestination.verdict === 'CAUTION'
                    ? 'bg-amber-50 border-amber-300'
                    : 'bg-emerald-50 border-emerald-300'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  <span>
                    {result.finalDestination.redirected
                      ? `Final destination (after ${result.finalDestination.hopCount - 1} redirect${result.finalDestination.hopCount - 1 === 1 ? '' : 's'})`
                      : 'Final destination (no redirects)'}
                  </span>
                </span>
                <span
                  className={`text-[10px] font-black px-2 py-0.5 rounded-full text-white ${
                    result.finalDestination.verdict === 'DANGER'
                      ? 'bg-rose-600'
                      : result.finalDestination.verdict === 'CAUTION'
                        ? 'bg-amber-500'
                        : 'bg-emerald-600'
                  }`}
                >
                  {result.finalDestination.verdict} · {result.finalDestination.riskScore}/100
                </span>
              </div>
              <p className="font-mono text-[11px] font-semibold text-slate-800 break-all">
                {result.finalDestination.url}
              </p>
              <p className="text-[11px] text-slate-600 mt-1">{result.finalDestination.summary}</p>
            </div>
          )}

          {/* Redirect Chain Node Graph if Shortener */}
          {result.hasRedirectChain && (
            <div className="p-3 bg-rose-50/60 border border-rose-200 rounded-xl">
              <span className="text-[10px] font-bold uppercase tracking-wider text-rose-600 block mb-1.5 flex items-center gap-1">
                <Layers className="w-3 h-3" />
                <span>{m.redirectChain}</span>
              </span>
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-1.5 overflow-x-auto text-xs py-0.5">
                {result.redirectChain.map((node, i) => (
                  <React.Fragment key={i}>
                    <div
                      className={`p-2 rounded-lg border flex-1 min-w-[150px] ${
                        node.flagged
                          ? 'bg-white border-rose-300 text-rose-900'
                          : 'bg-white border-slate-200 text-slate-700'
                      }`}
                    >
                      <span className="text-[9px] font-bold uppercase block text-slate-500">
                        Hop {node.step}: {node.type}
                      </span>
                      <p className="font-mono text-[11px] font-semibold truncate mt-0.5">{node.url}</p>
                    </div>
                    {i < result.redirectChain.length - 1 && (
                      <ArrowRight className="w-3.5 h-3.5 text-rose-400 shrink-0 hidden sm:block" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* Expandable Technical Intelligence Breakdown */}
          <div className="border-t border-slate-100 pt-2.5">
            <button
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="w-full flex items-center justify-between text-xs font-bold text-slate-600 hover:text-slate-900 py-1 cursor-pointer transition-colors"
            >
              <span className="flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-rose-500" />
                <span>{m.auditSignals}</span>
              </span>
              {showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>

            {showTechnicalDetails && (
              <div className="mt-2 p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-1.5 animate-fade-in">
                <div className="flex items-center justify-between py-0.5 border-b border-slate-200/60 text-[11px]">
                  <span className="text-slate-500">Audit Policy:</span>
                  <span className="font-mono font-semibold text-slate-700">SHA-256 Anonymized</span>
                </div>
                <div className="flex items-center justify-between py-0.5 border-b border-slate-200/60 text-[11px]">
                  <span className="text-slate-500">{m.decisionSpeed}:</span>
                  <span className="font-mono font-semibold text-emerald-700">{result.executionTimeMs}ms (Real-Time)</span>
                </div>
                {result.reasons && result.reasons.length > 0 && (
                  <div className="pt-1">
                    <span className="text-slate-500 block mb-0.5 font-semibold text-[11px]">Signals:</span>
                    <ul className="space-y-0.5 text-[11px] text-slate-700 list-disc list-inside">
                      {result.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer - Compact */}
        <div className="px-4 sm:px-5 py-2.5 border-t border-slate-100 bg-slate-50/80 flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-400 font-semibold tracking-wider">
            {formattedTime}
          </span>

          <button
            onClick={onClose}
            className="group inline-flex items-center gap-1.5 px-4 sm:px-5 py-1.5 text-xs font-bold text-white bg-[#dc2626] hover:bg-[#b91c1c] active:bg-[#991b1b] rounded-full shadow-sm transition-all cursor-pointer"
          >
            <span>{m.dismissButton}</span>
            <ArrowRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
