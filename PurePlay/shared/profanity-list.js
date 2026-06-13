/**
 * PurePlay - Profanity Detection Word List v2
 * Includes realistic Speech-to-Text transcription variants
 * (how humans actually say these words, not how they're spelled)
 */

const PROFANITY_CATEGORIES = {
  SEVERE:   "severe",
  MODERATE: "moderate",
  MILD:     "mild",
};

// ─── English Profanity ────────────────────────────────────────────────────────
// variations = how STT actually transcribes human speech
const ENGLISH_PROFANITY_LIST = [
  {
    word: "fuck", category: "severe", lang: "en",
    variations: [
      "fucking", "fucked", "fucker", "fuckers", "fucks", "fuk", "phuck",
      "fck", "fking", "f king", "effing", "effin", "f word", "the f word",
      "motherf", "f**k", "fu*k", "f***", "fukking", "fuking", "fukin",
      "fukkin", "frickin", "freaking", "fricking", // clean substitutes
    ],
  },
  {
    word: "shit", category: "severe", lang: "en",
    variations: [
      "shitting", "shitty", "shitted", "shits", "shiit", "shyt", "sht",
      "sh t", "bs", "bull shit", "holy shit", "oh shit", "aw shit",
    ],
  },
  {
    word: "bitch", category: "severe", lang: "en",
    variations: ["bitches", "bitching", "bitched", "biitch", "b tch", "bich"],
  },
  {
    word: "asshole", category: "severe", lang: "en",
    variations: ["assholes", "a hole", "a**hole", "arse hole", "arsehole"],
  },
  {
    word: "bastard", category: "severe", lang: "en",
    variations: ["bastards", "bast rd"],
  },
  {
    word: "cunt", category: "severe", lang: "en",
    variations: ["cunts", "c word"],
  },
  {
    word: "dick", category: "severe", lang: "en",
    variations: ["dicks", "d ck", "d**k"],
  },
  {
    word: "cock", category: "severe", lang: "en",
    variations: ["cocks", "c**k"],
  },
  {
    word: "whore", category: "severe", lang: "en",
    variations: ["whores", "ho", "hoe"],
  },
  {
    word: "slut", category: "severe", lang: "en",
    variations: ["sluts"],
  },
  {
    word: "nigga", category: "severe", lang: "en",
    variations: ["nigger", "n word", "the n word", "niggas", "nigg"],
  },
  {
    word: "motherfucker", category: "severe", lang: "en",
    variations: [
      "motherfucking", "mother fucker", "mother f", "mf", "em ef",
      "mofo", "mo fo",
    ],
  },
  {
    word: "bullshit", category: "severe", lang: "en",
    variations: ["bull shit", "bs"],
  },
  {
    word: "retard", category: "severe", lang: "en",
    variations: ["retarded", "retards", "r word"],
  },
  {
    word: "faggot", category: "severe", lang: "en",
    variations: ["fag", "fags", "f word"],
  },
  {
    word: "ass", category: "moderate", lang: "en",
    variations: ["asses", "asshat", "smart ass", "dumb ass", "jackass", "jack ass"],
  },
  {
    word: "damn", category: "moderate", lang: "en",
    variations: ["damned", "damnit", "dammit", "dayum", "dayumm"],
  },
  {
    word: "piss", category: "moderate", lang: "en",
    variations: ["pissed", "pissing", "pissed off"],
  },
  {
    word: "crap", category: "mild", lang: "en",
    variations: ["crappy", "craps"],
  },
  {
    word: "hell", category: "mild", lang: "en",
    variations: ["what the hell", "the hell"],
  },
];

// ─── Hindi / Hinglish Profanity ───────────────────────────────────────────────
// Written as humans SAY them (and as STT engines actually transcribe them)
// Key insight: STT often splits compound words, or uses alternate spellings
const HINDI_PROFANITY_LIST = [
  {
    word: "madarchod", category: "severe", lang: "hi",
    variations: [
      // How STT splits/transcribes this compound word:
      "mader chod", "madar chod", "mader chodh", "mader chaad",
      "maderchod", "mader ch", "madda chod", "madre chod",
      "mc", "em see",
      // Common alternate spellings:
      "maderchod", "madar chodh", "madhar chod",
      "madarc", "maadarchod",
    ],
  },
  {
    word: "behenchod", category: "severe", lang: "hi",
    variations: [
      // STT splits/transcribes as:
      "behen chod", "behan chod", "ben chod", "bhen chod",
      "bahanchod", "behan ch", "behen ch",
      "bc", "bee see",
      // Alternate:
      "bhenchod", "bhanchod", "bhen chodh",
    ],
  },
  {
    word: "chutiya", category: "severe", lang: "hi",
    variations: [
      // STT transcription variants:
      "chutia", "chootia", "chhutia", "chutiye", "chutiyon",
      "choot", "chut", "chuti ya", "chutia", "chutiye",
      "chotiya", "chotia", "chodiya",
      // Compound:
      "chutiyapa", "chutiyagiri",
    ],
  },
  {
    word: "gandu", category: "severe", lang: "hi",
    variations: [
      "gaand", "gaandu", "gand", "gaand maro",
      "gande", "gandoo", "gundu",
      "g*ndu",
    ],
  },
  {
    word: "loda", category: "severe", lang: "hi",
    variations: [
      // STT transcription:
      "lode", "lund", "lunde", "lauda", "laude",
      "lor", "lau da", "lau de", "lawda", "lawde",
      "lun", "lund kha",
    ],
  },
  {
    word: "randi", category: "severe", lang: "hi",
    variations: [
      "randis", "randiyon", "randibaz",
      "raandi", "rundi",
    ],
  },
  {
    word: "harami", category: "severe", lang: "hi",
    variations: [
      "haramzada", "haramzadi", "haramkhor",
      "haraamzada", "haramzaade", "haram",
      "haram zaada", "haram zadi",
    ],
  },
  {
    word: "bhosdike", category: "severe", lang: "hi",
    variations: [
      // STT variations:
      "bhos dike", "bhosdi ke", "bhosdika", "bhos di ke",
      "bhosad", "bhosdiwale", "bhosda",
      "bhos", "bhosd", "bhosdiwala",
    ],
  },
  {
    word: "maa ki aankh", category: "severe", lang: "hi",
    variations: [
      "maa ki aankh", "ma ki ankh", "teri maa ki",
      "teri maa", "aapki maa", "maa ko",
      "maa ka", "maa ki", "maaki",
    ],
  },
  {
    word: "teri maa", category: "severe", lang: "hi",
    variations: [
      "teri ma", "teri maa ki", "teri mummy",
      "tere maa", "tere baap", "tere ghar",
    ],
  },
  {
    word: "kutta", category: "moderate", lang: "hi",
    variations: [
      "kutte", "kutton", "kutiya", "kutiye",
      "kuttey", "kutton", "kuta", "kute",
    ],
  },
  {
    word: "saala", category: "moderate", lang: "hi",
    variations: [
      "saale", "sala", "sale", "saaley",
      "saala kutta", "saale kamine",
    ],
  },
  {
    word: "kamina", category: "moderate", lang: "hi",
    variations: [
      "kamine", "kaminon", "kaminey",
      "kaameena", "kameena",
    ],
  },
  {
    word: "ullu", category: "moderate", lang: "hi",
    variations: [
      "ullu ka pattha", "ull", "ullo",
      "ullu ka patta",
    ],
  },
  {
    word: "gadha", category: "moderate", lang: "hi",
    variations: [
      "gadhe", "gadhon", "gadde", "ghadha",
    ],
  },
  {
    word: "jhatu", category: "moderate", lang: "hi",
    variations: ["jhate", "jhaton", "jhaatu"],
  },
  {
    word: "chakka", category: "moderate", lang: "hi",
    variations: ["chakke", "chakkon"],
  },
  {
    word: "hijra", category: "moderate", lang: "hi",
    variations: ["hijron", "hijda", "hijde"],
  },
  {
    word: "bakwas", category: "mild", lang: "hi",
    variations: ["bakwaas", "bakwaasi"],
  },
  {
    word: "bevakoof", category: "mild", lang: "hi",
    variations: ["bewakoof", "bewakuf", "bewakoof", "beawakuf"],
  },
  {
    word: "pagal", category: "mild", lang: "hi",
    variations: ["pagli", "paglon", "pagal hai", "pagal ho"],
  },
  {
    word: "suar", category: "severe", lang: "hi",
    variations: ["suvar", "suwar", "suaron", "sooar"],
  },
  {
    word: "bhadwa", category: "severe", lang: "hi",
    variations: ["bhadwe", "bhadwon", "bhade", "bhaadwa"],
  },
];

// ─── Combined Default List ────────────────────────────────────────────────────
const DEFAULT_PROFANITY_LIST = [...ENGLISH_PROFANITY_LIST, ...HINDI_PROFANITY_LIST];

/**
 * Build a flat Set of words + variations for lookup
 */
function buildWordSet(list = DEFAULT_PROFANITY_LIST, filterCategories = null, filterLangs = null) {
  const wordSet = new Set();
  list.forEach(({ word, category, lang, variations }) => {
    if (filterCategories && !filterCategories.includes(category)) return;
    if (filterLangs     && !filterLangs.includes(lang))           return;
    wordSet.add(word.toLowerCase());
    variations.forEach(v => wordSet.add(v.toLowerCase().replace(/[*]/g, "")));
  });
  return wordSet;
}

/**
 * Build regex pattern for word boundary matching
 */
function buildRegex(wordSet) {
  const escaped = [...wordSet].map(w => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(`\\b(${escaped.join("|")})\\b`, "gi");
}

// Export (Node.js / shared usage)
if (typeof module !== "undefined") {
  module.exports = {
    DEFAULT_PROFANITY_LIST,
    ENGLISH_PROFANITY_LIST,
    HINDI_PROFANITY_LIST,
    PROFANITY_CATEGORIES,
    buildWordSet,
    buildRegex,
  };
}
