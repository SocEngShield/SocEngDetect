"""
Multilingual Keyword Normalization Map.
Maps non-English phishing keywords to English equivalents.
Used for detection without modifying original text signals.
"""

# ---------------------------
# KEYWORD MAPPING
# ---------------------------

KEYWORD_MAP = {
    # Authentication / Security
    "verify": [
        # Romance languages
        "verificar", "verifique", "verifica", "vérifier", "vérifiez",
        "überprüfen", "bestätigen", "verificare", "verifichi",
        # CJK
        "验证", "確認", "확인하다", "確認する",
        # Cyrillic
        "подтвердить", "проверить",
        # Arabic
        "تحقق", "تأكيد"
    ],
    "account": [
        "cuenta", "compte", "konto", "conto", "conta",
        "аккаунт", "учетная запись",
        "账户", "帳戶", "アカウント", "계정",
        "حساب"
    ],
    "password": [
        "contraseña", "mot de passe", "passwort", "senha", "parola",
        "пароль",
        "密码", "密碼", "パスワード", "비밀번호",
        "كلمة المرور", "كلمة السر"
    ],
    "login": [
        "iniciar sesión", "connexion", "anmelden", "accesso", "entrar",
        "войти", "авторизация",
        "登录", "登錄", "ログイン", "로그인",
        "تسجيل الدخول"
    ],
    "confirm": [
        "confirmar", "confirmer", "bestätigen", "confermare", "confirme",
        "подтвердить",
        "确认", "確認", "확인",
        "تأكيد"
    ],
    
    # Urgency
    "urgent": [
        "urgente", "urgent", "dringend",
        "срочно", "срочный",
        "紧急", "緊急", "긴급", "至急",
        "عاجل", "طارئ"
    ],
    "immediately": [
        "inmediatamente", "immédiatement", "sofort", "imediatamente",
        "сейчас", "немедленно",
        "立即", "马上", "即刻", "すぐに", "즉시",
        "فورا", "حالا"
    ],
    "now": [
        "ahora", "maintenant", "jetzt", "adesso", "agora",
        "сейчас", "теперь",
        "现在", "現在", "今すぐ", "지금",
        "الآن"
    ],
    "expires": [
        "expira", "expire", "läuft ab", "scade", "vence",
        "истекает",
        "过期", "到期", "期限切れ", "만료",
        "ينتهي"
    ],
    "deadline": [
        "plazo", "délai", "frist", "scadenza", "prazo",
        "срок", "дедлайн",
        "截止日期", "期限", "締め切り", "마감",
        "موعد نهائي"
    ],
    
    # Financial
    "bank": [
        "banco", "banque", "bank", "banca",
        "банк",
        "银行", "銀行", "은행",
        "بنك", "مصرف"
    ],
    "payment": [
        "pago", "paiement", "zahlung", "pagamento",
        "платеж", "оплата",
        "付款", "支付", "決済", "지불",
        "دفع", "سداد"
    ],
    "card": [
        "tarjeta", "carte", "karte", "carta",
        "карта",
        "卡", "カード", "카드",
        "بطاقة"
    ],
    "transfer": [
        "transferencia", "transfert", "überweisung", "trasferimento",
        "перевод",
        "转账", "振込", "이체",
        "تحويل"
    ],
    "credit": [
        "crédito", "crédit", "kredit", "credito",
        "кредит",
        "信用", "クレジット", "신용",
        "ائتمان"
    ],
    "bitcoin": [
        "биткоин",
        "比特币", "ビットコイン", "비트코인"
    ],
    "wallet": [
        "billetera", "portefeuille", "brieftasche", "portafoglio",
        "кошелек",
        "钱包", "ウォレット", "지갑",
        "محفظة"
    ],
    
    # Rewards / Lures
    "reward": [
        "recompensa", "récompense", "belohnung", "premio", "ricompensa",
        "награда", "вознаграждение",
        "奖励", "報酬", "보상",
        "مكافأة"
    ],
    "prize": [
        "premio", "prix", "preis", "prêmio",
        "приз",
        "奖品", "賞品", "상품",
        "جائزة"
    ],
    "winner": [
        "ganador", "gagnant", "gewinner", "vincitore", "vencedor",
        "победитель",
        "获奖者", "当選者", "수상자",
        "فائز"
    ],
    "won": [
        "ganado", "gagné", "gewonnen", "vinto", "ganhou",
        "выиграл",
        "赢得", "당첨",
        "فاز"
    ],
    "free": [
        "gratis", "gratuit", "kostenlos", "gratuito",
        "бесплатно",
        "免费", "無料", "무료",
        "مجاني"
    ],
    "gift": [
        "regalo", "cadeau", "geschenk",
        "подарок",
        "礼物", "プレゼント", "선물",
        "هدية"
    ],
    "lottery": [
        "lotería", "loterie", "lotterie", "lotteria",
        "лотерея",
        "彩票", "宝くじ", "복권",
        "يانصيب"
    ],
    
    # Threats
    "suspended": [
        "suspendido", "suspendu", "gesperrt", "sospeso", "suspenso",
        "заблокирован", "приостановлен", "заморожен",
        "暂停", "停止", "정지됨",
        "معلق"
    ],
    "blocked": [
        "bloqueado", "bloqué", "gesperrt", "bloccato",
        "заблокирован", "заблокировано",
        "封锁", "ブロック", "차단",
        "محظور"
    ],
    "limited": [
        "limitado", "limité", "eingeschränkt", "limitato",
        "ограничен", "ограничено",
        "限制", "制限", "제한",
        "محدود"
    ],
    "security": [
        "seguridad", "sécurité", "sicherheit", "sicurezza", "segurança",
        "безопасность", "защита",
        "安全", "セキュリティ", "보안",
        "أمان", "أمن"
    ],
    "alert": [
        "alerta", "alerte", "warnung", "avviso",
        "предупреждение", "оповещение", "внимание",
        "警报", "アラート", "경고",
        "تنبيه"
    ],
    "warning": [
        "advertencia", "avertissement", "warnung", "avvertimento",
        "предупреждение", "осторожно",
        "警告", "警告", "경고",
        "تحذير"
    ],
    "unauthorized": [
        "no autorizado", "non autorisé", "unbefugt",
        "несанкционированный", "несанкционированный доступ",
        "未授权", "不正", "무단",
        "غير مصرح"
    ],
    "hacked": [
        "hackeado", "piraté", "gehackt",
        "взломан", "взломали",
        "被黑", "ハッキング", "해킹",
        "مخترق"
    ],
    "compromised": [
        "comprometido", "compromis", "kompromittiert",
        "скомпрометирован", "взломан",
        "泄露", "侵害", "유출",
        "مخترق"
    ],
    "stolen": [
        "robado", "volé", "gestohlen",
        "украден", "похищен",
        "被盗", "盗まれた", "도난",
        "مسروق"
    ],
    
    # Actions
    "click": [
        "haga clic", "cliquez", "klicken", "clicca", "clique",
        "нажмите", "кликните",
        "点击", "クリック", "클릭",
        "انقر"
    ],
    "update": [
        "actualizar", "mettre à jour", "aktualisieren", "aggiornare",
        "обновить",
        "更新", "アップデート", "업데이트",
        "تحديث"
    ],
    "download": [
        "descargar", "télécharger", "herunterladen", "scaricare",
        "скачать",
        "下载", "ダウンロード", "다운로드",
        "تحميل"
    ],
    
    # QR Phishing keywords
    "scan": [
        "escanear", "scanner", "scannen", "scansionare",
        "сканировать", "отсканируйте",
        "扫描", "スキャン", "스캔",
        "مسح"
    ],
    "qr": [
        "código qr", "code qr", "qr-code",
        "qr-код", "кюар-код",
        "二维码", "QRコード", "QR코드"
    ],
    
    # Additional Russian/Cyrillic threat phrases
    "data": [
        "datos", "données", "daten",
        "данные", "информация",
        "数据", "データ", "데이터",
        "بيانات"
    ],
    "required": [
        "requerido", "requis", "erforderlich",
        "требуется", "необходимо", "обязательно",
        "必须", "必要", "필수",
        "مطلوب"
    ],
    "action": [
        "acción", "action", "aktion",
        "действие", "действия требуются",
        "操作", "アクション", "조치",
        "إجراء"
    ],
    "help": [
        "ayuda", "aide", "hilfe",
        "помощь", "помогите",
        "帮助", "助けて", "도움",
        "مساعدة"
    ],
    "money": [
        "dinero", "argent", "geld",
        "деньги", "денежные средства",
        "钱", "お金", "돈",
        "مال"
    ],
    "send": [
        "enviar", "envoyer", "senden",
        "отправить", "отправьте", "переслать",
        "发送", "送る", "보내다",
        "إرسال"
    ],
}



# ---------------------------
# ADVERSARIAL TEXT NORMALIZATION
# ---------------------------

# Symbol substitution map (leet speak / obfuscation)
SYMBOL_MAP = {
    "@": "a",
    "0": "o",
    "1": "l",
    "$": "s",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "!": "i",
    "|": "l",
    "(": "c",
    ")": "d",
    "+": "t",
    "^": "a",
    "6": "b",
    "9": "g",
    "2": "z",
    "8": "b",
}

# Homoglyph map (Cyrillic/Greek/Math lookalikes → Latin)
HOMOGLYPH_MAP = {
    # Cyrillic lookalikes (lowercase)
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "һ": "h", "ո": "n", "ԝ": "w", "ʏ": "y", "ᴠ": "v", "ҡ": "k",
    "ʟ": "l", "ᴍ": "m", "ƅ": "b", "ϲ": "c", "ⅿ": "m",
    # Cyrillic lookalikes (uppercase)
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "К": "K",
    "М": "M", "О": "O", "Р": "P", "Т": "T", "Х": "X", "Ү": "Y",
    "Ѕ": "S", "Ⅰ": "I", "Ј": "J", "Ꮃ": "W",
    # Greek lookalikes
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Mathematical / Special characters
    "ℓ": "l", "ℕ": "n", "ℙ": "p", "ℝ": "r", "ℤ": "z",
    "ⅰ": "i", "ⅴ": "v", "ⅹ": "x", "ⅼ": "l", "ⅽ": "c", "ⅾ": "d",
    "ℂ": "c", "ℍ": "h", "ℐ": "i", "ℒ": "l", "ℳ": "m", "ℛ": "r",
    "ℬ": "b", "ℰ": "e", "ℱ": "f", "ℋ": "h", "ℑ": "i", "ℜ": "r",
    "ℿ": "n", "⅀": "s",
    # Subscript/Superscript
    "ᵃ": "a", "ᵇ": "b", "ᶜ": "c", "ᵈ": "d", "ᵉ": "e", "ᶠ": "f",
    "ᵍ": "g", "ʰ": "h", "ⁱ": "i", "ʲ": "j", "ᵏ": "k", "ˡ": "l",
    "ᵐ": "m", "ⁿ": "n", "ᵒ": "o", "ᵖ": "p", "ʳ": "r", "ˢ": "s",
    "ᵗ": "t", "ᵘ": "u", "ᵛ": "v", "ʷ": "w", "ˣ": "x", "ʸ": "y", "ᶻ": "z",
    # Fullwidth Latin (lowercase)
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
    # Fullwidth Latin (uppercase)
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E",
    "Ｆ": "F", "Ｇ": "G", "Ｈ": "H", "Ｉ": "I", "Ｊ": "J",
    "Ｋ": "K", "Ｌ": "L", "Ｍ": "M", "Ｎ": "N", "Ｏ": "O",
    "Ｐ": "P", "Ｑ": "Q", "Ｒ": "R", "Ｓ": "S", "Ｔ": "T",
    "Ｕ": "U", "Ｖ": "V", "Ｗ": "W", "Ｘ": "X", "Ｙ": "Y", "Ｚ": "Z",
    # Accented / Modified Latin (common obfuscation)
    "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a", "ā": "a",
    "è": "e", "é": "e", "ê": "e", "ë": "e", "ē": "e",
    "ì": "i", "í": "i", "î": "i", "ï": "i", "ī": "i",
    "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "ø": "o", "ō": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u", "ū": "u",
    "ñ": "n", "ç": "c", "ý": "y", "ÿ": "y",
    # Small caps
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ꜰ": "f",
    "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k",
    "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ǫ": "q", "ʀ": "r",
    "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
}

# Zero-width and invisible characters to remove
ZERO_WIDTH_CHARS = [
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
    "\ufeff",  # BOM / zero-width no-break space
    "\u00ad",  # Soft hyphen
    "\u034f",  # Combining grapheme joiner
    "\u061c",  # Arabic letter mark
    "\u180e",  # Mongolian vowel separator
]


def normalize_obfuscation(text: str) -> str:
    """
    Normalize obfuscated text (spacing tricks, symbol substitutions, noise).
    Run BEFORE multilingual normalization.
    Handles: leet speak, homoglyphs, zero-width chars, spacing tricks.
    """
    result = text
    
    # 0. Remove zero-width and invisible characters FIRST
    for zw_char in ZERO_WIDTH_CHARS:
        result = result.replace(zw_char, "")
    
    # 1. Apply homoglyph substitutions (before lowercasing to catch uppercase)
    for homoglyph, latin in HOMOGLYPH_MAP.items():
        result = result.replace(homoglyph, latin)
    
    result = result.lower()
    
    # 2. Collapse single-character spacing ("v e r i f y" → "verify")
    words = result.split()
    collapsed_words = []
    i = 0
    while i < len(words):
        if len(words[i]) == 1 and words[i].isalpha():
            chars = [words[i]]
            j = i + 1
            while j < len(words) and len(words[j]) == 1 and words[j].isalpha():
                chars.append(words[j])
                j += 1
            if len(chars) >= 3:
                collapsed_words.append("".join(chars))
                i = j
            else:
                collapsed_words.append(words[i])
                i += 1
        else:
            collapsed_words.append(words[i])
            i += 1
    result = " ".join(collapsed_words)
    
    # 3. Apply symbol substitutions (leet speak)
    for symbol, letter in SYMBOL_MAP.items():
        result = result.replace(symbol, letter)
    
    # 4. Remove inline punctuation noise (keep word boundaries)
    cleaned_words = []
    for word in result.split():
        clean = ""
        for char in word:
            if char.isalnum() or char in ".-_":
                clean += char
        clean = clean.replace("-", "").replace("_", "")
        if clean:
            cleaned_words.append(clean)
    
    return " ".join(cleaned_words)


def normalize_text(text: str) -> tuple:
    """
    Normalize non-English keywords to English equivalents.
    Preserves original casing structure for signal detection.
    
    Args:
        text: Original message text
        
    Returns:
        tuple: (normalized_text, match_count)
            - normalized_text: Text with multilingual keywords mapped to English
            - match_count: Number of non-English keywords found and replaced
    """
    text_lower = text.lower()
    match_count = 0
    
    for english_word, variants in KEYWORD_MAP.items():
        for variant in variants:
            if variant in text_lower:
                text_lower = text_lower.replace(variant, english_word)
                match_count += 1
    
    return text_lower, match_count
