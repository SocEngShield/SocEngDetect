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
        "заблокирован", "приостановлен",
        "暂停", "停止", "정지됨",
        "معلق"
    ],
    "blocked": [
        "bloqueado", "bloqué", "gesperrt", "bloccato",
        "заблокирован",
        "封锁", "ブロック", "차단",
        "محظور"
    ],
    "limited": [
        "limitado", "limité", "eingeschränkt", "limitato",
        "ограничен",
        "限制", "制限", "제한",
        "محدود"
    ],
    "security": [
        "seguridad", "sécurité", "sicherheit", "sicurezza", "segurança",
        "безопасность",
        "安全", "セキュリティ", "보안",
        "أمان", "أمن"
    ],
    "alert": [
        "alerta", "alerte", "warnung", "avviso",
        "предупреждение", "оповещение",
        "警报", "アラート", "경고",
        "تنبيه"
    ],
    "warning": [
        "advertencia", "avertissement", "warnung", "avvertimento",
        "предупреждение",
        "警告", "警告", "경고",
        "تحذير"
    ],
    "unauthorized": [
        "no autorizado", "non autorisé", "unbefugt",
        "несанкционированный",
        "未授权", "不正", "무단",
        "غير مصرح"
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
        "сканировать",
        "扫描", "スキャン", "스캔",
        "مسح"
    ],
    "qr": [
        "código qr", "code qr", "qr-code",
        "qr-код",
        "二维码", "QRコード", "QR코드"
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
}

# Homoglyph map (Cyrillic/Greek lookalikes → Latin)
HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "К": "K",
    "М": "M", "О": "O", "Р": "P", "Т": "T", "Х": "X",
    # Greek lookalikes
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "ν": "v", "ι": "i",
    # Special characters
    "ℓ": "l", "ℕ": "n", "ℙ": "p", "ℝ": "r", "ℤ": "z",
    "ⅰ": "i", "ⅴ": "v", "ⅹ": "x",
    # Fullwidth Latin
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
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
