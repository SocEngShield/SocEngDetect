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
        "verificar", "verifique", "verifica", "vérifier", "vérifiez",
        "überprüfen", "bestätigen", "verificare", "verifichi"
    ],
    "account": [
        "cuenta", "compte", "konto", "conto", "conta",
        "аккаунт", "账户", "アカウント"
    ],
    "password": [
        "contraseña", "mot de passe", "passwort", "senha", "parola",
        "пароль", "密码", "パスワード"
    ],
    "login": [
        "iniciar sesión", "connexion", "anmelden", "accesso", "entrar",
        "войти", "登录", "ログイン"
    ],
    "confirm": [
        "confirmar", "confirmer", "bestätigen", "confermare", "confirme"
    ],
    
    # Urgency
    "urgent": [
        "urgente", "urgent", "dringend", "срочно", "紧急", "緊急"
    ],
    "immediately": [
        "inmediatamente", "immédiatement", "sofort", "imediatamente",
        "сейчас", "立即", "すぐに"
    ],
    "now": [
        "ahora", "maintenant", "jetzt", "adesso", "agora", "сейчас"
    ],
    "expires": [
        "expira", "expire", "läuft ab", "scade", "vence"
    ],
    
    # Financial
    "bank": [
        "banco", "banque", "bank", "banca", "банк", "银行", "銀行"
    ],
    "payment": [
        "pago", "paiement", "zahlung", "pagamento", "платеж", "付款"
    ],
    "card": [
        "tarjeta", "carte", "karte", "carta", "карта", "卡"
    ],
    "transfer": [
        "transferencia", "transfert", "überweisung", "trasferimento"
    ],
    
    # Rewards / Lures
    "reward": [
        "recompensa", "récompense", "belohnung", "premio", "ricompensa"
    ],
    "prize": [
        "premio", "prix", "preis", "prêmio", "приз"
    ],
    "winner": [
        "ganador", "gagnant", "gewinner", "vincitore", "vencedor"
    ],
    "won": [
        "ganado", "gagné", "gewonnen", "vinto", "ganhou"
    ],
    "free": [
        "gratis", "gratuit", "kostenlos", "gratuito", "бесплатно"
    ],
    
    # Threats
    "suspended": [
        "suspendido", "suspendu", "gesperrt", "sospeso", "suspenso"
    ],
    "blocked": [
        "bloqueado", "bloqué", "gesperrt", "bloccato", "bloqueado"
    ],
    "limited": [
        "limitado", "limité", "eingeschränkt", "limitato"
    ],
    "security": [
        "seguridad", "sécurité", "sicherheit", "sicurezza", "segurança"
    ],
    "alert": [
        "alerta", "alerte", "warnung", "avviso", "alerta"
    ],
    
    # Actions
    "click": [
        "haga clic", "cliquez", "klicken", "clicca", "clique"
    ],
    "update": [
        "actualizar", "mettre à jour", "aktualisieren", "aggiornare"
    ],
}


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
