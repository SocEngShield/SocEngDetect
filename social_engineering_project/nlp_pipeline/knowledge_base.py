"""
Social Engineering Attack Patterns Knowledge Base.
Balanced dataset for RAG-based detection.

Distribution (15 each x 9 categories = 135 total):
  - urgency               (social_engineering) : 15
  - reward_lure           (social_engineering) : 15
  - authority             (social_engineering) : 15
  - impersonation         (social_engineering) : 15
  - fear_threat           (social_engineering) : 30  (15 original + 15 merged from psychological_coercion)
  - fear_threat_severe    (social_engineering) : 15  NEW — service termination / legal / India-specific
  - legitimate_but_tricky (legitimate)         : 15
  - normal_communication  (legitimate)         : 15
"""

SOCIAL_ENGINEERING_DATASET = [

    # ═══════════════════════════════════════════════════════════════
    #  URGENCY  (15)
    # ═══════════════════════════════════════════════════════════════
    {"text": "URGENT: Your account will be suspended unless you verify your identity immediately by clicking this link", "label": "social_engineering", "category": "urgency", "confidence": 0.95},
    {"text": "ACTION REQUIRED: You have 24 hours to confirm your email or your account will be deleted permanently", "label": "social_engineering", "category": "urgency", "confidence": 0.93},
    {"text": "IMMEDIATE RESPONSE NEEDED: Your payment method expires today. Update now to avoid service interruption", "label": "social_engineering", "category": "urgency", "confidence": 0.91},
    {"text": "Limited time offer! Act now or miss out on this exclusive deal. Only 2 hours left!", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "FINAL WARNING: Your subscription will be cancelled in 1 hour unless you update your billing details right now", "label": "social_engineering", "category": "urgency", "confidence": 0.94},
    {"text": "Time-sensitive: Someone tried to access your account. Change your password within the next 30 minutes or lose access permanently", "label": "social_engineering", "category": "urgency", "confidence": 0.92},
    {"text": "CRITICAL ALERT: Your account security has been compromised. You must act within the next 15 minutes to prevent data loss", "label": "social_engineering", "category": "urgency", "confidence": 0.93},
    {"text": "NOTICE: Failure to verify your account within 12 hours will result in permanent deactivation. Click below to verify immediately", "label": "social_engineering", "category": "urgency", "confidence": 0.91},
    {"text": "Your access token expires in 10 minutes. Renew it now at this link or you will be locked out of all services", "label": "social_engineering", "category": "urgency", "confidence": 0.89},
    {"text": "LAST CHANCE: Confirm your shipping address in the next 2 hours or your order will be cancelled and your refund forfeited", "label": "social_engineering", "category": "urgency", "confidence": 0.90},
    {"text": "We detected unauthorized access. Respond within 60 minutes with your account credentials to secure your profile", "label": "social_engineering", "category": "urgency", "confidence": 0.94},
    {"text": "IMPORTANT: Your cloud storage is 99% full and files will be deleted in 3 hours. Upgrade immediately at this link", "label": "social_engineering", "category": "urgency", "confidence": 0.86},
    {"text": "Act fast — your tax refund of $4,200 will expire at midnight tonight. Submit your bank info now to receive it", "label": "social_engineering", "category": "urgency", "confidence": 0.93},
    {"text": "WARNING: If you don't reset your password within 20 minutes, all your saved data will be permanently erased", "label": "social_engineering", "category": "urgency", "confidence": 0.92},
    {"text": "Your verification window closes in 5 minutes. Failure to act will result in permanent account termination", "label": "social_engineering", "category": "urgency", "confidence": 0.91},

    # ═══════════════════════════════════════════════════════════════
    #  REWARD LURE  (15)
    # ═══════════════════════════════════════════════════════════════
    {"text": "Congratulations! You've won $1,000,000. Send us your bank details to claim your prize", "label": "social_engineering", "category": "reward_lure", "confidence": 0.98},
    {"text": "You are the lucky winner of our annual lottery! Click here to claim your $500,000 prize now", "label": "social_engineering", "category": "reward_lure", "confidence": 0.96},
    {"text": "You have a pending refund of $2,500. Click here to claim it before it expires", "label": "social_engineering", "category": "reward_lure", "confidence": 0.87},
    {"text": "FREE iPhone 15 Pro! You've been selected. Just pay $5.99 shipping to claim your prize", "label": "social_engineering", "category": "reward_lure", "confidence": 0.89},
    {"text": "You've been chosen for a $10,000 gift card giveaway! Enter your details here to receive your reward immediately", "label": "social_engineering", "category": "reward_lure", "confidence": 0.95},
    {"text": "Your email address was selected in our random draw. You've won a brand new MacBook Pro — claim it now", "label": "social_engineering", "category": "reward_lure", "confidence": 0.93},
    {"text": "EXCLUSIVE: You qualify for a secret government grant of $25,000. No repayment needed. Apply now before slots run out", "label": "social_engineering", "category": "reward_lure", "confidence": 0.96},
    {"text": "Amazon customer reward! You've earned 5,000 bonus points worth $500. Click below to redeem before they expire", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Congratulations valued customer! As a thank you, we're giving you $1,000 in store credit. Provide your account info to receive it", "label": "social_engineering", "category": "reward_lure", "confidence": 0.92},
    {"text": "You have unclaimed cashback of $750! This will be forfeited if not collected. Click here to get your money now", "label": "social_engineering", "category": "reward_lure", "confidence": 0.90},
    {"text": "WINNER ALERT: Our system randomly selected your phone number for a $2,000 Walmart voucher. Claim here", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Free vacation package to Bali! You are one of 10 lucky participants. Share your info to confirm your booking", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Your loyalty has earned you a surprise bonus of $3,500! Transfer will be initiated once you confirm your banking details", "label": "social_engineering", "category": "reward_lure", "confidence": 0.93},
    {"text": "Dear user, you've been selected for a cash prize of $5,000 in our monthly sweepstakes. Reply with your full name and address to claim", "label": "social_engineering", "category": "reward_lure", "confidence": 0.95},
    {"text": "You've won a Tesla Model 3! Just complete this short survey and pay a small processing fee of $9.99 to arrange delivery", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},

    # ═══════════════════════════════════════════════════════════════
    #  AUTHORITY  (15)
    # ═══════════���═══════════════════════════════════════════════════
    {"text": "I'm the CEO and I need you to transfer funds immediately. This is confidential.", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "This is your manager. I need you to purchase gift cards worth $5000 urgently for a client meeting", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "Director of Operations here. Send me employee payroll information immediately for audit purposes", "label": "social_engineering", "category": "authority", "confidence": 0.90},
    {"text": "This is the CFO. Wire $12,000 to the following account for an urgent vendor payment. Do not discuss this with anyone else", "label": "social_engineering", "category": "authority", "confidence": 0.95},
    {"text": "Hey, it's the VP of Engineering. I need you to share the production database credentials with me right now, we have an outage", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "I'm the head of HR. Please send me all employee SSN records by end of day for compliance review. Do not inform others", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "This is your supervisor. I'm in a meeting and can't talk. Buy 10 Apple gift cards ($200 each) and send me the codes ASAP", "label": "social_engineering", "category": "authority", "confidence": 0.96},
    {"text": "It's the president of the company. I need the company credit card number for an emergency purchase. Keep this between us", "label": "social_engineering", "category": "authority", "confidence": 0.95},
    {"text": "This is the CTO. Grant admin access to the following external email immediately — we have a critical partner onboarding", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "As your department head, I'm instructing you to process this invoice immediately. No need for the usual approval chain this time", "label": "social_engineering", "category": "authority", "confidence": 0.91},
    {"text": "I'm reaching out from the executive office. The CEO has approved a special bonus — send your direct deposit details for processing", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "This is the managing director. Disregard previous security protocols and transfer the project files to this personal Google Drive link", "label": "social_engineering", "category": "authority", "confidence": 0.96},
    {"text": "Your team lead here — I've forgotten my VPN credentials and IT is closed. Can you share yours so I can finish the deployment tonight?", "label": "social_engineering", "category": "authority", "confidence": 0.89},
    {"text": "This is the board chairman. We have a confidential acquisition in progress. Wire $50,000 to this escrow account immediately", "label": "social_engineering", "category": "authority", "confidence": 0.97},
    {"text": "Hello, I'm the new IT director. As part of the security migration, I need all employees to reply with their current passwords for the transition", "label": "social_engineering", "category": "authority", "confidence": 0.95},

    # ═══════════════════════════════════════════════════════════════
    #  IMPERSONATION  (15)
    # ═══════════════════════════════════════════════════════════════
    {"text": "Your package is waiting. Please update your shipping address and payment information.", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "Your IT department requires immediate password reset due to security breach. Click here to reset.", "label": "social_engineering", "category": "impersonation", "confidence": 0.91},
    {"text": "Netflix: Your account has been suspended. Update your payment details within 48 hours to restore access", "label": "social_engineering", "category": "impersonation", "confidence": 0.86},
    {"text": "Amazon: Unusual activity detected on your account. Verify your identity now to prevent account closure", "label": "social_engineering", "category": "impersonation", "confidence": 0.89},
    {"text": "Your bank has detected suspicious transactions. Call this number immediately to verify your account", "label": "social_engineering", "category": "impersonation", "confidence": 0.93},
    {"text": "PayPal Security: We noticed a login from an unrecognized device. Confirm your identity by entering your password at this link", "label": "social_engineering", "category": "impersonation", "confidence": 0.92},
    {"text": "Apple Support: Your iCloud account has been locked due to suspicious activity. Verify your credentials here to restore access", "label": "social_engineering", "category": "impersonation", "confidence": 0.91},
    {"text": "Microsoft 365: Your mailbox is full and incoming emails are being rejected. Click here to upgrade your storage immediately", "label": "social_engineering", "category": "impersonation", "confidence": 0.87},
    {"text": "FedEx: We were unable to deliver your package. Please confirm your address and pay the redelivery fee at this link", "label": "social_engineering", "category": "impersonation", "confidence": 0.90},
    {"text": "Google Security Alert: Someone has your password. You should change it immediately at the following link", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "Instagram Support: Your account has been flagged for copyright violation. Verify your identity within 24 hours or your account will be removed", "label": "social_engineering", "category": "impersonation", "confidence": 0.89},
    {"text": "This is Dropbox support. Your shared files have been reported as harmful. Please login through this link to review and restore them", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "Your Spotify Premium subscription could not be renewed. Update payment information at this link to avoid losing your playlists", "label": "social_engineering", "category": "impersonation", "confidence": 0.85},
    {"text": "IRS Notice: You have an outstanding tax liability. Submit payment immediately through our secure portal to avoid penalties and legal action", "label": "social_engineering", "category": "impersonation", "confidence": 0.94},
    {"text": "LinkedIn Security: We've detected unusual login activity. Confirm your identity by clicking this link and entering your credentials", "label": "social_engineering", "category": "impersonation", "confidence": 0.90},

    # ═══════════════════════════════════════════════════════════════
    #  FEAR / THREAT  (15)
    # ═══════════════════════════════════════════════════════════════
    {"text": "Security alert: Suspicious activity detected. Click here to secure your account NOW!", "label": "social_engineering", "category": "fear_threat", "confidence": 0.93},
    {"text": "WARNING: Your computer is infected with a virus. Download our security software immediately!", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "Legal notice: You have unpaid taxes. Failure to respond within 24 hours will result in legal action", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "Your personal data has been compromised in a breach. Click here immediately to secure your information", "label": "social_engineering", "category": "fear_threat", "confidence": 0.90},
    {"text": "ALERT: We have recorded your browsing activity. Pay $500 in Bitcoin within 48 hours or the information will be shared with your contacts", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "Your device has been compromised by ransomware. All files are encrypted. Send $1,000 to this wallet address to recover your data", "label": "social_engineering", "category": "fear_threat", "confidence": 0.98},
    {"text": "We have evidence of illegal downloads from your IP address. Contact us within 24 hours to settle this matter privately or face prosecution", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "SECURITY BREACH: Your email, passwords, and financial data have been leaked on the dark web. Act now to protect yourself", "label": "social_engineering", "category": "fear_threat", "confidence": 0.92},
    {"text": "Your webcam has been hacked and we have recorded private footage. Pay us $2,000 or the video will be sent to your entire contact list", "label": "social_engineering", "category": "fear_threat", "confidence": 0.98},
    {"text": "An arrest warrant has been issued in your name for unpaid debts. Call this number immediately to resolve the matter before authorities arrive", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "Your social media accounts have been flagged for suspicious content. Verify your identity now or your accounts will be permanently banned", "label": "social_engineering", "category": "fear_threat", "confidence": 0.89},
    {"text": "DANGER: Your router has been hacked. All your network traffic is being intercepted. Install this security patch immediately", "label": "social_engineering", "category": "fear_threat", "confidence": 0.93},
    {"text": "We've detected someone trying to steal your identity. Your credit score is at risk. Click here now to activate identity protection", "label": "social_engineering", "category": "fear_threat", "confidence": 0.91},
    {"text": "A complaint has been filed against you and legal proceedings will begin in 72 hours unless you respond to this notice immediately", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "CRITICAL WARNING: Multiple failed login attempts detected. Your account will be permanently locked. Verify your identity now to prevent lockout", "label": "social_engineering", "category": "fear_threat", "confidence": 0.91},

    # ═══════════════════════════════════════════════════════════════
    #  PSYCHOLOGICAL COERCION  (15) — merged into fear_threat category
    # ═══════════════════════════════════════════════════════════════
    {"text": "We know where you live and we know your family. Cooperate or face the consequences.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "I have recorded you through your webcam. Pay up or the footage goes to everyone you know.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "Comply with our demands or we will ruin your career and destroy your reputation permanently.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "Do as I say or I will expose your private conversations and browsing history to your employer.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "We have accessed your email and phone. We have everything. Do exactly what we tell you or face the consequences.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "This is your last warning. You have 24 hours to comply. There will be no second chance and no way back.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.94},
    {"text": "Keep this between us. Do not tell anyone. If you disobey there will be severe consequences for you and your family.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "I am ordering you to process this now. No questions asked. Do it quietly or I will make sure you regret it.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "Your files are encrypted and there is no recovery without our key. This is permanent. Pay now or lose everything forever.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "We will leak your personal photos and private data to the public unless you cooperate immediately.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "I know your secrets. I have proof. Do what I ask or everyone will know. You have 48 hours.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "You will be held personally responsible. This will follow you for the rest of your career. Comply now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.93},
    {"text": "If you don't do exactly as instructed, we will release damaging information about you. This is not a bluff.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "We are watching your every move. We have hacked your camera and microphone. Obey or suffer the consequences.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "Disappoint me on this and it will reflect very badly on you. Keep this confidential and do it now without question.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.91},

    # ═══════════════════════════════════════════════════════════════
    #  FEAR / THREAT — SEVERE  (15)  NEW: service termination, legal,
    #  India-specific scams (Aadhaar, PAN, SIM, court, police, FIR)
    # ═══════════════════════════════════════════════════════════════
    {"text": "Your bank account has been frozen due to suspicious activity. Contact us immediately or your funds will be permanently seized", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "Your Aadhaar number has been misused for illegal activities. Your Aadhaar will be deactivated within 24 hours unless you verify now", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "Your PAN card has been blocked by the Income Tax Department due to suspicious transactions. Call immediately to unblock", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "Your SIM card will be deactivated within 2 hours due to illegal usage detected. Press 1 to speak to a telecom officer immediately", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "An FIR has been filed against you for financial fraud. Report to the nearest police station or face arrest within 48 hours", "label": "social_engineering", "category": "fear_threat", "confidence": 0.97},
    {"text": "A court summon has been issued in your name. Failure to appear will result in a non-bailable arrest warrant", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "The Income Tax Department has initiated an investigation against you. Settle your dues within 24 hours to avoid prosecution", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "A police complaint has been registered against your phone number for fraud. Your number will be blacklisted permanently", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "Your bank account will be permanently closed within 24 hours due to KYC non-compliance. Update immediately to prevent closure", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "Your internet service will be terminated immediately due to illegal content accessed from your IP. Contact cyber cell now", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "Legal action has been initiated against you. Your property and bank assets will be seized unless you settle immediately", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "Your passport has been flagged and a look-out notice has been issued. You are prohibited from leaving the country until further notice", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "Your electricity connection will be disconnected today due to unpaid dues. Pay immediately through this link to avoid disconnection", "label": "social_engineering", "category": "fear_threat", "confidence": 0.94},
    {"text": "Your credit card has been used for money laundering. The bank has reported this to authorities. Call now to avoid criminal charges", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "Your email account will be permanently deleted due to violation of terms. Verify your identity within 1 hour to prevent deletion", "label": "social_engineering", "category": "fear_threat", "confidence": 0.93},

    # ═══════════════════════════════════════════════════════════════
    #  LEGITIMATE BUT TRICKY  (15)
    # ═══════════════════════════════════════════════════════════════
    {"text": "Please verify your email address to complete your registration. Click the link we sent to your inbox.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Your subscription is expiring on March 15th. Visit your account settings to renew if you'd like to continue the service.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.94},
    {"text": "Reminder: Your password hasn't been changed in 90 days. For security, we recommend updating it through the app settings.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Congratulations on your promotion! The team wanted to celebrate — are you free for lunch this Friday?", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Security notice: We've enabled two-factor authentication on your account as part of our company-wide security upgrade.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "The CEO will be joining the all-hands meeting tomorrow at 3 PM to present the quarterly results. Please attend if possible.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "URGENT: The production server is down. All engineers please join the incident bridge call immediately.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Your free trial of Adobe Creative Cloud ends in 7 days. Visit adobe.com/plans to see subscription options.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Alert: Scheduled maintenance tonight from 11 PM to 3 AM. You may experience brief service interruptions.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Hi, this is your manager. Can you send me the Q3 budget report by end of day? The director asked for it.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Your Amazon order #112-4835991 has shipped! Track your package at amazon.com/orders.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "We detected a login from a new device (Chrome on Windows). If this was you, no action is needed. Otherwise, reset your password in settings.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "ACTION REQUIRED: Please complete your annual compliance training by March 31st. Access it through the HR portal.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Congratulations — you've earned enough loyalty points for a $25 reward! Redeem in the app under 'My Rewards'.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.94},
    {"text": "Your payment of $149.99 to Netflix has been processed. If you did not authorize this charge, contact your bank directly.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},

    # ═══════════════════════════════════════════════════════════════
    #  NORMAL COMMUNICATION  (15)
    # ═══════════════════════════════════════════════════════════════
    {"text": "Hey, can we schedule a meeting for next Tuesday at 2 PM?", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Here are the quarterly reports you requested. Let me know if you need any clarification.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Thanks for your email. I'll review the documents and get back to you by Friday.", "label": "legitimate", "category": "normal_communication", "confidence": 0.96},
    {"text": "Good morning! Hope you're having a great day. Looking forward to our meeting.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Let's catch up over coffee sometime next week. Are you free on Wednesday?", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "Attached is the invoice for your review. Payment is due within 30 days.", "label": "legitimate", "category": "normal_communication", "confidence": 0.96},
    {"text": "Thank you for your order! Your package will arrive in 3-5 business days.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Reminder: Team standup meeting at 10 AM tomorrow. Please join via the usual Zoom link.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Just checking in — how's the project going? Let me know if you need any help from my side.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Happy birthday! Wishing you a wonderful year ahead. Enjoy your special day!", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "I've shared the Google Doc with you. Feel free to leave comments or suggestions directly in the document.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "The client loved the presentation! Great job on the design and the data analysis. Let's discuss next steps Monday.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "I'll be out of office next week on vacation. Please reach out to Sarah for anything urgent while I'm away.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Could you review the pull request I submitted this morning? It's a small bug fix for the login page.", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "We're organizing a team lunch for next Friday. Please fill out the form to let us know your dietary preferences.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
]