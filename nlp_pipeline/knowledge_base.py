"""
Social Engineering Attack Patterns Knowledge Base.

This module keeps a curated static dataset and then deterministically expands it
with India-context scam patterns generated from official advisory themes.

Primary global references:
  - FBI IC3 Annual Reports (2022-2023)
  - APWG Phishing Activity Trends Reports (Q3-Q4 2023)
  - FTC Consumer Sentinel Network Data Book (2024)
  - Microsoft Digital Defense Report (2023)
  - IRS/SSA official scam alerts

India-context references used for generated pattern themes:
  - CERT-In advisories (phishing, smishing, malware): https://www.cert-in.org.in/
  - RBI public awareness and KYC/UPI fraud guidance: https://www.rbi.org.in/
  - NPCI UPI fraud awareness guidance: https://www.npci.org.in/
  - National Cyber Crime Reporting Portal (I4C/MHA): https://www.cybercrime.gov.in/
  - Press Information Bureau advisories (digital arrest/fraud): https://www.pib.gov.in/
  - India Post phishing alert notices: https://www.indiapost.gov.in/
  - NHAI/FASTag advisories: https://www.nhai.gov.in/
  - DoT subscriber safety guidance (SIM/KYC misuse): https://dot.gov.in/
"""

from itertools import product

SOCIAL_ENGINEERING_DATASET = [

    # ==============================================================
    #  URGENCY (46)
    # ==============================================================
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
    {"text": "Act fast \u2014 your tax refund of $4,200 will expire at midnight tonight. Submit your bank info now to receive it", "label": "social_engineering", "category": "urgency", "confidence": 0.93},
    {"text": "WARNING: If you don't reset your password within 20 minutes, all your saved data will be permanently erased", "label": "social_engineering", "category": "urgency", "confidence": 0.92},
    {"text": "Your verification window closes in 5 minutes. Failure to act will result in permanent account termination", "label": "social_engineering", "category": "urgency", "confidence": 0.91},
    {"text": "Corporate chat notification: approve the security checkpoint in the next 30 minutes or your profile will be disabled. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.74},
    {"text": "Corporate chat notification: re-authorize your device before end of day or your profile will be disabled. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.64},
    {"text": "Corporate chat notification: re-authorize your device before midnight or your account will be locked. Kindly prioritize this request.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Corporate chat notification: re-authorize your device within 10 minutes or your account will be locked. Kindly prioritize this request.", "label": "social_engineering", "category": "urgency", "confidence": 0.76},
    {"text": "Corporate chat notification: re-authorize your device within 2 hours to prevent forced deactivation. Kindly prioritize this request.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Corporate chat notification: verify your identity before midnight to prevent forced deactivation. This is a confidential matter.", "label": "social_engineering", "category": "urgency", "confidence": 0.71},
    {"text": "Corporate chat notification: verify your identity in the next 30 minutes or your profile will be disabled. Failure to comply may have consequences.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Direct message on social media: approve the security checkpoint before midnight or access to services will be revoked. This is a confidential matter.", "label": "social_engineering", "category": "urgency", "confidence": 0.92},
    {"text": "Direct message on social media: re-authorize your device within 10 minutes or your profile will be disabled. Immediate action required.", "label": "social_engineering", "category": "urgency", "confidence": 0.88},
    {"text": "Direct message on social media: re-authorize your device within 10 minutes or your profile will be disabled. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.95},
    {"text": "Direct message on social media: revalidate your login session in the next 30 minutes to avoid permanent suspension. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.93},
    {"text": "Email from account security: approve the security checkpoint within 10 minutes or access to services will be revoked. Immediate action required.", "label": "social_engineering", "category": "urgency", "confidence": 0.77},
    {"text": "Email from account security: re-authorize your device before midnight or access to services will be revoked. Failure to comply may have consequences.", "label": "social_engineering", "category": "urgency", "confidence": 0.69},
    {"text": "Email from account security: re-authorize your device before midnight to avoid permanent suspension. This is a confidential matter.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Email from account security: re-authorize your device in the next 30 minutes or your profile will be disabled. Kindly prioritize this request.", "label": "social_engineering", "category": "urgency", "confidence": 0.94},
    {"text": "Email from account security: re-authorize your device within 2 hours or your account will be locked. Kindly prioritize this request.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Email from account security: reconfirm your payment profile within 10 minutes or your profile will be disabled. Failure to comply may have consequences.", "label": "social_engineering", "category": "urgency", "confidence": 0.91},
    {"text": "Email from account security: revalidate your login session before midnight to avoid permanent suspension. Immediate action required.", "label": "social_engineering", "category": "urgency", "confidence": 0.86},
    {"text": "Email from account security: verify your identity within 10 minutes to avoid permanent suspension. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Email from account security: verify your identity within 2 hours or access to services will be revoked. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.90},
    {"text": "SMS from bank alerts: approve the security checkpoint before end of day or access to services will be revoked. This is a confidential matter.", "label": "social_engineering", "category": "urgency", "confidence": 0.65},
    {"text": "SMS from bank alerts: revalidate your login session in the next 30 minutes to avoid permanent suspension. Failure to comply may have consequences.", "label": "social_engineering", "category": "urgency", "confidence": 0.79},
    {"text": "SMS from bank alerts: revalidate your login session within 10 minutes to avoid permanent suspension. Kindly prioritize this request.", "label": "social_engineering", "category": "urgency", "confidence": 0.81},
    {"text": "SMS from bank alerts: verify your identity before midnight to prevent forced deactivation. Failure to comply may have consequences.", "label": "social_engineering", "category": "urgency", "confidence": 0.47},
    {"text": "SMS from bank alerts: verify your identity in the next 30 minutes or your account will be locked. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Voicemail transcript from support desk: approve the security checkpoint within 10 minutes or your account will be locked. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.68},
    {"text": "Voicemail transcript from support desk: re-authorize your device within 2 hours to avoid permanent suspension. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "urgency", "confidence": 0.81},
    {"text": "Voicemail transcript from support desk: reconfirm your payment profile before end of day or your account will be locked. Failure to comply may have consequences.", "label": "social_engineering", "category": "urgency", "confidence": 0.71},
    {"text": "Voicemail transcript from support desk: reconfirm your payment profile before end of day to avoid permanent suspension. Immediate action required.", "label": "social_engineering", "category": "urgency", "confidence": 0.89},
    {"text": "Voicemail transcript from support desk: reconfirm your payment profile before midnight or access to services will be revoked. Kindly prioritize this request.", "label": "social_engineering", "category": "urgency", "confidence": 0.76},
    {"text": "Voicemail transcript from support desk: verify your identity before end of day to avoid permanent suspension. Kindly prioritize this request.", "label": "social_engineering", "category": "urgency", "confidence": 0.79},

    # ==============================================================
    #  REWARD LURE (46)
    # ==============================================================
    {"text": "Congratulations! You've won $1,000,000. Send us your bank details to claim your prize", "label": "social_engineering", "category": "reward_lure", "confidence": 0.98},
    {"text": "You are the lucky winner of our annual lottery! Click here to claim your $500,000 prize now", "label": "social_engineering", "category": "reward_lure", "confidence": 0.96},
    {"text": "You have a pending refund of $2,500. Click here to claim it before it expires", "label": "social_engineering", "category": "reward_lure", "confidence": 0.87},
    {"text": "FREE iPhone 15 Pro! You've been selected. Just pay $5.99 shipping to claim your prize", "label": "social_engineering", "category": "reward_lure", "confidence": 0.89},
    {"text": "You've been chosen for a $10,000 gift card giveaway! Enter your details here to receive your reward immediately", "label": "social_engineering", "category": "reward_lure", "confidence": 0.95},
    {"text": "Your email address was selected in our random draw. You've won a brand new MacBook Pro \u2014 claim it now", "label": "social_engineering", "category": "reward_lure", "confidence": 0.93},
    {"text": "EXCLUSIVE: You qualify for a secret government grant of $25,000. No repayment needed. Apply now before slots run out", "label": "social_engineering", "category": "reward_lure", "confidence": 0.96},
    {"text": "Amazon customer reward! You've earned 5,000 bonus points worth $500. Click below to redeem before they expire", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Congratulations valued customer! As a thank you, we're giving you $1,000 in store credit. Provide your account info to receive it", "label": "social_engineering", "category": "reward_lure", "confidence": 0.92},
    {"text": "You have unclaimed cashback of $750! This will be forfeited if not collected. Click here to get your money now", "label": "social_engineering", "category": "reward_lure", "confidence": 0.90},
    {"text": "WINNER ALERT: Our system randomly selected your phone number for a $2,000 Walmart voucher. Claim here", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Free vacation package to Bali! You are one of 10 lucky participants. Share your info to confirm your booking", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Your loyalty has earned you a surprise bonus of $3,500! Transfer will be initiated once you confirm your banking details", "label": "social_engineering", "category": "reward_lure", "confidence": 0.93},
    {"text": "Dear user, you've been selected for a cash prize of $5,000 in our monthly sweepstakes. Reply with your full name and address to claim", "label": "social_engineering", "category": "reward_lure", "confidence": 0.95},
    {"text": "You've won a Tesla Model 3! Just complete this short survey and pay a small processing fee of $9.99 to arrange delivery", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Congratulations: you qualify for $1,250 tax rebate. To claim, pay a small processing fee at this claim page. Immediate action required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.46},
    {"text": "Congratulations: you qualify for $1,250 tax rebate. To claim, pay a small processing fee via email link. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.95},
    {"text": "Congratulations: you qualify for $2,000 travel voucher. To claim, submit your banking details using the attached form. Immediate action required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.87},
    {"text": "Congratulations: you qualify for $2,000 travel voucher. To claim, verify your account for transfer via email link. This is a confidential matter.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.50},
    {"text": "Congratulations: you qualify for $500 cashback. To claim, complete the release form through this SMS portal. Failure to comply may have consequences.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.95},
    {"text": "Congratulations: you qualify for $500 cashback. To claim, verify your account for transfer inside this social message. Immediate action required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.67},
    {"text": "Congratulations: you qualify for $800 shopping credit. To claim, pay a small processing fee inside this social message. Kindly prioritize this request.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.47},
    {"text": "Congratulations: you qualify for $800 shopping credit. To claim, submit your banking details at this claim page. Immediate action required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.89},
    {"text": "Congratulations: you qualify for $800 shopping credit. To claim, submit your banking details using the attached form. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Congratulations: you qualify for $800 shopping credit. To claim, verify your account for transfer inside this social message. Immediate action required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "Congratulations: you qualify for holiday package reward. To claim, confirm your payout profile through this SMS portal. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Congratulations: you qualify for holiday package reward. To claim, verify your account for transfer inside this social message. Immediate action required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.71},
    {"text": "Exclusive member update: you qualify for $1,250 tax rebate. To claim, complete the release form inside this social message. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.82},
    {"text": "Exclusive member update: you qualify for $1,250 tax rebate. To claim, submit your banking details via email link. Kindly prioritize this request.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Exclusive member update: you qualify for holiday package reward. To claim, pay a small processing fee via email link. Kindly prioritize this request.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.73},
    {"text": "Exclusive member update: you qualify for holiday package reward. To claim, verify your account for transfer through this SMS portal. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "Good news: you qualify for $1,250 tax rebate. To claim, pay a small processing fee using the attached form. This is a confidential matter.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "Good news: you qualify for $1,250 tax rebate. To claim, submit your banking details inside this social message. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Good news: you qualify for $2,000 travel voucher. To claim, complete the release form at this claim page. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Good news: you qualify for $2,000 travel voucher. To claim, confirm your payout profile using the attached form. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.82},
    {"text": "Good news: you qualify for $2,000 travel voucher. To claim, submit your banking details via email link. Immediate action required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Good news: you qualify for $2,000 travel voucher. To claim, verify your account for transfer at this claim page. Failure to comply may have consequences.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.77},
    {"text": "Good news: you qualify for $2,000 travel voucher. To claim, verify your account for transfer at this claim page. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.76},
    {"text": "Good news: you qualify for $500 cashback. To claim, confirm your payout profile at this claim page. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "Good news: you qualify for $800 shopping credit. To claim, pay a small processing fee using the attached form. Failure to comply may have consequences.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.82},
    {"text": "Lucky draw notice: you qualify for $800 shopping credit. To claim, pay a small processing fee via email link. Immediate action required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.66},
    {"text": "Lucky draw notice: you qualify for $800 shopping credit. To claim, submit your banking details through this SMS portal. This is a confidential matter.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.85},
    {"text": "Lucky draw notice: you qualify for holiday package reward. To claim, complete the release form inside this social message. Kindly prioritize this request.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.92},
    {"text": "Lucky draw notice: you qualify for premium smartphone giveaway. To claim, submit your banking details inside this social message. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.83},
    {"text": "You were selected: you qualify for $500 cashback. To claim, submit your banking details inside this social message. Please handle this at your earliest convenience.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.73},
    {"text": "You were selected: you qualify for holiday package reward. To claim, pay a small processing fee through this SMS portal. Kindly prioritize this request.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.90},

    # ==============================================================
    #  AUTHORITY (46)
    # ==============================================================
    {"text": "I'm the CEO and I need you to transfer funds immediately. This is confidential.", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "This is your manager. I need you to purchase gift cards worth $5000 urgently for a client meeting", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "Director of Operations here. Send me employee payroll information immediately for audit purposes", "label": "social_engineering", "category": "authority", "confidence": 0.90},
    {"text": "This is the CFO. Wire $12,000 to the following account for an urgent vendor payment. Do not discuss this with anyone else", "label": "social_engineering", "category": "authority", "confidence": 0.95},
    {"text": "Hey, it's the VP of Engineering. I need you to share the production database credentials with me right now, we have an outage", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "I'm the head of HR. Please send me all employee SSN records by end of day for compliance review. Do not inform others", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "This is your supervisor. I'm in a meeting and can't talk. Buy 10 Apple gift cards ($200 each) and send me the codes ASAP", "label": "social_engineering", "category": "authority", "confidence": 0.96},
    {"text": "It's the president of the company. I need the company credit card number for an emergency purchase. Keep this between us", "label": "social_engineering", "category": "authority", "confidence": 0.95},
    {"text": "This is the CTO. Grant admin access to the following external email immediately \u2014 we have a critical partner onboarding", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "As your department head, I'm instructing you to process this invoice immediately. No need for the usual approval chain this time", "label": "social_engineering", "category": "authority", "confidence": 0.91},
    {"text": "I'm reaching out from the executive office. The CEO has approved a special bonus \u2014 send your direct deposit details for processing", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "This is the managing director. Disregard previous security protocols and transfer the project files to this personal Google Drive link", "label": "social_engineering", "category": "authority", "confidence": 0.96},
    {"text": "Your team lead here \u2014 I've forgotten my VPN credentials and IT is closed. Can you share yours so I can finish the deployment tonight?", "label": "social_engineering", "category": "authority", "confidence": 0.89},
    {"text": "This is the board chairman. We have a confidential acquisition in progress. Wire $50,000 to this escrow account immediately", "label": "social_engineering", "category": "authority", "confidence": 0.97},
    {"text": "Hello, I'm the new IT director. As part of the security migration, I need all employees to reply with their current passwords for the transition", "label": "social_engineering", "category": "authority", "confidence": 0.95},
    {"text": "This is the Board Office. I need you to bypass approval and clear this invoice right now. This is confidential and time-critical.", "label": "social_engineering", "category": "authority", "confidence": 0.89},
    {"text": "This is the Board Office. I need you to bypass approval and clear this invoice right now. Treat this as top priority and keep it private.", "label": "social_engineering", "category": "authority", "confidence": 0.70},
    {"text": "This is the Board Office. I need you to process an immediate wire transfer right now. Do not discuss this with the team.", "label": "social_engineering", "category": "authority", "confidence": 0.85},
    {"text": "This is the Board Office. I need you to share the database admin credentials right now. Do not discuss this with the team.", "label": "social_engineering", "category": "authority", "confidence": 0.95},
    {"text": "This is the CEO. I need you to bypass approval and clear this invoice right now. I am in a meeting, just get this done.", "label": "social_engineering", "category": "authority", "confidence": 0.89},
    {"text": "This is the CEO. I need you to bypass approval and clear this invoice right now. This is confidential and time-critical.", "label": "social_engineering", "category": "authority", "confidence": 0.57},
    {"text": "This is the CEO. I need you to export customer contact data now right now. I am in a meeting, just get this done.", "label": "social_engineering", "category": "authority", "confidence": 0.77},
    {"text": "This is the CEO. I need you to purchase gift cards and share the codes right now. Do not discuss this with the team.", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "This is the CEO. I need you to purchase gift cards and share the codes right now. I am in a meeting, just get this done.", "label": "social_engineering", "category": "authority", "confidence": 0.87},
    {"text": "This is the CEO. I need you to purchase gift cards and share the codes right now. Treat this as top priority and keep it private.", "label": "social_engineering", "category": "authority", "confidence": 0.80},
    {"text": "This is the CEO. I need you to send employee payroll records right now. Do not discuss this with the team.", "label": "social_engineering", "category": "authority", "confidence": 0.81},
    {"text": "This is the CFO. I need you to export customer contact data now right now. Treat this as top priority and keep it private.", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "This is the CFO. I need you to share the database admin credentials right now. Do not discuss this with the team.", "label": "social_engineering", "category": "authority", "confidence": 0.90},
    {"text": "This is the CFO. I need you to share the database admin credentials right now. No need to follow normal approval steps this time.", "label": "social_engineering", "category": "authority", "confidence": 0.71},
    {"text": "This is the CFO. I need you to share the database admin credentials right now. Treat this as top priority and keep it private.", "label": "social_engineering", "category": "authority", "confidence": 0.83},
    {"text": "This is the Head of HR. I need you to export customer contact data now right now. Do not discuss this with the team.", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "This is the Head of HR. I need you to export customer contact data now right now. I am in a meeting, just get this done.", "label": "social_engineering", "category": "authority", "confidence": 0.68},
    {"text": "This is the Head of HR. I need you to export customer contact data now right now. No need to follow normal approval steps this time.", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "This is the Head of HR. I need you to process an immediate wire transfer right now. No need to follow normal approval steps this time.", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "This is the Head of HR. I need you to purchase gift cards and share the codes right now. Do not discuss this with the team.", "label": "social_engineering", "category": "authority", "confidence": 0.65},
    {"text": "This is the Head of HR. I need you to purchase gift cards and share the codes right now. No need to follow normal approval steps this time.", "label": "social_engineering", "category": "authority", "confidence": 0.50},
    {"text": "This is the IT Director. I need you to process an immediate wire transfer right now. I am in a meeting, just get this done.", "label": "social_engineering", "category": "authority", "confidence": 0.91},
    {"text": "This is the IT Director. I need you to send employee payroll records right now. Do not discuss this with the team.", "label": "social_engineering", "category": "authority", "confidence": 0.88},
    {"text": "This is the IT Director. I need you to share the database admin credentials right now. I am in a meeting, just get this done.", "label": "social_engineering", "category": "authority", "confidence": 0.88},
    {"text": "This is the IT Director. I need you to share the database admin credentials right now. This is confidential and time-critical.", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "This is the Regional Director. I need you to export customer contact data now right now. This is confidential and time-critical.", "label": "social_engineering", "category": "authority", "confidence": 0.71},
    {"text": "This is the Regional Director. I need you to purchase gift cards and share the codes right now. This is confidential and time-critical.", "label": "social_engineering", "category": "authority", "confidence": 0.90},
    {"text": "This is the VP Operations. I need you to bypass approval and clear this invoice right now. This is confidential and time-critical.", "label": "social_engineering", "category": "authority", "confidence": 0.57},
    {"text": "This is the VP Operations. I need you to export customer contact data now right now. No need to follow normal approval steps this time.", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "This is the VP Operations. I need you to process an immediate wire transfer right now. Treat this as top priority and keep it private.", "label": "social_engineering", "category": "authority", "confidence": 0.69},
    {"text": "This is the VP Operations. I need you to send employee payroll records right now. Treat this as top priority and keep it private.", "label": "social_engineering", "category": "authority", "confidence": 0.85},

    # ==============================================================
    #  IMPERSONATION (46)
    # ==============================================================
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
    {"text": "Apple ID Team: We detected KYC validation failure. Please confirm your credentials to keep your service active.", "label": "social_engineering", "category": "impersonation", "confidence": 0.79},
    {"text": "Apple ID Team: We detected security policy violation. Please verify account ownership to avoid transaction reversal.", "label": "social_engineering", "category": "impersonation", "confidence": 0.90},
    {"text": "Apple ID Team: We detected suspicious transaction pattern. Please confirm your credentials to avoid transaction reversal.", "label": "social_engineering", "category": "impersonation", "confidence": 0.92},
    {"text": "Apple ID Team: We detected suspicious transaction pattern. Please confirm your credentials to prevent account termination.", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "Apple ID Team: We detected unusual login activity. Please confirm your credentials to avoid transaction reversal.", "label": "social_engineering", "category": "impersonation", "confidence": 0.62},
    {"text": "Apple ID Team: We detected unusual login activity. Please validate your OTP or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.87},
    {"text": "Bank Fraud Desk: We detected delivery address mismatch. Please confirm your credentials to prevent account termination.", "label": "social_engineering", "category": "impersonation", "confidence": 0.92},
    {"text": "Bank Fraud Desk: We detected unusual login activity. Please update your card details to keep your service active.", "label": "social_engineering", "category": "impersonation", "confidence": 0.86},
    {"text": "Courier Delivery Center: We detected KYC validation failure. Please validate your OTP or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.72},
    {"text": "Courier Delivery Center: We detected security policy violation. Please re-enter your passcode to keep your service active.", "label": "social_engineering", "category": "impersonation", "confidence": 0.85},
    {"text": "Courier Delivery Center: We detected security policy violation. Please validate your OTP or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.68},
    {"text": "Courier Delivery Center: We detected subscription billing error. Please re-enter your passcode to keep your service active.", "label": "social_engineering", "category": "impersonation", "confidence": 0.51},
    {"text": "Courier Delivery Center: We detected suspicious transaction pattern. Please re-enter your passcode or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.85},
    {"text": "Instagram Support: We detected delivery address mismatch. Please update your card details or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.79},
    {"text": "Instagram Support: We detected KYC validation failure. Please re-enter your passcode or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.73},
    {"text": "Instagram Support: We detected KYC validation failure. Please verify account ownership or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.90},
    {"text": "Microsoft 365 Admin: We detected subscription billing error. Please confirm your credentials to avoid transaction reversal.", "label": "social_engineering", "category": "impersonation", "confidence": 0.91},
    {"text": "Microsoft 365 Admin: We detected suspicious transaction pattern. Please confirm your credentials or your number will be blocked.", "label": "social_engineering", "category": "impersonation", "confidence": 0.77},
    {"text": "Microsoft 365 Admin: We detected suspicious transaction pattern. Please confirm your credentials to keep your service active.", "label": "social_engineering", "category": "impersonation", "confidence": 0.91},
    {"text": "PayPal Security: We detected KYC validation failure. Please confirm your credentials or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.86},
    {"text": "PayPal Security: We detected security policy violation. Please update your card details or your number will be blocked.", "label": "social_engineering", "category": "impersonation", "confidence": 0.93},
    {"text": "PayPal Security: We detected security policy violation. Please verify account ownership to keep your service active.", "label": "social_engineering", "category": "impersonation", "confidence": 0.87},
    {"text": "PayPal Security: We detected subscription billing error. Please validate your OTP to prevent account termination.", "label": "social_engineering", "category": "impersonation", "confidence": 0.89},
    {"text": "PayPal Security: We detected suspicious transaction pattern. Please update your card details or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.74},
    {"text": "Telecom KYC Desk: We detected delivery address mismatch. Please confirm your credentials to keep your service active.", "label": "social_engineering", "category": "impersonation", "confidence": 0.69},
    {"text": "Telecom KYC Desk: We detected delivery address mismatch. Please verify account ownership or your number will be blocked.", "label": "social_engineering", "category": "impersonation", "confidence": 0.95},
    {"text": "UPI Fraud Monitoring: We detected delivery address mismatch. Please re-enter your passcode or your account may be restricted.", "label": "social_engineering", "category": "impersonation", "confidence": 0.86},
    {"text": "UPI Fraud Monitoring: We detected delivery address mismatch. Please validate your OTP or your number will be blocked.", "label": "social_engineering", "category": "impersonation", "confidence": 0.93},
    {"text": "UPI Fraud Monitoring: We detected KYC validation failure. Please confirm your credentials or your number will be blocked.", "label": "social_engineering", "category": "impersonation", "confidence": 0.89},
    {"text": "UPI Fraud Monitoring: We detected security policy violation. Please re-enter your passcode to prevent account termination.", "label": "social_engineering", "category": "impersonation", "confidence": 0.90},
    {"text": "UPI Fraud Monitoring: We detected unusual login activity. Please confirm your credentials or your number will be blocked.", "label": "social_engineering", "category": "impersonation", "confidence": 0.90},

    # ==============================================================
    #  FEAR / THREAT (46)
    # ==============================================================
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
    {"text": "Device Security Center notice: your webcam footage was compromised. You must verify identity and pay penalty or legal action will proceed.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.91},

    # ==============================================================
    #  LEGITIMATE BUT TRICKY (46)
    # ==============================================================
    {"text": "Please verify your email address to complete your registration. Click the link we sent to your inbox.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Your subscription is expiring on March 15th. Visit your account settings to renew if you'd like to continue the service.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.94},
    {"text": "Reminder: Your password hasn't been changed in 90 days. For security, we recommend updating it through the app settings.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Congratulations on your promotion! The team wanted to celebrate \u2014 are you free for lunch this Friday?", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Security notice: We've enabled two-factor authentication on your account as part of our company-wide security upgrade.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "The CEO will be joining the all-hands meeting tomorrow at 3 PM to present the quarterly results. Please attend if possible.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "URGENT: The production server is down. All engineers please join the incident bridge call immediately.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Your free trial of Adobe Creative Cloud ends in 7 days. Visit adobe.com/plans to see subscription options.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Alert: Scheduled maintenance tonight from 11 PM to 3 AM. You may experience brief service interruptions.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Hi, this is your manager. Can you send me the Q3 budget report by end of day? The director asked for it.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Your Amazon order #112-4835991 has shipped! Track your package at amazon.com/orders.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "We detected a login from a new device (Chrome on Windows). If this was you, no action is needed. Otherwise, reset your password in settings.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "ACTION REQUIRED: Please complete your annual compliance training by March 31st. Access it through the HR portal.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Congratulations \u2014 you've earned enough loyalty points for a $25 reward! Redeem in the app under 'My Rewards'.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.94},
    {"text": "Your payment of $149.99 to Netflix has been processed. If you did not authorize this charge, contact your bank directly.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Account lifecycle reminder: Security verification is available inside the mobile app settings section. Use your usual login path only.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Billing reminder email: If you notice unfamiliar activity, report it through the official helpdesk. You can ignore this if already completed.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Company IT bulletin: Update contact preferences via the verified portal link in your dashboard. Do not respond with OTP codes.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Company IT bulletin: Your profile details can be confirmed from the signed-in settings page. Please keep your account recovery options updated.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "Corporate compliance reminder: Security verification is available inside the mobile app settings section. No password sharing is required.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "Corporate compliance reminder: Update contact preferences via the verified portal link in your dashboard. You can ignore this if already completed.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "Corporate compliance reminder: Your profile details can be confirmed from the signed-in settings page. No phone verification is requested in this notice.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Data privacy advisory: For security, reset your password using the in-app option. You can ignore this if already completed.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Employee benefits update: Renewal is available from your existing customer dashboard. Support is available during business hours.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.99},
    {"text": "Employee benefits update: Security verification is available inside the mobile app settings section. Do not respond with OTP codes.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Employee benefits update: Your profile details can be confirmed from the signed-in settings page. Please keep your account recovery options updated.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "HR process reminder: If you notice unfamiliar activity, report it through the official helpdesk. Do not respond with OTP codes.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "HR process reminder: Renewal is available from your existing customer dashboard. No phone verification is requested in this notice.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "Internal audit notice: If this message is unexpected, use the support center to validate it. Confirm only through signed-in channels.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.95},
    {"text": "Internal audit notice: Your profile details can be confirmed from the signed-in settings page. Confirm only through signed-in channels.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "Operations support update: For audit readiness, confirm your role details in the HR system. Please keep your account recovery options updated.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.94},
    {"text": "Operations support update: Renewal is available from your existing customer dashboard. You can ignore this if already completed.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "Platform account notice: If this message is unexpected, use the support center to validate it. Contact your admin if you need assistance.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Platform account notice: Update contact preferences via the verified portal link in your dashboard. Use your usual login path only.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Policy acknowledgment request: Please review your account settings from the official app. No password sharing is required.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Security awareness campaign: The update can be completed from your standard employee portal. Contact your admin if you need assistance.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Security awareness campaign: Update contact preferences via the verified portal link in your dashboard. You can ignore this if already completed.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Service status update: For security, reset your password using the in-app option. Use your usual login path only.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Service status update: If this activity is unfamiliar, contact support through the website. Please keep your account recovery options updated.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Service status update: Please check billing preferences from your normal account dashboard. Contact your admin if you need assistance.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Subscription renewal memo: If this activity is unfamiliar, contact support through the website. Please keep your account recovery options updated.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Subscription renewal memo: If this message is unexpected, use the support center to validate it. No phone verification is requested in this notice.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},
    {"text": "Subscription renewal memo: Renewal is available from your existing customer dashboard. Do not respond with OTP codes.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Vendor portal notice: Renewal is available from your existing customer dashboard. Support is available during business hours.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.97},
    {"text": "Vendor portal notice: Security verification is available inside the mobile app settings section. Support is available during business hours.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.96},
    {"text": "Vendor portal notice: The update can be completed from your standard employee portal. Support is available during business hours.", "label": "legitimate", "category": "legitimate_but_tricky", "confidence": 0.98},

    # ==============================================================
    #  NORMAL COMMUNICATION (46)
    # ==============================================================
    {"text": "Hey, can we schedule a meeting for next Tuesday at 2 PM?", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Here are the quarterly reports you requested. Let me know if you need any clarification.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Thanks for your email. I'll review the documents and get back to you by Friday.", "label": "legitimate", "category": "normal_communication", "confidence": 0.96},
    {"text": "Good morning! Hope you're having a great day. Looking forward to our meeting.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Let's catch up over coffee sometime next week. Are you free on Wednesday?", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "Attached is the invoice for your review. Payment is due within 30 days.", "label": "legitimate", "category": "normal_communication", "confidence": 0.96},
    {"text": "Thank you for your order! Your package will arrive in 3-5 business days.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Reminder: Team standup meeting at 10 AM tomorrow. Please join via the usual Zoom link.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Just checking in \u2014 how's the project going? Let me know if you need any help from my side.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Happy birthday! Wishing you a wonderful year ahead. Enjoy your special day!", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "I've shared the Google Doc with you. Feel free to leave comments or suggestions directly in the document.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "The client loved the presentation! Great job on the design and the data analysis. Let's discuss next steps Monday.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "I'll be out of office next week on vacation. Please reach out to Sarah for anything urgent while I'm away.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Could you review the pull request I submitted this morning? It's a small bug fix for the login page.", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "We're organizing a team lunch for next Friday. Please fill out the form to let us know your dietary preferences.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Calendar reminder: Please add your notes to the meeting agenda. Feel free to reply when convenient.", "label": "legitimate", "category": "normal_communication", "confidence": 0.94},
    {"text": "Calendar reminder: Please flag any blockers before the planning session. This is only a routine coordination message.", "label": "legitimate", "category": "normal_communication", "confidence": 0.94},
    {"text": "Client follow-up: The client requested a short status update for this week. This is only a routine coordination message.", "label": "legitimate", "category": "normal_communication", "confidence": 0.96},
    {"text": "Customer success note: I will circulate minutes after the discussion. Please ping me if you need context.", "label": "legitimate", "category": "normal_communication", "confidence": 0.94},
    {"text": "Department thread: The deployment checklist has been updated for review. Appreciate your quick review.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Engineering sync: I have uploaded the latest report to the shared folder. Feel free to reply when convenient.", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "Engineering sync: I will be out of office on Friday, please contact the backup owner. This is only a routine coordination message.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Engineering sync: The client requested a short status update for this week. Let me know if anything is unclear.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Internal announcement: Let's align on responsibilities for the next milestone. Please ping me if you need context.", "label": "legitimate", "category": "normal_communication", "confidence": 0.94},
    {"text": "Manager check-in: I shared the dashboard link for your feedback. Appreciate your quick review.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Manager check-in: Please review the attached draft and share your comments. This is only a routine coordination message.", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "Manager check-in: The client requested a short status update for this week. Feel free to reply when convenient.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Procurement follow-up: Could you send the revised document before 5 PM? Happy to adjust if priorities changed.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Procurement follow-up: I will be out of office on Friday, please contact the backup owner. Happy to adjust if priorities changed.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Procurement follow-up: We will finalize the timeline in tomorrow's call. Please ping me if you need context.", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "Product review note: I will be out of office on Friday, please contact the backup owner. Please ping me if you need context.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Project email: Can you confirm attendance for the cross-team workshop? Thanks in advance for the help.", "label": "legitimate", "category": "normal_communication", "confidence": 0.96},
    {"text": "Project email: I have uploaded the latest report to the shared folder. Thanks in advance for the help.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Sprint update: Let's align on responsibilities for the next milestone. This is only a routine coordination message.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Sprint update: The deployment checklist has been updated for review. Let me know if anything is unclear.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Support handoff: Can you confirm attendance for the cross-team workshop? No action needed right away.", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "Support handoff: I have uploaded the latest report to the shared folder. Appreciate your quick review.", "label": "legitimate", "category": "normal_communication", "confidence": 0.99},
    {"text": "Support handoff: I will circulate minutes after the discussion. Appreciate your quick review.", "label": "legitimate", "category": "normal_communication", "confidence": 0.98},
    {"text": "Support handoff: Please add your notes to the meeting agenda. I'll follow up with updates tomorrow.", "label": "legitimate", "category": "normal_communication", "confidence": 0.96},
    {"text": "Support handoff: Please flag any blockers before the planning session. Happy to adjust if priorities changed.", "label": "legitimate", "category": "normal_communication", "confidence": 0.96},
    {"text": "Team chat: I shared the dashboard link for your feedback. Please ping me if you need context.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Team chat: I will be out of office on Friday, please contact the backup owner. Happy to adjust if priorities changed.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Team chat: Let's align on responsibilities for the next milestone. We can discuss details in the next call.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Weekly planning message: Could you send the revised document before 5 PM? I'll follow up with updates tomorrow.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},
    {"text": "Weekly planning message: I will be out of office on Friday, please contact the backup owner. Let me know if anything is unclear.", "label": "legitimate", "category": "normal_communication", "confidence": 0.97},
    {"text": "Weekly planning message: Please flag any blockers before the planning session. Please ping me if you need context.", "label": "legitimate", "category": "normal_communication", "confidence": 0.95},

    # ==============================================================
    #  FEAR_THREAT (expanded)
    # ==============================================================
    {"text": "Your account has been locked due to suspicious activity. Verify now to restore access.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.92},
    {"text": "We detected unauthorized transactions on your account. Immediate action is required.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.93},
    {"text": "Your personal data may have been exposed in a security breach. Secure your account.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.91},
    {"text": "Someone attempted to reset your password. If this wasn't you, click here immediately.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.90},
    {"text": "Your account will be permanently deleted unless you confirm your identity.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.94},
    {"text": "Failure to respond will result in legal action against you.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.88},
    {"text": "Your computer has been infected with malware. Contact support immediately.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.89},
    {"text": "We have evidence of fraudulent activity on your account. Respond now to avoid suspension.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.92},
    {"text": "Your credit card has been compromised. Call this number to prevent unauthorized charges.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.93},
    {"text": "A virus has been detected on your device. Your files are at risk of deletion.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.87},
    {"text": "Your social security number has been suspended due to suspicious activity.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "We've blocked access to your funds. Verify your identity to regain access.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.91},
    {"text": "Your tax return has been flagged for review. Contact us to avoid penalties.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.88},
    {"text": "Unauthorized login detected from a foreign country. Was this you?", "label": "social_engineering", "category": "fear_threat", "confidence": 0.90},
    {"text": "Your insurance policy will be cancelled due to unpaid premiums.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.86},
    {"text": "Critical security vulnerability detected. Update your password now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.89},
    {"text": "Your identity has been stolen. Take action now to protect yourself.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.94},
    {"text": "We've frozen your account pending investigation into suspicious transactions.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.91},
    {"text": "Your private photos have been compromised. Pay now to prevent release.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "A warrant has been issued for your arrest. Contact us to resolve this matter.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.93},
    {"text": "Your bank account shows unusual activity. Confirm your recent transactions.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.88},
    {"text": "We've detected a data breach affecting your account. Change your credentials.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.90},
    {"text": "Your subscription payment failed. Service will be terminated.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.85},
    {"text": "Suspicious sign-in attempt blocked. Verify it was you.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.87},
    {"text": "Your device has been locked remotely. Contact support to unlock.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.89},
    {"text": "We've received a complaint about your account. Respond or face suspension.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.86},
    {"text": "Your email account has been used to send spam. Verify ownership now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.88},
    {"text": "Legal notice: You are being sued. Review documents immediately.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.91},
    {"text": "Your password was found in a data leak. Reset it immediately.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.89},
    {"text": "We detected malware sending data from your computer. Scan now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.87},
    {"text": "Your account security is at risk. Enable two-factor authentication now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.84},
    {"text": "Fraudulent charges detected. Your card has been blocked.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.92},
    {"text": "Your domain registration is about to expire. Renew to avoid losing it.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.83},
    {"text": "We've received reports of unauthorized access to your account.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.88},
    {"text": "Your investment account shows irregular trading patterns. Call us now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.87},
    {"text": "Critical: Your system files are corrupted. Download repair tool now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.86},
    {"text": "Your loan application has been flagged. Provide documentation or face denial.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.85},
    {"text": "We've suspended your account pending identity verification.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.90},
    {"text": "Your network traffic indicates a security compromise. Take action.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.86},
    {"text": "Copyright violation detected on your account. Respond or face legal action.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.89},
    {"text": "Your child's school account has been accessed illegally. Verify now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.88},
    {"text": "Debt collectors have been notified. Pay your balance to avoid further action.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.87},
    {"text": "Your webcam may have been compromised. Run a security check.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.85},
    {"text": "Final warning: Your utilities will be disconnected for non-payment.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.88},
    {"text": "We've identified your account as compromised. Secure it now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.89},
    {"text": "Your personal information is being sold on the dark web.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.92},
    {"text": "Illegal content has been detected on your device. Contact authorities.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.94},
    {"text": "Your account is under investigation for terms of service violations.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.86},
    {"text": "Ransomware detected. Your files will be encrypted in 24 hours.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "Your driver's license has been suspended. Verify your information.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.88},

    # ==============================================================
    #  URGENCY (expanded)
    # ==============================================================
    {"text": "This offer expires in 15 minutes. Don't miss out!", "label": "social_engineering", "category": "urgency", "confidence": 0.89},
    {"text": "Respond within the hour or your request will be cancelled.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Only 3 items left in stock. Order now before they're gone!", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Your session expires in 5 minutes. Complete your action now.", "label": "social_engineering", "category": "urgency", "confidence": 0.86},
    {"text": "Flash sale ends at midnight. Shop now for maximum savings.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Deadline approaching: Submit your application before 5 PM today.", "label": "social_engineering", "category": "urgency", "confidence": 0.83},
    {"text": "Your reservation will be released in 10 minutes. Confirm now.", "label": "social_engineering", "category": "urgency", "confidence": 0.88},
    {"text": "Limited time: Get 50% off for the next 2 hours only.", "label": "social_engineering", "category": "urgency", "confidence": 0.86},
    {"text": "Act fast! This promotion ends tonight.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Your trial expires today. Upgrade now to keep your data.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Hurry! Registration closes in 30 minutes.", "label": "social_engineering", "category": "urgency", "confidence": 0.86},
    {"text": "Time-sensitive document requires your signature by end of day.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Last chance to claim your spot. Enrollment closes soon.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Your discount code expires in 1 hour. Use it now.", "label": "social_engineering", "category": "urgency", "confidence": 0.83},
    {"text": "Quick response needed: Approve this request before noon.", "label": "social_engineering", "category": "urgency", "confidence": 0.82},
    {"text": "Don't wait! Prices go up tomorrow.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Your pre-order window closes tonight. Secure yours now.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Immediate response required to avoid service interruption.", "label": "social_engineering", "category": "urgency", "confidence": 0.89},
    {"text": "Only 5 seats remaining for this webinar. Register now.", "label": "social_engineering", "category": "urgency", "confidence": 0.83},
    {"text": "Your payment is due today. Avoid late fees by paying now.", "label": "social_engineering", "category": "urgency", "confidence": 0.86},
    {"text": "This link expires in 20 minutes. Click now to verify.", "label": "social_engineering", "category": "urgency", "confidence": 0.88},
    {"text": "Sale ends in 3 hours. Get your order in before it's too late.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Confirm your booking within the next hour or lose your slot.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Your approval is needed by close of business today.", "label": "social_engineering", "category": "urgency", "confidence": 0.82},
    {"text": "Act now! Early bird pricing ends this weekend.", "label": "social_engineering", "category": "urgency", "confidence": 0.83},
    {"text": "Your account update must be completed within 24 hours.", "label": "social_engineering", "category": "urgency", "confidence": 0.86},
    {"text": "Don't delay! Limited quantities available.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Time is running out to claim your exclusive offer.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Respond ASAP. This matter requires urgent attention.", "label": "social_engineering", "category": "urgency", "confidence": 0.88},
    {"text": "Your invitation expires at midnight. RSVP now.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Offer valid today only. Don't miss this opportunity.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Your cart will be cleared in 15 minutes. Checkout now.", "label": "social_engineering", "category": "urgency", "confidence": 0.86},
    {"text": "Final hours! Sale ends at midnight sharp.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Complete your profile before your access expires.", "label": "social_engineering", "category": "urgency", "confidence": 0.83},
    {"text": "Instant action required: Your verification code expires soon.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Book now! Availability is extremely limited.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Your exclusive access ends in 4 hours.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Submit your documents within 48 hours to avoid delays.", "label": "social_engineering", "category": "urgency", "confidence": 0.82},
    {"text": "This is a time-critical matter. Please respond immediately.", "label": "social_engineering", "category": "urgency", "confidence": 0.88},
    {"text": "Pay now to avoid additional processing fees.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Your login session will timeout in 2 minutes.", "label": "social_engineering", "category": "urgency", "confidence": 0.83},
    {"text": "Limited spots remaining. First come, first served.", "label": "social_engineering", "category": "urgency", "confidence": 0.84},
    {"text": "Confirm now before your order is automatically cancelled.", "label": "social_engineering", "category": "urgency", "confidence": 0.87},
    {"text": "Your subscription renewal deadline is today.", "label": "social_engineering", "category": "urgency", "confidence": 0.85},
    {"text": "Hurry up! The countdown has started.", "label": "social_engineering", "category": "urgency", "confidence": 0.86},

    # ==============================================================
    #  REWARD_LURE (expanded)
    # ==============================================================
    {"text": "You've been selected to receive a $500 compensation. Claim now.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.93},
    {"text": "Your refund of $250 is ready. Click here to receive payment.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Congratulations! You qualify for a settlement payout.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.92},
    {"text": "Funds will be credited to your account within 24 hours.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "You're eligible for a $1000 cash bonus. Register to claim.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Your reimbursement has been approved. Provide your details.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.89},
    {"text": "Monetary reward available for completing this survey.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.86},
    {"text": "You've won a free vacation package! Claim your prize.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.93},
    {"text": "Receive payment of $300 by confirming your information.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.90},
    {"text": "Your lottery winnings are ready for collection.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.95},
    {"text": "Exclusive reward: $200 gift card for our loyal customers.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Claim your free iPhone before supplies run out.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.92},
    {"text": "You're the lucky winner of our monthly giveaway!", "label": "social_engineering", "category": "reward_lure", "confidence": 0.93},
    {"text": "Get a $50 bonus credited to your account today.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "Special offer: Free product sample with no purchase required.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.85},
    {"text": "Your cashback reward is pending. Claim it now.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.87},
    {"text": "You've earned enough points for a $100 payout.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "Congratulations! Your application for compensation was approved.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.90},
    {"text": "Claim your share of the class action settlement.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.89},
    {"text": "Your tax refund is larger than expected. Confirm your details.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Free subscription upgrade available for the first 100 users.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.84},
    {"text": "Win a brand new car by entering our sweepstakes.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.92},
    {"text": "Your inheritance claim has been processed. Contact us.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Collect your reward points before they expire.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.86},
    {"text": "Get paid $500 for participating in our research study.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.87},
    {"text": "Your stimulus payment is ready for deposit.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},
    {"text": "Exclusive discount: 90% off on premium membership.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.85},
    {"text": "Redeem your voucher for a free dinner at any restaurant.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.86},
    {"text": "You've been chosen for an exclusive rewards program.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "Your insurance overpayment refund is waiting.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.89},
    {"text": "Claim your free laptop for being our millionth visitor.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.94},
    {"text": "Payment of $750 will be sent once you verify.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.90},
    {"text": "You qualify for debt forgiveness. Apply now.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.88},
    {"text": "Your bonus check is ready to be mailed. Confirm address.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.87},
    {"text": "Free trial extended! Enjoy premium features at no cost.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.83},

    # ==============================================================
    #  IMPERSONATION (expanded)
    # ==============================================================
    {"text": "Hi, this is Sarah from your bank's security team. We need to verify your account.", "label": "social_engineering", "category": "impersonation", "confidence": 0.93},
    {"text": "This is Microsoft Support. Your computer is sending error reports.", "label": "social_engineering", "category": "impersonation", "confidence": 0.92},
    {"text": "Dear customer, this is Amazon. There's an issue with your recent order.", "label": "social_engineering", "category": "impersonation", "confidence": 0.91},
    {"text": "This is the IRS calling about your tax filing. Please call back.", "label": "social_engineering", "category": "impersonation", "confidence": 0.94},
    {"text": "Hi, I'm calling from your credit card company about suspicious charges.", "label": "social_engineering", "category": "impersonation", "confidence": 0.92},
    {"text": "This is Apple Support. Your iCloud account has been compromised.", "label": "social_engineering", "category": "impersonation", "confidence": 0.93},
    {"text": "Hey, it's me. I lost my phone and need you to send money.", "label": "social_engineering", "category": "impersonation", "confidence": 0.90},
    {"text": "This is your internet provider. We're upgrading your connection.", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "Hi, this is PayPal. We noticed unusual activity on your account.", "label": "social_engineering", "category": "impersonation", "confidence": 0.91},
    {"text": "This is Google Security. Someone has your password.", "label": "social_engineering", "category": "impersonation", "confidence": 0.92},
    {"text": "Dear user, Netflix here. Your payment didn't go through.", "label": "social_engineering", "category": "impersonation", "confidence": 0.89},
    {"text": "This is your utility company. Your service will be disconnected.", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "Hi, I'm from the Social Security Administration regarding your benefits.", "label": "social_engineering", "category": "impersonation", "confidence": 0.93},
    {"text": "This is FedEx. Your package couldn't be delivered.", "label": "social_engineering", "category": "impersonation", "confidence": 0.87},
    {"text": "Hello, this is your pharmacy. Your prescription is ready.", "label": "social_engineering", "category": "impersonation", "confidence": 0.84},
    {"text": "This is the fraud department at your bank. Please verify recent transactions.", "label": "social_engineering", "category": "impersonation", "confidence": 0.92},
    {"text": "Hi, WhatsApp here. Your account verification is needed.", "label": "social_engineering", "category": "impersonation", "confidence": 0.89},
    {"text": "This is your mobile carrier. Your bill is overdue.", "label": "social_engineering", "category": "impersonation", "confidence": 0.86},
    {"text": "Dear member, this is your gym. Your membership needs renewal.", "label": "social_engineering", "category": "impersonation", "confidence": 0.83},
    {"text": "This is the police department. You have an outstanding warrant.", "label": "social_engineering", "category": "impersonation", "confidence": 0.94},
    {"text": "Hi, this is John from IT. We need your login credentials for maintenance.", "label": "social_engineering", "category": "impersonation", "confidence": 0.91},
    {"text": "This is Facebook Support. Your account has been flagged.", "label": "social_engineering", "category": "impersonation", "confidence": 0.90},
    {"text": "Dear customer, DHL here. Customs fees are required for your package.", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "This is your boss. I need you to purchase gift cards urgently.", "label": "social_engineering", "category": "impersonation", "confidence": 0.93},
    {"text": "Hi, I'm calling from the hospital about your test results.", "label": "social_engineering", "category": "impersonation", "confidence": 0.87},
    {"text": "This is Spotify. Your premium subscription has issues.", "label": "social_engineering", "category": "impersonation", "confidence": 0.85},
    {"text": "Dear user, Instagram Security here. Verify your identity.", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "This is the lottery commission. You've won a prize.", "label": "social_engineering", "category": "impersonation", "confidence": 0.91},
    {"text": "Hi, this is your child's school. There's an emergency.", "label": "social_engineering", "category": "impersonation", "confidence": 0.89},
    {"text": "This is UPS. Confirm delivery address for your shipment.", "label": "social_engineering", "category": "impersonation", "confidence": 0.86},
    {"text": "Dear customer, this is Uber. Your account needs verification.", "label": "social_engineering", "category": "impersonation", "confidence": 0.87},
    {"text": "This is LinkedIn. Someone viewed your profile from a suspicious location.", "label": "social_engineering", "category": "impersonation", "confidence": 0.86},
    {"text": "Hi, I'm the new contractor. The CFO asked me to reach out.", "label": "social_engineering", "category": "impersonation", "confidence": 0.88},
    {"text": "This is Venmo Support. A large transfer was initiated.", "label": "social_engineering", "category": "impersonation", "confidence": 0.89},
    {"text": "Dear member, your insurance company here. Policy update required.", "label": "social_engineering", "category": "impersonation", "confidence": 0.85},

    # ==============================================================
    #  AUTHORITY (expanded)
    # ==============================================================
    {"text": "This is the IT Department. All employees must reset passwords today.", "label": "social_engineering", "category": "authority", "confidence": 0.91},
    {"text": "As your manager, I'm directing you to process this payment.", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "Legal notice: You are required to appear in court.", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "Government mandate: Update your tax information immediately.", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "HR requires all staff to complete this form by end of day.", "label": "social_engineering", "category": "authority", "confidence": 0.88},
    {"text": "Executive order: Confidential wire transfer needed.", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "Compliance department: Your certification expires soon.", "label": "social_engineering", "category": "authority", "confidence": 0.86},
    {"text": "This directive comes from senior leadership. Handle immediately.", "label": "social_engineering", "category": "authority", "confidence": 0.91},
    {"text": "Board resolution: All shareholders must verify holdings.", "label": "social_engineering", "category": "authority", "confidence": 0.89},
    {"text": "Finance department requires updated banking details.", "label": "social_engineering", "category": "authority", "confidence": 0.87},
    {"text": "CEO instruction: Purchase these gift cards for client appreciation.", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "Audit team: Submit your expense reports today.", "label": "social_engineering", "category": "authority", "confidence": 0.85},
    {"text": "Security policy mandate: Install this software update.", "label": "social_engineering", "category": "authority", "confidence": 0.88},
    {"text": "Tax authority requires immediate documentation.", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "Management decision: Project deadline moved to today.", "label": "social_engineering", "category": "authority", "confidence": 0.84},
    {"text": "Immigration services: Your visa application requires action.", "label": "social_engineering", "category": "authority", "confidence": 0.90},
    {"text": "Official notice: Jury duty summons enclosed.", "label": "social_engineering", "category": "authority", "confidence": 0.89},
    {"text": "IT Security mandate: Provide credentials for system upgrade.", "label": "social_engineering", "category": "authority", "confidence": 0.91},
    {"text": "Director's orders: Expedite this vendor payment.", "label": "social_engineering", "category": "authority", "confidence": 0.90},
    {"text": "Health department order: Submit vaccination records.", "label": "social_engineering", "category": "authority", "confidence": 0.87},
    {"text": "Regulatory compliance: Complete training by Friday.", "label": "social_engineering", "category": "authority", "confidence": 0.84},
    {"text": "VP instruction: Handle this personally and discreetly.", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "Corporate policy: All passwords must be changed now.", "label": "social_engineering", "category": "authority", "confidence": 0.88},
    {"text": "Legal department: Sign this NDA immediately.", "label": "social_engineering", "category": "authority", "confidence": 0.87},
    {"text": "Supervisory directive: Override normal approval process.", "label": "social_engineering", "category": "authority", "confidence": 0.91},
    {"text": "Official summons: Appear at this address for questioning.", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "IT administrator: Your account will be disabled for maintenance.", "label": "social_engineering", "category": "authority", "confidence": 0.86},
    {"text": "Executive request: Transfer funds to this new account.", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "Procurement order: Bypass vendor verification this time.", "label": "social_engineering", "category": "authority", "confidence": 0.89},
    {"text": "Department head decision: Work remotely and use this VPN.", "label": "social_engineering", "category": "authority", "confidence": 0.85},

    # ==============================================================
    #  SAFE / LEGITIMATE (benign messages)
    # ==============================================================
    {"text": "Your order has shipped. Track your package with this link.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Payment received. Thank you for your purchase.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your appointment is confirmed for Tuesday at 3 PM.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Here are the meeting notes from today's standup.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your subscription will renew in 7 days.", "label": "legitimate", "category": "safe", "confidence": 0.95},
    {"text": "Thank you for contacting support. We'll respond within 24 hours.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Your password was successfully changed.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Monthly statement attached for your review.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Your flight itinerary is attached. Have a safe trip!", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Reminder: Your dentist appointment is tomorrow at 10 AM.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your return has been processed. Refund will appear in 3-5 days.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Thanks for your feedback. We appreciate your input.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your account settings have been updated successfully.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Weekly digest: Here's what you missed this week.", "label": "legitimate", "category": "safe", "confidence": 0.95},
    {"text": "Your package was delivered to your front door.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Invoice #12345 attached. Payment due in 30 days.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Your reservation at the restaurant is confirmed.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Attached is the report you requested last week.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your direct deposit has been processed.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "The team lunch is scheduled for Friday at noon.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your car service appointment is set for Monday.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Thank you for your order. Estimated delivery: March 15.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Your prescription is ready for pickup.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Meeting rescheduled to Wednesday at 2 PM.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your library books are due next Tuesday.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Quarterly earnings report attached for review.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Your gym membership has been renewed.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Shipping update: Your package is out for delivery.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your hotel reservation has been confirmed.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Thank you for attending our webinar.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Your insurance policy documents are attached.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Team meeting moved to conference room B.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your product review has been published.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Agenda for tomorrow's meeting attached.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your account balance is $1,234.56.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Project update: Phase 2 completed successfully.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your vaccination records have been updated.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Reminder: Staff meeting at 9 AM tomorrow.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your online order is being prepared.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Receipt for your recent purchase attached.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your credit card statement is now available.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Office closed Monday for holiday.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your annual review has been scheduled.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "The document has been signed by all parties.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your phone plan has been updated.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Class schedule for next semester attached.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your pet's vaccination is due next month.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Minutes from yesterday's meeting attached.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your electricity bill is available online.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "The conference call dial-in info is below.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your parking permit has been renewed.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Budget report for Q3 is attached.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Your software license has been activated.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Happy birthday from all of us at the office!", "label": "legitimate", "category": "safe", "confidence": 0.99},
    {"text": "The shared drive has been updated with new files.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your timesheet has been approved.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Newsletter: Company updates for March.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Your test results are available in the patient portal.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Carpool schedule for next week attached.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your event registration was successful.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "PTO request approved. Enjoy your time off.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your lease renewal documents are ready.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Team happy hour at 5 PM today.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Contract signed and filed successfully.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your benefits enrollment has been confirmed.", "label": "legitimate", "category": "safe", "confidence": 0.97},


    # ==============================================================
    #  QR CODE PHISHING (Source: FBI IC3 2023, FTC Scam Alerts 2024)
    # ==============================================================
    # QR codes used in parking meters, payment scams, crypto fraud
    {"text": "Scan this QR code to verify your identity and secure your account", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.94},
    {"text": "Use the QR code below to update your payment information", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.93},
    {"text": "Scan QR to claim your reward before it expires", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.92},
    {"text": "QR code attached for immediate account verification", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.91},
    {"text": "Pay parking fee by scanning this QR code", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.88},
    {"text": "Scan to receive your crypto airdrop - limited time only", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.95},
    {"text": "Your package requires QR code verification for delivery", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.90},
    {"text": "Scan this code to unlock exclusive member benefits", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.89},
    {"text": "QR payment required to process your refund", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.92},
    {"text": "Scan the barcode to confirm your bank transfer", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.91},
    {"text": "Use this QR to reset your password securely", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.90},
    {"text": "Restaurant menu - scan QR code to view and pay", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.75},
    {"text": "Scan QR code on your invoice to complete payment", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.87},
    {"text": "Authenticate your session by scanning this QR code", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.92},
    {"text": "QR code verification needed for your tax refund", "label": "social_engineering", "category": "qr_phishing", "confidence": 0.94},

    # ==============================================================
    #  BUSINESS EMAIL COMPROMISE (Source: FBI IC3 2023)
    # ==============================================================
    {"text": "I need you to wire $50,000 to this account immediately. Don't tell anyone - this is confidential.", "label": "social_engineering", "category": "bec", "confidence": 0.96},
    {"text": "Change the payment account for invoice #4521 to this new bank. Process urgently.", "label": "social_engineering", "category": "bec", "confidence": 0.94},
    {"text": "This is the CEO. I need gift cards for a client. Buy $2000 in Apple cards and send codes.", "label": "social_engineering", "category": "bec", "confidence": 0.97},
    {"text": "We're changing vendors. Wire the payment to this updated account before Friday.", "label": "social_engineering", "category": "bec", "confidence": 0.93},
    {"text": "Invoice attached. Please update our banking details in your system and pay to new account.", "label": "social_engineering", "category": "bec", "confidence": 0.92},
    {"text": "I'm in a meeting. Purchase 5 Amazon gift cards ($500 each) and email me the codes ASAP.", "label": "social_engineering", "category": "bec", "confidence": 0.96},
    {"text": "Payroll update: Direct deposit for employees should go to this new routing number.", "label": "social_engineering", "category": "bec", "confidence": 0.95},
    {"text": "This is HR. Update your direct deposit to this account for your bonus payment.", "label": "social_engineering", "category": "bec", "confidence": 0.93},
    {"text": "Vendor payment urgent. Accountant is out. Wire $85,000 to attached details. Keep confidential.", "label": "social_engineering", "category": "bec", "confidence": 0.95},
    {"text": "Real estate closing today. Wire earnest money to escrow at this account number.", "label": "social_engineering", "category": "bec", "confidence": 0.91},

    # ==============================================================
    #  CRYPTOCURRENCY SCAMS (Source: FTC 2024, APWG Q4 2023)
    # ==============================================================
    {"text": "Connect your wallet to claim free ETH airdrop. Limited to first 1000 users.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.95},
    {"text": "Your wallet has been compromised. Enter seed phrase to secure funds.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.98},
    {"text": "Validate your MetaMask wallet to continue using DeFi services.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.94},
    {"text": "Bitcoin giveaway! Send 0.1 BTC and receive 1 BTC back immediately.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.97},
    {"text": "Your NFT mint is ready. Connect wallet and approve transaction.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.89},
    {"text": "Crypto exchange security alert. Verify wallet to prevent freeze.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.93},
    {"text": "Investment opportunity: 50% guaranteed returns on crypto in 30 days.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.96},
    {"text": "Enter your private key to migrate tokens to new blockchain.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.98},
    {"text": "Romance partner needs help converting cryptocurrency. Send to this wallet.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.94},
    {"text": "Pig butchering investment: Join our exclusive crypto trading group for guaranteed profits.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.95},

    # ==============================================================
    #  GOVERNMENT IMPERSONATION (Source: IRS, SSA, FBI IC3 2023)
    # ==============================================================
    {"text": "IRS Notice: You owe back taxes. Pay immediately via gift card to avoid arrest.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.97},
    {"text": "Social Security Administration: Your SSN has been suspended. Call immediately.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.96},
    {"text": "Medicare: Update your card information to continue receiving benefits.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.93},
    {"text": "DMV: Your license will be suspended. Pay fine via this link.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.92},
    {"text": "FBI Warning: Your identity has been used in crimes. Cooperate or face charges.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.95},
    {"text": "Customs: Package held. Pay customs duty via wire transfer to release.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.91},
    {"text": "Student loan forgiveness: Apply now by providing SSN and bank details.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.94},
    {"text": "Court summons: Appear or pay fine immediately. Warrant issued.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.93},
    {"text": "Immigration: Your visa status requires immediate verification.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.92},
    {"text": "EPA grant: You qualify for $10,000 environmental grant. Apply with bank info.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.90},

    # ==============================================================
    #  DELIVERY/SHIPPING SCAMS (Source: USPS, FTC 2024)
    # ==============================================================
    {"text": "USPS: Package delivery failed. Update address and pay $1.99 redelivery fee.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.94},
    {"text": "FedEx: Customs charges due. Pay to release your international package.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.93},
    {"text": "Your Amazon package cannot be delivered. Verify address and payment method.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.91},
    {"text": "DHL: Shipment on hold. Schedule delivery by clicking this link.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.90},
    {"text": "UPS: Package requires signature. Reschedule at this link with card on file.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.89},
    {"text": "Royal Mail: You have an undelivered parcel. Pay fee to receive.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.92},
    {"text": "Missed delivery. Track your package: [suspicious link]", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.88},
    {"text": "Your order is held at customs. Pay import duty to release.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.91},

    # ==============================================================
    #  TECH SUPPORT SCAMS (Source: Microsoft, FTC 2024)
    # ==============================================================
    {"text": "Microsoft detected virus on your computer. Call this number immediately.", "label": "social_engineering", "category": "tech_support", "confidence": 0.95},
    {"text": "Your computer has been blocked. Call support to remove malware.", "label": "social_engineering", "category": "tech_support", "confidence": 0.94},
    {"text": "Apple: Your iCloud has been breached. Call Apple Support now.", "label": "social_engineering", "category": "tech_support", "confidence": 0.93},
    {"text": "Security warning: Browser infected. Download this tool to fix.", "label": "social_engineering", "category": "tech_support", "confidence": 0.92},
    {"text": "Windows Defender alert: Trojan detected. Contact Microsoft certified partner.", "label": "social_engineering", "category": "tech_support", "confidence": 0.94},
    {"text": "Your antivirus subscription expired. Renew now or risk infection.", "label": "social_engineering", "category": "tech_support", "confidence": 0.88},
    {"text": "Pop-up: Your PC is at risk. Call toll-free support for immediate help.", "label": "social_engineering", "category": "tech_support", "confidence": 0.95},
    {"text": "Router compromised. Download this security patch immediately.", "label": "social_engineering", "category": "tech_support", "confidence": 0.91},

    # ==============================================================
    #  SMISHING / SMS SPECIFIC (Source: FBI IC3 2023, FTC)
    # ==============================================================
    {"text": "Your bank account is locked. Reply YES to verify or call 1-800-XXX.", "label": "social_engineering", "category": "smishing", "confidence": 0.93},
    {"text": "Free msg: You've won $1000 Walmart gift card. Claim: bit.ly/xxx", "label": "social_engineering", "category": "smishing", "confidence": 0.95},
    {"text": "Netflix: Payment failed. Update billing at netflix-secure.com", "label": "social_engineering", "category": "smishing", "confidence": 0.94},
    {"text": "Apple ID locked. Verify at apple-id-support.com to restore access.", "label": "social_engineering", "category": "smishing", "confidence": 0.95},
    {"text": "Venmo: Suspicious login. Tap to secure: venmo-verify.com", "label": "social_engineering", "category": "smishing", "confidence": 0.94},
    {"text": "Your Chase card ending 1234 was charged $499. Reply STOP if not you.", "label": "social_engineering", "category": "smishing", "confidence": 0.91},
    {"text": "PayPal: Unusual activity detected. Confirm identity at paypa1-secure.com", "label": "social_engineering", "category": "smishing", "confidence": 0.96},
    {"text": "USPS: Your package has a $3.99 shipping fee. Pay here to deliver.", "label": "social_engineering", "category": "smishing", "confidence": 0.93},

    # ==============================================================
    #  ROMANCE/PIG BUTCHERING SCAMS (Source: FBI IC3 2023, FTC 2024)
    # ==============================================================
    {"text": "I know we just met online but I feel a deep connection. Can you help with my medical bills?", "label": "social_engineering", "category": "romance_scam", "confidence": 0.94},
    {"text": "My daughter is sick and I'm stuck overseas. Can you wire money for her treatment?", "label": "social_engineering", "category": "romance_scam", "confidence": 0.95},
    {"text": "I'm a US soldier deployed abroad. I need money for my flight home to meet you.", "label": "social_engineering", "category": "romance_scam", "confidence": 0.96},
    {"text": "I've been trading crypto and making huge profits. Let me show you how.", "label": "social_engineering", "category": "romance_scam", "confidence": 0.92},
    {"text": "My inheritance is stuck. I need you to pay the release fee and we'll share it.", "label": "social_engineering", "category": "romance_scam", "confidence": 0.95},
    {"text": "I want to visit you but my passport was stolen. Can you send money for a new one?", "label": "social_engineering", "category": "romance_scam", "confidence": 0.94},
    {"text": "I have a business opportunity that guarantees 300% returns. Trust me.", "label": "social_engineering", "category": "romance_scam", "confidence": 0.93},
    {"text": "Send the money via Western Union. I'll pay you back double when I arrive.", "label": "social_engineering", "category": "romance_scam", "confidence": 0.96},
    {"text": "My crypto trading platform needs an initial deposit. Join my exclusive group.", "label": "social_engineering", "category": "romance_scam", "confidence": 0.94},
    {"text": "I'm stranded at the airport with no money. Please help me, my love.", "label": "social_engineering", "category": "romance_scam", "confidence": 0.93},

    # ==============================================================
    #  JOB/EMPLOYMENT SCAMS (Source: FTC 2024, Better Business Bureau)
    # ==============================================================
    {"text": "Work from home! Earn $5000/week. No experience needed. Start today!", "label": "social_engineering", "category": "job_scam", "confidence": 0.94},
    {"text": "Congratulations! You've been selected for a mystery shopper position. Send ID to confirm.", "label": "social_engineering", "category": "job_scam", "confidence": 0.93},
    {"text": "Remote data entry job: $50/hour. Send your SSN and bank info for direct deposit setup.", "label": "social_engineering", "category": "job_scam", "confidence": 0.96},
    {"text": "You need to purchase equipment for this job. We'll reimburse you after training.", "label": "social_engineering", "category": "job_scam", "confidence": 0.95},
    {"text": "Job offer: Process payments from home. Keep 10% commission on each transaction.", "label": "social_engineering", "category": "job_scam", "confidence": 0.94},
    {"text": "LinkedIn recruiter: Exciting opportunity! Pay $200 for training materials to start.", "label": "social_engineering", "category": "job_scam", "confidence": 0.95},
    {"text": "Urgent hiring: Cash check and wire portion to supplier. Easy money!", "label": "social_engineering", "category": "job_scam", "confidence": 0.97},
    {"text": "Google is hiring remote workers. Apply with personal details at google-careers-apply.com", "label": "social_engineering", "category": "job_scam", "confidence": 0.94},
    {"text": "Your resume matched our job. Interview via Telegram. Send ID for background check.", "label": "social_engineering", "category": "job_scam", "confidence": 0.93},
    {"text": "Start earning today as an app tester. Buy gift cards, send codes, get reimbursed.", "label": "social_engineering", "category": "job_scam", "confidence": 0.96},

    # ==============================================================
    #  INVOICE/PAYMENT FRAUD (Source: FBI IC3 2023)
    # ==============================================================
    {"text": "Invoice attached. Please note our bank details have changed. Pay to new account.", "label": "social_engineering", "category": "invoice_fraud", "confidence": 0.95},
    {"text": "This is your supplier. We've changed banks. Update payment info immediately.", "label": "social_engineering", "category": "invoice_fraud", "confidence": 0.94},
    {"text": "Urgent: Wire payment to updated account before contract deadline.", "label": "social_engineering", "category": "invoice_fraud", "confidence": 0.93},
    {"text": "Our accounting department requires payment to this new routing number.", "label": "social_engineering", "category": "invoice_fraud", "confidence": 0.92},
    {"text": "Please disregard previous invoice. Updated invoice with correct bank attached.", "label": "social_engineering", "category": "invoice_fraud", "confidence": 0.94},
    {"text": "Final reminder: Outstanding invoice must be paid to avoid service termination.", "label": "social_engineering", "category": "invoice_fraud", "confidence": 0.88},
    {"text": "Legal notice: Pay this invoice within 24 hours or face collection action.", "label": "social_engineering", "category": "invoice_fraud", "confidence": 0.91},
    {"text": "Subscription renewal invoice. Auto-charge failed. Manual payment required.", "label": "social_engineering", "category": "invoice_fraud", "confidence": 0.87},

    # ==============================================================
    #  UTILITY/SERVICE SCAMS (Source: FTC 2024)
    # ==============================================================
    {"text": "Electric company: Your power will be shut off in 30 minutes. Pay now to avoid.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.94},
    {"text": "Water service disconnection notice. Immediate payment required via gift card.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.95},
    {"text": "Gas company: Suspected leak at your address. Pay inspection fee or service terminated.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.93},
    {"text": "Internet provider: Your service will be suspended. Pay overdue balance now.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.89},
    {"text": "This is your phone carrier. Pay now to avoid number deactivation.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.90},

    # ==============================================================
    #  ADVANCE FEE / INHERITANCE SCAMS (Source: FBI IC3, FTC)
    # ==============================================================
    {"text": "You're entitled to inheritance from deceased relative. Pay legal fees to claim.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.96},
    {"text": "Nigerian prince needs help transferring $15 million. You'll receive 30%.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.98},
    {"text": "Lottery official: You won $2.5 million. Pay taxes upfront to receive winnings.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.97},
    {"text": "Unclaimed funds in your name. Pay processing fee to release $500,000.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.95},
    {"text": "Bank of England: Dormant account with your name. Send ID and fee to claim.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.96},
    {"text": "UN compensation fund: You qualify for $950,000. Pay $500 courier fee.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.97},
    {"text": "Grant approved! Pay $250 administrative fee to receive $10,000 government grant.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.94},

    # ==============================================================
    #  CHARITY/DISASTER SCAMS (Source: FTC, FEMA)
    # ==============================================================
    {"text": "Donate now to help earthquake victims. Send via wire transfer for immediate relief.", "label": "social_engineering", "category": "charity_scam", "confidence": 0.88},
    {"text": "Hurricane relief fund: Your donation is tax deductible. Pay via gift card.", "label": "social_engineering", "category": "charity_scam", "confidence": 0.92},
    {"text": "Children's cancer foundation: Donate today and save a life. Cash only.", "label": "social_engineering", "category": "charity_scam", "confidence": 0.85},
    {"text": "Veterans charity: Support our troops. Wire donation to this account.", "label": "social_engineering", "category": "charity_scam", "confidence": 0.87},
    {"text": "COVID relief fund: Send Bitcoin donation to help frontline workers.", "label": "social_engineering", "category": "charity_scam", "confidence": 0.91},

    # ==============================================================
    #  HEALTH/MEDICARE SCAMS (Source: OIG, FTC 2024)
    # ==============================================================
    {"text": "Medicare: Free genetic testing kit available. Provide Medicare number to receive.", "label": "social_engineering", "category": "health_scam", "confidence": 0.93},
    {"text": "Your new Medicare card is ready. Verify identity with SSN and DOB.", "label": "social_engineering", "category": "health_scam", "confidence": 0.94},
    {"text": "Pharmacy: Your prescription is ready. Update insurance with card number.", "label": "social_engineering", "category": "health_scam", "confidence": 0.86},
    {"text": "COVID vaccine registration: Enter personal details to schedule appointment.", "label": "social_engineering", "category": "health_scam", "confidence": 0.84},
    {"text": "Health insurance: Your policy needs immediate update. Call or face coverage loss.", "label": "social_engineering", "category": "health_scam", "confidence": 0.89},

    # ==============================================================
    #  EXTENDED BENIGN / LEGITIMATE (balance dataset)
    # ==============================================================
    {"text": "Your Uber ride receipt from yesterday is attached.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Sprint planning meeting moved to 2 PM. Please update your calendar.", "label": "legitimate", "category": "safe", "confidence": 0.99},
    {"text": "Your code review for PR #1234 has been approved.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Slack workspace invite: Join the engineering team channel.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "GitHub: You were mentioned in issue #567.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Conference registration confirmed. Badge pickup at registration desk.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Office closed for holiday. Normal hours resume Tuesday.", "label": "legitimate", "category": "safe", "confidence": 0.99},
    {"text": "Your expense report for Q3 has been processed.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Team building event: Bowling next Friday at 5 PM. RSVP requested.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your AWS bill for October is available in the billing console.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Reminder: Submit timesheets by end of day Friday.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your library books are due in 3 days. Return or renew online.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Gym membership renewal: Your annual membership renews next month.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Weather alert: Heavy rain expected tomorrow. Drive safely.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your Spotify Wrapped is ready! See your top songs of the year.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "New episode available: Your favorite podcast released a new episode.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Movie tickets confirmed: 2 tickets for Saturday 7 PM showing.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Thank you for your purchase at Target. Receipt attached.", "label": "legitimate", "category": "safe", "confidence": 0.98},

    # ==============================================================
    #  INDIA CONTEXTUAL SCAMS (RTO/eChallan, UPI, KYC, FASTag)
    # ============================================================== 
    {"text": "RTO notice: Your eChallan is pending. Pay immediately to avoid license suspension.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.95},
    {"text": "Traffic police alert: Unpaid challan detected. Download receipt at the link below now.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.93},
    {"text": "Parivahan update required. Install RTO Challan APK to verify your vehicle details.", "label": "social_engineering", "category": "impersonation", "confidence": 0.97},
    {"text": "Final warning from transport office: Penalty doubles after midnight. Clear challan now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.94},
    {"text": "MParivahan team: Your vehicle is blacklisted due to challan non-payment. Verify now.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "Court action will start for unpaid traffic challan. Click to settle before hearing date.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.96},
    {"text": "Road safety authority: Pay eChallan via this private QR code to avoid legal notice.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.94},
    {"text": "State transport portal verification failed. Re-enter RC, DL and OTP in this form.", "label": "social_engineering", "category": "impersonation", "confidence": 0.92},
    {"text": "Your driving license renewal is blocked due to pending challan. Update payment details now.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.91},
    {"text": "Highway police message: Vehicle seizure scheduled in 24 hours unless challan is paid.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.95},
    {"text": "Transport compliance desk: Confirm identity and pay challan with card to prevent FIR filing.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.95},
    {"text": "RTO helpdesk: Install update package to auto-clear your eChallan penalties.", "label": "social_engineering", "category": "impersonation", "confidence": 0.96},

    {"text": "NPCI alert: Your UPI ID will be blocked in 30 minutes. Verify UPI PIN to continue.", "label": "social_engineering", "category": "smishing", "confidence": 0.97},
    {"text": "Bank KYC expired. Update PAN, Aadhaar and account number now to avoid account freeze.", "label": "social_engineering", "category": "authority", "confidence": 0.94},
    {"text": "Your UPI transaction failed due to KYC suspension. Click link and confirm MPIN immediately.", "label": "social_engineering", "category": "smishing", "confidence": 0.96},
    {"text": "SBI security team: Share OTP to reverse unauthorized UPI debit.", "label": "social_engineering", "category": "impersonation", "confidence": 0.96},
    {"text": "Aadhaar and PAN mismatch detected. Your netbanking access will be disabled tonight.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.93},
    {"text": "UPI support desk: Enter debit card details to reactivate your daily transfer limit.", "label": "social_engineering", "category": "impersonation", "confidence": 0.94},
    {"text": "Immediate KYC action required. Submit selfie and OTP from this secure form.", "label": "social_engineering", "category": "urgency", "confidence": 0.90},
    {"text": "Your mobile SIM eKYC is invalid. Bank services will stop in 2 hours unless verified.", "label": "social_engineering", "category": "fear_threat", "confidence": 0.92},
    {"text": "UPI fraud monitor: Device change detected. Confirm your UPI PIN to secure your wallet.", "label": "social_engineering", "category": "impersonation", "confidence": 0.95},
    {"text": "RBI compliance message: Your account is flagged for suspicious transfers. Verify now.", "label": "social_engineering", "category": "authority", "confidence": 0.93},
    {"text": "Netbanking lock alert: Share one-time code with support to unlock payments.", "label": "social_engineering", "category": "impersonation", "confidence": 0.95},
    {"text": "Aadhaar update pending. Pension and subsidy credits may stop unless details are confirmed.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.91},
    {"text": "UPI chargeback approved. Pay Rs 10 verification fee to receive refund instantly.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.90},
    {"text": "PhonePe support: Your account audit is incomplete. Enter CVV and OTP to retain access.", "label": "social_engineering", "category": "impersonation", "confidence": 0.96},
    {"text": "Paytm security: Merchant verification failed. Confirm bank credentials to avoid suspension.", "label": "social_engineering", "category": "impersonation", "confidence": 0.94},

    {"text": "FASTag blacklisted due to insufficient balance. Recharge from this link now.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.93},
    {"text": "NHAI notice: FASTag will be permanently blocked unless KYC is revalidated today.", "label": "social_engineering", "category": "authority", "confidence": 0.92},
    {"text": "India Post: Parcel held at sorting center. Pay customs fee through this short URL.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.95},
    {"text": "Courier update: Package cannot be delivered until address is verified with OTP.", "label": "social_engineering", "category": "delivery_scam", "confidence": 0.90},
    {"text": "Electricity board warning: Connection disconnection scheduled today. Pay pending bill now.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.94},
    {"text": "Water utility alert: Bill overdue by 3 days. Immediate payment required to avoid cut-off.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.91},
    {"text": "Gas agency notice: Subsidy stopped due to KYC failure. Update bank details using this form.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.92},
    {"text": "FASTag penalty notice: Toll violations found. Pay now using this private payment gateway.", "label": "social_engineering", "category": "utility_scam", "confidence": 0.93},

    {"text": "PM subsidy disbursement approved. Verify bank account to receive Rs 12,500 today.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.90},
    {"text": "Government relief grant: You are shortlisted. Pay processing fee to release payment.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.94},
    {"text": "Ayushman card update: Confirm details and OTP to unlock free health benefits.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.91},
    {"text": "PM Kisan installment pending. Verify Aadhaar and account PIN from this portal.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.92},
    {"text": "Income tax refund ready: Submit card details for instant credit of Rs 8,400.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.93},
    {"text": "State scholarship office: Confirm student KYC and transfer fee to release scholarship.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.90},
    {"text": "Public distribution scheme update: Your ration benefits are paused until re-verification.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.89},
    {"text": "Election commission notice: Voter card suspended due to profile mismatch. Verify now.", "label": "social_engineering", "category": "gov_impersonation", "confidence": 0.88},
    {"text": "District office support: Welfare payout is ready. Share OTP to complete beneficiary check.", "label": "social_engineering", "category": "authority", "confidence": 0.90},
    {"text": "Municipal tax waiver approved for your property. Pay a small activation fee to claim.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.91},

    {"text": "Part-time online task: Rate hotels and earn Rs 3,000 per day. No experience required.", "label": "social_engineering", "category": "job_scam", "confidence": 0.95},
    {"text": "Work from home data entry role. Security deposit required before onboarding.", "label": "social_engineering", "category": "job_scam", "confidence": 0.94},
    {"text": "Crypto mentor group: Guaranteed 5x returns in one week. Join premium channel now.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.95},
    {"text": "Telegram investment desk: Daily profit assured if you transfer funds immediately.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.93},
    {"text": "Freelance project approved. Pay registration fee and submit ID to start today.", "label": "social_engineering", "category": "job_scam", "confidence": 0.91},
    {"text": "Instant loan approval with no documents. Pay insurance premium first to disburse amount.", "label": "social_engineering", "category": "advance_fee", "confidence": 0.92},
    {"text": "Trading bot access for selected members only. Guaranteed monthly income if you invest now.", "label": "social_engineering", "category": "crypto_scam", "confidence": 0.94},
    {"text": "You are shortlisted for airport ground staff role. Submit training fee in 2 hours.", "label": "social_engineering", "category": "job_scam", "confidence": 0.92},
    {"text": "Remote support executive hiring. Share Aadhaar, PAN and bank details to confirm offer.", "label": "social_engineering", "category": "job_scam", "confidence": 0.90},
    {"text": "Special IPO allocation available. Transfer booking amount immediately for guaranteed listing gains.", "label": "social_engineering", "category": "reward_lure", "confidence": 0.91},

    # ============================================================== 
    #  INDIA CONTEXTUAL BENIGN / SAFE
    # ============================================================== 
    {"text": "UPI payment of Rs 450 successful to merchant. UTR ending 1294.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your IRCTC ticket booking is confirmed for train 12627. Chart will be prepared later.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "FASTag recharge of Rs 500 completed successfully through the official app.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Electricity bill payment received. Next due date is 15th of next month.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Your gas cylinder booking has been confirmed. Delivery expected in 2 days.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "State transport portal confirms challan payment. Download receipt from official dashboard.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Aadhaar authentication completed successfully for your bank branch eKYC request.", "label": "legitimate", "category": "safe", "confidence": 0.96},
    {"text": "Income tax portal message: Your ITR has been successfully e-verified.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your passport appointment is scheduled for 11:30 AM on Tuesday at PSK center.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Municipal office notification: Property tax receipt is available in your online account.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Your bank confirms fixed deposit renewal as requested at branch.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Courier update: Shipment reached local hub and is out for delivery.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "University admissions office: Document verification slot confirmed for Monday.", "label": "legitimate", "category": "safe", "confidence": 0.97},
    {"text": "Hospital appointment reminder: OPD consultation is confirmed for 4 PM tomorrow.", "label": "legitimate", "category": "safe", "confidence": 0.98},
    {"text": "Metro card recharge successful. Available balance updated in app.", "label": "legitimate", "category": "safe", "confidence": 0.98},

]


INDIA_KB_SOURCES = [
  {
    "title": "CERT-In advisories on phishing, smishing, and malicious mobile campaigns",
    "url": "https://www.cert-in.org.in/",
  },
  {
    "title": "RBI consumer guidance on KYC/UPI and banking fraud prevention",
    "url": "https://www.rbi.org.in/",
  },
  {
    "title": "NPCI awareness guidance for UPI fraud and safe transaction behavior",
    "url": "https://www.npci.org.in/",
  },
  {
    "title": "National Cyber Crime Reporting Portal (I4C/MHA) fraud trend alerts",
    "url": "https://www.cybercrime.gov.in/",
  },
  {
    "title": "Press Information Bureau advisories on digital arrest and impersonation scams",
    "url": "https://www.pib.gov.in/",
  },
  {
    "title": "India Post cautions about fake parcel, customs, and delivery messages",
    "url": "https://www.indiapost.gov.in/",
  },
  {
    "title": "NHAI/FASTag guidance on official recharge channels and fraud avoidance",
    "url": "https://www.nhai.gov.in/",
  },
  {
    "title": "Department of Telecommunications subscriber safety guidance",
    "url": "https://dot.gov.in/",
  },
]


INDIA_GENERATED_PATTERN_COUNT = 0


def _append_generated_india_patterns():
  """Expand India-context patterns using deterministic template combinations."""
  global INDIA_GENERATED_PATTERN_COUNT

  existing = {
    str(item.get("text", "")).strip().lower()
    for item in SOCIAL_ENGINEERING_DATASET
    if item.get("text")
  }
  generated = []

  def add_pattern(text, label, category, confidence):
    normalized = " ".join(str(text).split()).strip()
    if not normalized:
      return
    key = normalized.lower()
    if key in existing:
      return
    existing.add(key)
    generated.append(
      {
        "text": normalized,
        "label": label,
        "category": category,
        "confidence": confidence,
      }
    )

  # Government and digital-arrest impersonation themes (CERT-In, PIB, I4C).
  gov_senders = [
    "Cyber Crime Cell notice",
    "State police cyber desk",
    "Income Tax compliance office",
    "Telecom compliance authority",
    "e-Governance verification center",
    "District legal enforcement unit",
  ]
  gov_pretexts = [
    "Your Aadhaar-linked SIM is under investigation",
    "A complaint was registered for suspicious digital transactions",
    "Your KYC profile is marked non-compliant",
    "A cyber fraud FIR is being prepared against this mobile number",
  ]
  gov_actions = [
    "Verify identity by sharing OTP and Aadhaar details now",
    "Complete verification form with PAN, bank account and UPI PIN",
    "Call the officer number in this message and confirm account credentials",
  ]
  gov_consequences = [
    "or legal proceedings will begin today",
    "to avoid account freezing and legal action",
  ]

  for sender, pretext, action, consequence in product(
    gov_senders, gov_pretexts, gov_actions, gov_consequences
  ):
    add_pattern(
      f"{sender}: {pretext}. {action} {consequence}.",
      "social_engineering",
      "gov_impersonation",
      0.95,
    )

  # UPI/KYC and wallet impersonation themes (RBI, NPCI, CERT-In).
  upi_brands = [
    "NPCI UPI monitoring",
    "SBI security desk",
    "PhonePe compliance team",
    "Paytm risk control",
    "Netbanking fraud support",
    "Bank KYC verification center",
  ]
  upi_events = [
    "unusual UPI device login detected",
    "KYC revalidation pending for your profile",
    "wallet audit shows suspicious transfers",
    "UPI handle flagged for temporary suspension",
  ]
  upi_requests = [
    "share OTP to secure the account",
    "confirm UPI PIN and card details for reactivation",
    "verify identity on this link with Aadhaar and PAN",
  ]
  upi_deadlines = [
    "within 10 minutes",
    "before midnight today",
  ]

  for brand, event, request, deadline in product(
    upi_brands, upi_events, upi_requests, upi_deadlines
  ):
    add_pattern(
      f"{brand}: {event}; {request} {deadline} to prevent permanent block.",
      "social_engineering",
      "smishing",
      0.95,
    )

  # Delivery and customs scam themes (India Post and courier alerts).
  delivery_senders = [
    "India Post dispatch",
    "Courier customs desk",
    "Parcel routing center",
    "Express delivery support",
  ]
  delivery_issues = [
    "parcel held due to address mismatch",
    "shipment paused for customs verification",
    "delivery stopped for incomplete KYC",
  ]
  delivery_actions = [
    "pay release fee via this payment link",
    "submit card details and OTP for redelivery",
    "scan QR and complete address verification now",
  ]
  delivery_threats = [
    "or package will be returned",
    "to avoid legal disposal of shipment",
  ]

  for sender, issue, action, threat in product(
    delivery_senders, delivery_issues, delivery_actions, delivery_threats
  ):
    add_pattern(
      f"{sender}: {issue}; {action} {threat}.",
      "social_engineering",
      "delivery_scam",
      0.93,
    )

  # FASTag and utility billing extortion themes (NHAI and utility advisories).
  utility_senders = [
    "FASTag support",
    "State electricity board",
    "Water utility operations",
    "Gas service compliance",
  ]
  utility_issues = [
    "service profile marked inactive",
    "billing KYC verification failed",
    "account flagged for immediate disconnection",
  ]
  utility_actions = [
    "pay pending amount through this private link",
    "verify card credentials and OTP in the attached form",
    "complete recharge using this QR code now",
  ]
  utility_deadlines = [
    "within 30 minutes",
    "before service is permanently disconnected",
  ]

  for sender, issue, action, deadline in product(
    utility_senders, utility_issues, utility_actions, utility_deadlines
  ):
    add_pattern(
      f"{sender}: {issue}; {action} {deadline}.",
      "social_engineering",
      "utility_scam",
      0.92,
    )

  # Grant/refund and advance-fee hooks seen in regional fraud advisories.
  benefit_programs = [
    "PM subsidy desk",
    "tax refund processing center",
    "scholarship benefit office",
    "municipal rebate division",
  ]
  benefit_lures = [
    "benefit amount approved",
    "cash rebate ready for instant credit",
    "grant release pending final verification",
  ]
  benefit_actions = [
    "pay small activation fee",
    "share OTP and account details",
    "confirm card credentials for transfer",
  ]

  for program, lure, action in product(benefit_programs, benefit_lures, benefit_actions):
    category = "advance_fee" if "pay" in action else "reward_lure"
    add_pattern(
      f"{program}: {lure}; {action} to receive funds today.",
      "social_engineering",
      category,
      0.91,
    )

  # Job and investment trap templates (high-volume vectors in cybercrime reports).
  scam_channels = [
    "Telegram hiring group",
    "WhatsApp recruiter",
    "online trading mentor",
    "remote task coordinator",
  ]
  scam_claims = [
    "earn Rs 3000 per day from home",
    "guaranteed crypto profit every week",
    "airport and IT support jobs available immediately",
  ]
  scam_steps = [
    "pay registration fee before onboarding",
    "share Aadhaar, PAN and bank details to unlock payout",
    "transfer initial investment for guaranteed returns",
  ]

  for channel, claim, step in product(scam_channels, scam_claims, scam_steps):
    if "investment" in step:
      category = "crypto_scam"
    elif "registration fee" in step:
      category = "job_scam"
    elif "guaranteed" in claim:
      category = "crypto_scam"
    else:
      category = "job_scam"
    add_pattern(
      f"{channel}: {claim}; {step} right now to keep your slot.",
      "social_engineering",
      category,
      0.92,
    )

  # Legitimate India-context notifications to reduce over-flagging.
  safe_services = [
    "UPI app",
    "IRCTC",
    "India Post",
    "FASTag official app",
    "electricity board",
    "passport seva",
  ]
  safe_updates = [
    "transaction completed successfully",
    "appointment confirmed in the official portal",
    "receipt available in your account dashboard",
    "payment posted with no action required",
  ]
  safe_context = [
    "No OTP sharing is required",
    "Please use only official app channels",
  ]

  for service, update, context in product(safe_services, safe_updates, safe_context):
    add_pattern(
      f"{service}: {update}. {context}.",
      "legitimate",
      "safe",
      0.98,
    )

  SOCIAL_ENGINEERING_DATASET.extend(generated)
  INDIA_GENERATED_PATTERN_COUNT = len(generated)


_append_generated_india_patterns()
