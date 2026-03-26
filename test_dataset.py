"""
Labeled test dataset for social engineering detection evaluation.
~100 samples with ground truth labels.
"""

TEST_SAMPLES = [
    # =========================================================================
    # ATTACK SAMPLES (50 samples)
    # =========================================================================
    
    # Fear/Threat samples (10)
    {
        "text": "Your account has been compromised! Click here immediately to secure it or lose all your data.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "FINAL WARNING: Your bank account will be suspended in 24 hours unless you verify your credentials now.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "We detected unauthorized access to your account. Your funds are at risk. Verify immediately.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "Legal action will be taken against you if you don't respond within 48 hours. Contact us immediately.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "Your computer is infected with malware! Call this number now or your files will be deleted permanently.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "SECURITY ALERT: Someone tried to access your PayPal. Confirm your identity or account will be locked.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "Your tax return has been flagged for fraud. Failure to respond will result in arrest warrant.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "WARNING: Your social security number has been suspended due to suspicious activity. Press 1 now.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "Your account will be terminated and all data erased if you don't update your password immediately.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "URGENT: Virus detected on your device. Your banking credentials are exposed. Act now!",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    
    # Authority/Impersonation samples (10)
    {
        "text": "This is Microsoft Support. We've detected critical errors on your computer. Please allow remote access.",
        "labels": ["Authority", "Impersonation"],
        "attack": True
    },
    {
        "text": "Hi, this is John from IT Security. I need your password to complete the security audit.",
        "labels": ["Authority", "Impersonation"],
        "attack": True
    },
    {
        "text": "The CEO has requested you transfer $50,000 to this account immediately. This is confidential.",
        "labels": ["Authority", "Urgency"],
        "attack": True
    },
    {
        "text": "From: Apple Support - Your iCloud account requires immediate verification. Click here.",
        "labels": ["Authority", "Impersonation"],
        "attack": True
    },
    {
        "text": "This is the IRS. You owe back taxes and must pay via gift cards to avoid prosecution.",
        "labels": ["Authority", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "Amazon Security Team: Unusual activity detected. Verify your account details here.",
        "labels": ["Authority", "Impersonation"],
        "attack": True
    },
    {
        "text": "I'm the new CFO. Wire the funds to this new account. Don't tell anyone - it's confidential.",
        "labels": ["Authority", "Urgency"],
        "attack": True
    },
    {
        "text": "Google Alert: Your account was accessed from Russia. Confirm your identity immediately.",
        "labels": ["Authority", "Impersonation", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "HR Department: Your benefits will expire unless you update your SSN and bank details today.",
        "labels": ["Authority", "Urgency"],
        "attack": True
    },
    {
        "text": "This is your bank's fraud department. We need to verify your PIN to protect your account.",
        "labels": ["Authority", "Impersonation"],
        "attack": True
    },
    
    # Urgency samples (10)
    {
        "text": "ACT NOW! This offer expires in 10 minutes. Don't miss out on this exclusive deal!",
        "labels": ["Urgency", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "IMMEDIATE ACTION REQUIRED: Your subscription expires today. Update payment method now.",
        "labels": ["Urgency"],
        "attack": True
    },
    {
        "text": "You have 1 hour to claim your prize before it's awarded to someone else!",
        "labels": ["Urgency", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "LAST CHANCE: Verify your email within 30 minutes or your account will be deleted.",
        "labels": ["Urgency", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "Time-sensitive: Complete this survey in the next 5 minutes to receive your $500 gift card.",
        "labels": ["Urgency", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "RESPOND IMMEDIATELY - Your package cannot be delivered without address confirmation!",
        "labels": ["Urgency"],
        "attack": True
    },
    {
        "text": "Only 2 spots left! Register now before registration closes in 15 minutes.",
        "labels": ["Urgency", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "Your invoice is overdue. Pay within 24 hours to avoid late fees and service termination.",
        "labels": ["Urgency", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "ALERT: Password reset required within the next hour due to policy changes.",
        "labels": ["Urgency"],
        "attack": True
    },
    {
        "text": "Flash sale ends at midnight! Click now to get 90% off - limited stock available!",
        "labels": ["Urgency", "Reward/Lure"],
        "attack": True
    },
    
    # Reward/Lure samples (10)
    {
        "text": "Congratulations! You've been selected to receive a free iPhone 15. Click to claim your prize.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "You've won $1,000,000 in our lottery! Send us your bank details to receive your winnings.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "Exclusive investment opportunity: Guaranteed 500% returns in just 30 days. Limited spots!",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "Free gift card worth $500 waiting for you! Just complete this short survey to claim.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "You've been chosen for a $10,000 research grant. Provide your details to receive payment.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "WINNER NOTIFICATION: Your email was randomly selected for our $50,000 cash prize!",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "Secret Bitcoin investment strategy that made me $100,000 last month. DM for details.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "Free vacation package to Hawaii! You've been selected. Confirm your booking now.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "Earn $5000/week working from home! No experience needed. Reply for more info.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "You qualify for a government stimulus payment of $3,400. Click here to claim.",
        "labels": ["Reward/Lure", "Authority"],
        "attack": True
    },
    
    # Mixed/Complex attacks (10)
    {
        "text": "Netflix: Your payment failed. Update within 24 hours or lose access. Click here to fix.",
        "labels": ["Authority", "Urgency", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "Dear customer, unusual login from Nigeria. Secure your account now or risk identity theft.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    {
        "text": "Your cousin needs urgent help. Send $2000 via Western Union immediately. Will explain later.",
        "labels": ["Authority", "Urgency", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "Tech Support: We'll give you a $100 credit if you let us remote into your PC to fix errors.",
        "labels": ["Authority", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "IMPORTANT: Your antivirus expired. Click here for free renewal before hackers attack!",
        "labels": ["Urgency", "Fear/Threat", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "This is PayPal. Confirm your identity or your $5,000 transfer will be cancelled.",
        "labels": ["Authority", "Urgency", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "You're pre-approved for a $50,000 loan! Bad credit OK. Apply now - offer expires today!",
        "labels": ["Reward/Lure", "Urgency"],
        "attack": True
    },
    {
        "text": "FBI WARNING: Your IP was used for illegal activity. Pay fine via Bitcoin to avoid arrest.",
        "labels": ["Authority", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "Hello, I'm a prince and need your help transferring $10M. You'll receive 30% for helping.",
        "labels": ["Authority", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "Your Amazon order #12345 has a problem. Verify your credit card to avoid cancellation.",
        "labels": ["Authority", "Urgency"],
        "attack": True
    },
    
    # =========================================================================
    # BENIGN SAMPLES (50 samples)
    # =========================================================================
    
    # Normal business communication (10)
    {
        "text": "Hi team, here's the agenda for tomorrow's meeting. Please review and add any items.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Thanks for your help with the project. The client was very happy with the results.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Could you please send me the quarterly report when you have a chance? No rush.",
        "labels": [],
        "attack": False
    },
    {
        "text": "I'll be out of office next week. Please contact Sarah for any urgent matters.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Let's schedule a call to discuss the proposal. What times work for you?",
        "labels": [],
        "attack": False
    },
    {
        "text": "Just following up on our conversation from last week. Have you had a chance to review?",
        "labels": [],
        "attack": False
    },
    {
        "text": "Great work on the presentation! The team really appreciated your insights.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Please find attached the signed contract. Let me know if you need anything else.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Happy to announce we've reached our quarterly goals. Thanks everyone for your hard work!",
        "labels": [],
        "attack": False
    },
    {
        "text": "The meeting has been rescheduled to 3 PM. Same conference room as before.",
        "labels": [],
        "attack": False
    },
    
    # Personal messages (10)
    {
        "text": "Hey! How was your weekend? Let's catch up over coffee sometime.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Happy birthday! Hope you have a wonderful day filled with joy and celebration.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Thanks for dinner last night. It was great seeing you and the family again.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Just checking in to see how you're doing. It's been a while since we talked.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Congratulations on your promotion! You really deserve it after all your hard work.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Would you like to join us for the hiking trip next Saturday? Weather looks good.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Loved the photos from your vacation! Looks like you had an amazing time.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Don't forget Mom's birthday is next week. Should we plan something together?",
        "labels": [],
        "attack": False
    },
    {
        "text": "The kids had a blast at the party. Thanks for organizing everything!",
        "labels": [],
        "attack": False
    },
    {
        "text": "Looking forward to seeing you at the reunion. It's going to be fun!",
        "labels": [],
        "attack": False
    },
    
    # Legitimate service notifications (10)
    {
        "text": "Your package has been delivered and left at your front door. Thank you for shopping with us.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your monthly statement is ready to view in your online account.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Thank you for your order. Your items will ship within 2-3 business days.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your appointment is confirmed for Tuesday at 2 PM. Reply YES to confirm.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your subscription will renew next month. No action needed if you wish to continue.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Here's your receipt for your recent purchase. Keep this for your records.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your flight itinerary is attached. Check-in opens 24 hours before departure.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Password changed successfully. If you didn't make this change, contact support.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your reservation at the restaurant is confirmed for 7 PM on Friday.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Thank you for contacting support. Your ticket number is #45678. We'll respond within 24 hours.",
        "labels": [],
        "attack": False
    },
    
    # Educational/Informational (10)
    {
        "text": "Here's the study guide for next week's exam. Good luck everyone!",
        "labels": [],
        "attack": False
    },
    {
        "text": "The workshop will cover basic Python programming. No prior experience required.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Please remember to submit your assignment by Friday. Late submissions will be accepted with penalty.",
        "labels": [],
        "attack": False
    },
    {
        "text": "The library will be closed for renovations next month. Online resources remain available.",
        "labels": [],
        "attack": False
    },
    {
        "text": "New course materials have been uploaded to the learning portal.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Office hours are Tuesday and Thursday 2-4 PM. Feel free to drop by with questions.",
        "labels": [],
        "attack": False
    },
    {
        "text": "The lecture notes from today's class are now available online.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Registration for fall semester opens next Monday. Plan your schedule accordingly.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Here are some recommended readings for the research paper. Let me know if you need more.",
        "labels": [],
        "attack": False
    },
    {
        "text": "The tutoring center is available for help with math and science courses.",
        "labels": [],
        "attack": False
    },
    
    # Legitimate promotions/newsletters (10)
    {
        "text": "This week's newsletter: New features added to your favorite tools.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Our store is having a sale this weekend. Visit us for great deals on selected items.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Thank you for being a loyal customer. Here's a 10% discount code for your next purchase.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Check out our new blog post about productivity tips for remote workers.",
        "labels": [],
        "attack": False
    },
    {
        "text": "You're invited to our annual customer appreciation event next month.",
        "labels": [],
        "attack": False
    },
    {
        "text": "We've updated our privacy policy. Please review the changes at your convenience.",
        "labels": [],
        "attack": False
    },
    {
        "text": "New products just arrived! Browse our collection at our online store.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Join our webinar on digital marketing trends. Register on our website.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your feedback matters! Take our quick survey to help us improve.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Happy holidays from our team! We appreciate your support throughout the year.",
        "labels": [],
        "attack": False
    },
]


def get_attack_samples():
    """Return only attack samples."""
    return [s for s in TEST_SAMPLES if s["attack"]]


def get_benign_samples():
    """Return only benign samples."""
    return [s for s in TEST_SAMPLES if not s["attack"]]


def get_all_samples():
    """Return all test samples."""
    return TEST_SAMPLES
