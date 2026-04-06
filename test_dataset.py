"""
Labeled test dataset for social engineering detection evaluation.
Expanded dataset: 150+ samples with ground truth labels.
Includes URL-based attacks, F1/F2 test cases, and edge cases.
"""

TEST_SAMPLES = [
    # =========================================================================
    # ATTACK SAMPLES (75+ samples)
    # =========================================================================
    
    # Fear/Threat samples (12)
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
    {
        "text": "Your credit score has dropped significantly due to unpaid debt. Resolve now or face collection.",
        "labels": ["Fear/Threat"],
        "attack": True
    },
    {
        "text": "ALERT: Unauthorized transaction of $4,999 detected. Confirm or dispute within 2 hours.",
        "labels": ["Fear/Threat", "Urgency"],
        "attack": True
    },
    
    # Authority/Impersonation samples (12)
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
    {
        "text": "WhatsApp Security: Your account will be deleted. Verify at whatsapp-verify.xyz",
        "labels": ["Authority", "Impersonation"],
        "attack": True
    },
    {
        "text": "Netflix Billing: Payment failed. Update card at netflix-secure-billing.tk or lose access.",
        "labels": ["Authority", "Impersonation", "Urgency"],
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
    
    # Reward/Lure samples (12)
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
    {
        "text": "Double your crypto investment in 24 hours! Join our exclusive trading group now.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "CONGRATULATIONS! You've won a brand new Tesla Model 3. Claim at tesla-giveaway.xyz",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    
    # URL-based attacks (F1 test cases) (15)
    {
        "text": "Verify your account at http://secure-paypal-login.xyz to avoid suspension.",
        "labels": ["Impersonation", "Urgency"],
        "attack": True
    },
    {
        "text": "Your Netflix payment failed. Update at http://netflix-billing.tk/update",
        "labels": ["Impersonation", "Urgency"],
        "attack": True
    },
    {
        "text": "Click here to claim your prize: bit.ly/free-iphone-15-winner",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "Bank security alert! Confirm your identity: http://192.168.1.100/bank-verify",
        "labels": ["Fear/Threat", "Impersonation"],
        "attack": True
    },
    {
        "text": "Your Amazon order requires verification: http://arnazon-orders.com/verify",
        "labels": ["Impersonation"],
        "attack": True
    },
    {
        "text": "Microsoft Account: Unusual signin. Verify at http://micr0soft-account.ru/login",
        "labels": ["Impersonation", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "Google Security: Confirm your identity at tinyurl.com/google-verify-2024",
        "labels": ["Impersonation"],
        "attack": True
    },
    {
        "text": "Your Apple ID was locked. Unlock at http://appie-id-verify.top/unlock",
        "labels": ["Impersonation", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "Claim your $1000 Walmart gift card: http://walmart-rewards.gq/claim",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "LinkedIn Security: Verify your professional profile at linkedin-verify.buzz",
        "labels": ["Impersonation"],
        "attack": True
    },
    {
        "text": "Your package is held at customs. Pay fee at http://ups-delivery.ml/customs",
        "labels": ["Impersonation", "Urgency"],
        "attack": True
    },
    {
        "text": "Facebook alert: Someone logged in from new device. Secure at fb-security.cc",
        "labels": ["Impersonation", "Fear/Threat"],
        "attack": True
    },
    {
        "text": "Update your password now: http://paypa1-secure.xyz/account-recovery",
        "labels": ["Impersonation"],
        "attack": True
    },
    {
        "text": "IRS refund of $2,847 available. Claim at http://irs-refund-claim.tk",
        "labels": ["Authority", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "Your Instagram account will be deleted. Appeal at insta-appeal.top/save",
        "labels": ["Impersonation", "Fear/Threat"],
        "attack": True
    },
    
    # OTP/Code scams (5)
    {
        "text": "Your OTP is 847291. Share this code with our support agent to verify your account.",
        "labels": ["Impersonation"],
        "attack": True
    },
    {
        "text": "We sent you a verification code. Please reply with the code to complete the transfer.",
        "labels": ["Impersonation"],
        "attack": True
    },
    {
        "text": "Your WhatsApp verification code is needed for security audit. Send it now.",
        "labels": ["Impersonation", "Urgency"],
        "attack": True
    },
    {
        "text": "I accidentally sent my code to your number. Can you forward me the 6-digit code?",
        "labels": ["Impersonation"],
        "attack": True
    },
    {
        "text": "Bank security requires your SMS code for verification. Reply with the code.",
        "labels": ["Authority", "Impersonation"],
        "attack": True
    },
    
    # Job scams (5)
    {
        "text": "Congratulations! You're hired for remote data entry. $45/hour. Send SSN to proceed.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "We found your resume. Immediate opening for $80k/year work from home position.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "HR: You're selected for final interview. Wire $500 for background check to proceed.",
        "labels": ["Authority", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "Make $10,000/month as a package forwarder! Easy work, no experience needed.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "Job offer: Social media manager. $5000/week. Send copy of ID to start immediately.",
        "labels": ["Reward/Lure", "Urgency"],
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
    
    # Romance/Relationship scams (4)
    {
        "text": "I'm a US soldier stationed overseas. I've fallen in love with you. Send $500 for my flight home.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    {
        "text": "I'm stuck abroad and lost my wallet. Can you wire me $1000? I'll pay you back double.",
        "labels": ["Urgency", "Reward/Lure"],
        "attack": True
    },
    {
        "text": "We've been chatting for weeks. I need help with hospital bills. Can you send crypto?",
        "labels": ["Fear/Threat"],
        "attack": True
    },
    {
        "text": "I want to send you a gift package worth $50,000 but need $200 for customs clearance.",
        "labels": ["Reward/Lure"],
        "attack": True
    },
    
    # =========================================================================
    # BENIGN SAMPLES (75+ samples)
    # =========================================================================
    
    # Normal business communication (12)
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
    {
        "text": "Please review the budget proposal and let me know your thoughts by end of week.",
        "labels": [],
        "attack": False
    },
    {
        "text": "The project timeline has been updated. New deadline is December 15th.",
        "labels": [],
        "attack": False
    },
    
    # Personal messages (12)
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
    {
        "text": "Got your message about the movie night. I'll bring snacks!",
        "labels": [],
        "attack": False
    },
    {
        "text": "Hope you're feeling better. Let me know if you need anything from the store.",
        "labels": [],
        "attack": False
    },
    
    # Legitimate service notifications (15)
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
    {
        "text": "Your order has shipped! Track it at ups.com with tracking number 1Z999AA10123456784.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Reminder: Your car service appointment is tomorrow at 9 AM at AutoCare Center.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your prescription is ready for pickup at CVS Pharmacy on Main Street.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Thank you for your payment of $150.00. Your balance is now $0.00.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your credit card ending in 4242 was used for a $25.99 purchase at Amazon.",
        "labels": [],
        "attack": False
    },
    
    # Educational/Informational (12)
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
    {
        "text": "Grades have been posted to the student portal. Check your results there.",
        "labels": [],
        "attack": False
    },
    {
        "text": "The campus career fair is next Wednesday. Bring copies of your resume.",
        "labels": [],
        "attack": False
    },
    
    # Legitimate promotions/newsletters (12)
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
    {
        "text": "Our app just got updated with new features. Update from the App Store or Google Play.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Join our loyalty program and earn points on every purchase. Sign up at checkout.",
        "labels": [],
        "attack": False
    },
    
    # Legitimate URLs (trusted domains) (10)
    {
        "text": "Reset your password at https://accounts.google.com/signin/recovery",
        "labels": [],
        "attack": False
    },
    {
        "text": "View your order status at https://www.amazon.com/your-orders",
        "labels": [],
        "attack": False
    },
    {
        "text": "Update your payment method at https://www.paypal.com/myaccount/settings",
        "labels": [],
        "attack": False
    },
    {
        "text": "Check your statement at https://www.chase.com/personal/online-banking",
        "labels": [],
        "attack": False
    },
    {
        "text": "Download the latest version at https://github.com/microsoft/vscode/releases",
        "labels": [],
        "attack": False
    },
    {
        "text": "Join the meeting at https://zoom.us/j/123456789",
        "labels": [],
        "attack": False
    },
    {
        "text": "View the shared document at https://docs.google.com/document/d/example",
        "labels": [],
        "attack": False
    },
    {
        "text": "Track your package at https://www.ups.com/track?tracknum=1Z999",
        "labels": [],
        "attack": False
    },
    {
        "text": "Update your profile at https://www.linkedin.com/in/yourprofile",
        "labels": [],
        "attack": False
    },
    {
        "text": "Subscribe to our channel at https://www.youtube.com/channel/example",
        "labels": [],
        "attack": False
    },
    
    # Healthcare/Medical (5)
    {
        "text": "Reminder: Your annual checkup is scheduled for next Tuesday at 10 AM.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your lab results are ready. Log into the patient portal to view them.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Time to refill your prescription. Contact your pharmacy to place an order.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your insurance claim has been processed. You can view the details online.",
        "labels": [],
        "attack": False
    },
    {
        "text": "The doctor's office is closed Friday. For emergencies, call the after-hours line.",
        "labels": [],
        "attack": False
    },
    
    # Banking/Financial (legitimate) (5)
    {
        "text": "Your monthly statement is available. Log into online banking to view it.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Direct deposit of $2,500.00 has been credited to your checking account.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your credit card payment of $350 was received. Thank you.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Reminder: Your loan payment is due on the 15th of this month.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your new debit card has been mailed and should arrive in 5-7 business days.",
        "labels": [],
        "attack": False
    },
    
    # Social media notifications (5)
    {
        "text": "John Smith commented on your post: 'Great photo!'",
        "labels": [],
        "attack": False
    },
    {
        "text": "You have 5 new connection requests on LinkedIn.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Sarah liked your photo from last weekend.",
        "labels": [],
        "attack": False
    },
    {
        "text": "You were mentioned in a comment by @friend123.",
        "labels": [],
        "attack": False
    },
    {
        "text": "Your tweet received 50 likes and 10 retweets.",
        "labels": [],
        "attack": False
    },
]

# =========================================================================
# HELD-OUT VALIDATION SET (20% - DO NOT USE FOR TRAINING/TUNING)
# These samples are for final evaluation only
# =========================================================================
VALIDATION_SAMPLES = [
    # QR Phishing attacks (new category)
    {"text": "Scan this QR code to verify your PayPal account before it's suspended.", "labels": ["Urgency", "Impersonation"], "attack": True},
    {"text": "Use QR to claim your Amazon gift card reward. Limited time only!", "labels": ["Reward/Lure", "Urgency"], "attack": True},
    {"text": "QR code payment required to release your package from customs.", "labels": ["Fear/Threat"], "attack": True},
    {"text": "Scan barcode to update your banking credentials securely.", "labels": ["Authority"], "attack": True},
    {"text": "QR authentication needed to prevent account termination.", "labels": ["Fear/Threat", "Urgency"], "attack": True},
    
    # BEC attacks
    {"text": "CFO here. Wire $75,000 to vendor immediately. Keep confidential.", "labels": ["Authority", "Urgency"], "attack": True},
    {"text": "New vendor bank account details attached. Process payment today.", "labels": ["Authority", "Urgency"], "attack": True},
    {"text": "Buy Apple gift cards for client appreciation. Send codes ASAP.", "labels": ["Authority", "Urgency"], "attack": True},
    {"text": "Payroll department: Update direct deposit to this new account number.", "labels": ["Authority"], "attack": True},
    {"text": "This is HR. Your bonus will be deposited to this new account.", "labels": ["Authority", "Reward/Lure"], "attack": True},
    
    # Crypto scams
    {"text": "Connect MetaMask wallet to claim free Ethereum airdrop now!", "labels": ["Reward/Lure", "Urgency"], "attack": True},
    {"text": "Enter seed phrase to recover compromised wallet assets.", "labels": ["Fear/Threat", "Urgency"], "attack": True},
    {"text": "Guaranteed 100% returns on Bitcoin investment. Join now!", "labels": ["Reward/Lure"], "attack": True},
    {"text": "NFT minting live! Connect wallet and approve transaction.", "labels": ["Urgency"], "attack": True},
    {"text": "Crypto exchange security: Verify wallet or funds frozen.", "labels": ["Fear/Threat", "Authority"], "attack": True},
    
    # Government impersonation
    {"text": "IRS: You owe $5,000 in taxes. Pay via gift card to avoid arrest.", "labels": ["Authority", "Fear/Threat"], "attack": True},
    {"text": "Social Security suspended. Call immediately to restore.", "labels": ["Authority", "Fear/Threat", "Urgency"], "attack": True},
    {"text": "DMV: License suspended. Pay fine online to reinstate.", "labels": ["Authority", "Fear/Threat"], "attack": True},
    {"text": "FBI: Your IP linked to illegal activity. Cooperate now.", "labels": ["Authority", "Fear/Threat"], "attack": True},
    {"text": "Medicare: Free genetic test kit. Provide Medicare number.", "labels": ["Authority", "Reward/Lure"], "attack": True},
    
    # Tech support scams
    {"text": "Windows Defender: Critical virus detected! Call Microsoft immediately.", "labels": ["Authority", "Fear/Threat", "Urgency"], "attack": True},
    {"text": "Your computer is sending spam. Call this number to fix.", "labels": ["Fear/Threat", "Urgency"], "attack": True},
    {"text": "Apple Support: iCloud breached. Verify credentials now.", "labels": ["Authority", "Fear/Threat"], "attack": True},
    {"text": "Antivirus expired. Renew immediately or risk infection.", "labels": ["Fear/Threat", "Urgency"], "attack": True},
    {"text": "Browser infected with malware. Download fix tool now.", "labels": ["Fear/Threat", "Urgency"], "attack": True},
    
    # Multilingual attacks
    {"text": "紧急通知：您的账户已被暂停。立即验证以恢复访问。", "labels": ["Urgency", "Fear/Threat"], "attack": True},
    {"text": "Срочно! Ваш аккаунт заблокирован. Подтвердите пароль немедленно.", "labels": ["Urgency", "Fear/Threat"], "attack": True},
    {"text": "عاجل: تم تعليق حسابك. انقر هنا للتحقق من هويتك.", "labels": ["Urgency", "Fear/Threat"], "attack": True},
    {"text": "긴급: 계정이 정지되었습니다. 지금 비밀번호를 확인하세요.", "labels": ["Urgency", "Fear/Threat"], "attack": True},
    {"text": "Votre compte sera suspendu. Vérifiez immédiatement avec ce lien.", "labels": ["Urgency", "Fear/Threat"], "attack": True},
    
    # Adversarial/Obfuscated
    {"text": "V e r i f y your acc0unt n0w or it will be $uspended!", "labels": ["Urgency", "Fear/Threat"], "attack": True},
    {"text": "Urgent: Your pаypal аccount needs verification. Click here.", "labels": ["Urgency", "Impersonation"], "attack": True},
    {"text": "Your Аmаzоn order has a problem. Update раyment info.", "labels": ["Impersonation", "Urgency"], "attack": True},
    {"text": "L0gin to your bаnk аccount imm3diately to avoid susp3nsion.", "labels": ["Urgency", "Fear/Threat"], "attack": True},
    {"text": "C1ick here to c1aim your $1000 r3ward before it exp1res!", "labels": ["Reward/Lure", "Urgency"], "attack": True},
    
    # Romance/pig butchering
    {"text": "I'm an engineer stuck overseas. Send $500 and I'll pay you back double.", "labels": ["Reward/Lure"], "attack": True},
    {"text": "My crypto platform has 50% daily returns. Join my exclusive group.", "labels": ["Reward/Lure"], "attack": True},
    {"text": "I need help with medical bills. Can you wire money via Western Union?", "labels": ["Fear/Threat"], "attack": True},
    {"text": "Send the customs fee and I'll send you the $50,000 package.", "labels": ["Reward/Lure"], "attack": True},
    {"text": "Investment opportunity: guaranteed profits, no risk, act now!", "labels": ["Reward/Lure", "Urgency"], "attack": True},
    
    # Benign samples for validation
    {"text": "Your Uber ride has ended. Receipt attached for your records.", "labels": [], "attack": False},
    {"text": "Team standup at 10 AM tomorrow. Please prepare your updates.", "labels": [], "attack": False},
    {"text": "Your GitHub pull request has been merged successfully.", "labels": [], "attack": False},
    {"text": "Conference call link: https://zoom.us/j/987654321", "labels": [], "attack": False},
    {"text": "Please review the attached document before our meeting.", "labels": [], "attack": False},
    {"text": "Office will be closed for maintenance this Saturday.", "labels": [], "attack": False},
    {"text": "Your expense report has been approved by your manager.", "labels": [], "attack": False},
    {"text": "New blog post: 10 Tips for Remote Work Productivity", "labels": [], "attack": False},
    {"text": "Your dentist appointment is confirmed for Thursday 2 PM.", "labels": [], "attack": False},
    {"text": "Package delivered to front door. Thank you for shopping with us.", "labels": [], "attack": False},
    {"text": "Your Spotify Premium subscription renewed successfully.", "labels": [], "attack": False},
    {"text": "Flight itinerary attached for your trip next week.", "labels": [], "attack": False},
    {"text": "Welcome to our newsletter! Here's what's new this month.", "labels": [], "attack": False},
    {"text": "Your library books are due in 5 days. Renew online if needed.", "labels": [], "attack": False},
    {"text": "Team happy hour at 5 PM. Join us at the usual spot!", "labels": [], "attack": False},
    {"text": "Your annual performance review is scheduled for next Monday.", "labels": [], "attack": False},
    {"text": "Movie tickets confirmed: 2 seats for Saturday 8 PM showing.", "labels": [], "attack": False},
    {"text": "Your food delivery is on the way. Arrives in 20 minutes.", "labels": [], "attack": False},
    {"text": "Weather update: Sunny skies expected for the weekend.", "labels": [], "attack": False},
    {"text": "Thank you for your purchase at Target. See you again soon!", "labels": [], "attack": False},
]


def get_attack_samples():
    """Return only attack samples from main test set."""
    return [s for s in TEST_SAMPLES if s["attack"]]


def get_benign_samples():
    """Return only benign samples from main test set."""
    return [s for s in TEST_SAMPLES if not s["attack"]]


def get_all_samples():
    """Return all main test samples (training/tuning allowed)."""
    return TEST_SAMPLES


def get_validation_samples():
    """Return held-out validation samples (final evaluation only)."""
    return VALIDATION_SAMPLES


def get_all_samples_with_validation():
    """Return combined test + validation samples."""
    return TEST_SAMPLES + VALIDATION_SAMPLES


def get_url_attack_samples():
    """Return attack samples containing URLs (F1 test cases)."""
    url_patterns = ["http://", "https://", "www.", ".xyz", ".tk", ".ru", "bit.ly", "tinyurl"]
    return [s for s in TEST_SAMPLES if s["attack"] and any(p in s["text"].lower() for p in url_patterns)]


def get_qr_attack_samples():
    """Return attack samples related to QR code phishing."""
    qr_patterns = ["qr", "scan", "barcode"]
    all_samples = TEST_SAMPLES + VALIDATION_SAMPLES
    return [s for s in all_samples if s["attack"] and any(p in s["text"].lower() for p in qr_patterns)]


def get_multilingual_samples():
    """Return samples containing non-ASCII characters (multilingual)."""
    def has_non_ascii(text):
        return any(ord(c) > 127 for c in text)
    all_samples = TEST_SAMPLES + VALIDATION_SAMPLES
    return [s for s in all_samples if has_non_ascii(s["text"])]


def get_stats():
    """Return dataset statistics."""
    attacks = get_attack_samples()
    benign = get_benign_samples()
    url_attacks = get_url_attack_samples()
    val_attacks = [s for s in VALIDATION_SAMPLES if s["attack"]]
    val_benign = [s for s in VALIDATION_SAMPLES if not s["attack"]]
    return {
        "total": len(TEST_SAMPLES),
        "attacks": len(attacks),
        "benign": len(benign),
        "url_attacks": len(url_attacks),
        "validation_total": len(VALIDATION_SAMPLES),
        "validation_attacks": len(val_attacks),
        "validation_benign": len(val_benign),
    }
