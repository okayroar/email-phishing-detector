import re
import csv

# Default list of suspicious keywords often found in phishing emails.
# The higher the score, the more suspicious the keyword.
suspicious_keywords = {
    "urgent": 5, "immediate": 5, "account": 4, "password": 5, "verify": 4, 
    "click": 3, "login": 4, "credit card": 5, "bank": 4, "limited time": 3, 
    "offer": 3, "update": 4, "security alert": 5, "refund": 3, "free": 3
}

# Function to detect suspicious keywords in an email text.
# It returns a dictionary of detected keywords with their scores and the total phishing score.
def detect_phishing(email_text, keywords):
    # Convert email text to lowercase to ensure case-insensitive matching.
    email_text = email_text.lower()
    
    detected_keywords = {}  # Dictionary to store detected keywords.
    phishing_score = 0  # Initialize phishing score to 0.
    
    # Loop through the predefined suspicious keywords and scores.
    for keyword, score in keywords.items():
        # Check if the keyword is present in the email text.
        if keyword in email_text:
            detected_keywords[keyword] = score  # Store the detected keyword and its score.
            phishing_score += score  # Add the score of the keyword to the total phishing score.
    
    return detected_keywords, phishing_score  # Return detected keywords and total phishing score.

# Function to detect URLs and .apk file links in the email.
# It returns two lists: one for .apk URLs and one for insecure HTTP URLs.
def detect_urls_and_apk(email_text):
    # Use regular expression to find all URLs in the email (both http and https).
    urls = re.findall(r'(https?://\S+|http://\S+)', email_text)
    
    detected_apk_urls = []  # List to store URLs that contain .apk files (potentially harmful).
    detected_http_urls = []  # List to store insecure HTTP URLs (potential phishing risk).
    
    # Loop through the detected URLs to identify .apk and HTTP links.
    for url in urls:
        if ".apk" in url:
            detected_apk_urls.append(url)  # If the URL contains an .apk file, add to list.
        if url.startswith("http://"):
            detected_http_urls.append(url)  # If the URL is HTTP (not HTTPS), add to list.
    
    return detected_apk_urls, detected_http_urls  # Return both lists of URLs.

# Function to allow users to add custom phishing keywords.
# Users can assign a risk score (1-5) to their custom keywords.
def customize_keywords():
    print("\nWould you like to add any custom keywords? (yes/no)")
    choice = input().lower()  # Ask user if they want to add custom keywords.

    if choice == "yes":  # If user chooses yes, enter the customization loop.
        while True:
            keyword = input("Enter the custom keyword: ")  # Prompt for a custom keyword.
            score = input(f"Assign a risk score (1-5) for '{keyword}': ")  # Ask for a score between 1 and 5.
            
            # Check if the score is valid (an integer between 1 and 5).
            if score.isdigit() and 1 <= int(score) <= 5:
                suspicious_keywords[keyword.lower()] = int(score)  # Add custom keyword to the suspicious list.
                print(f"'{keyword}' added with a score of {score}.")
            else:
                print("Please enter a valid score between 1 and 5.")  # Prompt for a valid score if input is incorrect.
            
            # Ask user if they want to add another keyword or stop.
            more = input("Do you want to add another keyword? (yes/no): ").lower()
            if more == "no":  # Break out of the loop if the user is done adding keywords.
                break

# Function to analyze emails from a CSV file.
# It reads each email's content and subject from the CSV file and analyzes it for phishing indicators.
def analyze_emails_from_csv(file_path):
    # Open the CSV file containing emails using the CSV module.
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        email_reader = csv.DictReader(csvfile)  # Read the CSV file into a dictionary format (column names as keys).
        
        # Loop through each row (email) in the CSV file.
        for row in email_reader:
            email_content = row['email_content']  # Extract the email content.
            email_subject = row['subject']  # Extract the email subject.
            
            # Display the email subject before analysis for clarity.
            print(f"\nAnalyzing email with subject: {email_subject}")
            
            # Detect suspicious keywords and calculate the phishing score for the email.
            detected_keywords, phishing_score = detect_phishing(email_content, suspicious_keywords)
            
            # Detect URLs and .apk file links in the email content.
            detected_apk_urls, detected_http_urls = detect_urls_and_apk(email_content)
            
            # Check if any suspicious keywords were found in the email.
            if detected_keywords:
                print("\nPotential phishing email detected!")
                print("Suspicious keywords found with scores:", detected_keywords)
                print(f"Phishing risk score: {phishing_score}")
            else:
                print("\nNo suspicious keywords found.")
            
            # Check if any .apk URLs were detected (potentially harmful).
            if detected_apk_urls:
                print("\nDetected .apk file URLs (potentially harmful):")
                for url in detected_apk_urls:
                    print(f"- {url}")
            
            # Check if any insecure HTTP URLs were detected (potential phishing risk).
            if detected_http_urls:
                print("\nDetected insecure HTTP URLs (potential phishing risk):")
                for url in detected_http_urls:
                    print(f"- {url}")
            
            # Provide a final assessment based on phishing risk score and detected URLs.
            if phishing_score > 10 or detected_apk_urls:
                print("\nWarning: The email has a high phishing risk!")  # High-risk assessment if score > 10 or .apk found.
            elif phishing_score > 5:
                print("\nCaution: The email may be phishing, please review carefully.")  # Moderate risk if score > 5.
            else:
                print("\nThe email seems safe, but remain vigilant.")  # Low risk if score <= 5.

# Main function to run the entire program.
def main():
    customize_keywords()
    file_path = input("Enter the path to your CSV file: ")
    analyze_emails_from_csv(file_path)

main()