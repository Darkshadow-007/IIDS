import yara
import os
import subprocess

# Define the destination directory where you want to save the encoded Zeek log bytes
destination_directory = "/home/Darkshadow/Desktop/IIDS2/Zeek_logs"

#Define the destination to save the Alerted files output
alerted_file="/home/Darkshadow/Desktop/IIDS2/"

# Define the path to the output merged log file
output_file = "/home/Darkshadow/Desktop/IIDS2/matched.log"

# Initialize a list to store matched log file names
matched_log_files = []

# Match YARA rules with Zeek logs
def match_yara_rules_with_logs(yara_rules, zeek_log_directory):
    if not yara_rules:
        return
    
    # Iterate through Zeek log files in the specified directory
    for log_filename in os.listdir(zeek_log_directory):
        log_file_path = os.path.join(zeek_log_directory, log_filename)

        # Check if the file is a Zeek log file (e.g., conn.log, http.log, etc.)
        if not os.path.isfile(log_file_path) or not log_filename.endswith(".log"):
            continue
            
            
        # Read and parse the Zeek log file
        with open(log_file_path, 'r') as log_file:
            
            zeek_log_content = log_file.read()
            #zeek_log_bytes = zeek_log_content.encode()

            # Ensure the destination directory exists, or create it if it doesn't
            if not os.path.exists(destination_directory):
                os.makedirs(destination_directory)

            # Define the destination file path in the new folder
            destination_file_path = os.path.join(destination_directory, log_filename)

            # Write the encoded Zeek log bytes to the destination file
            with open(destination_file_path, 'w') as destination_file:
                destination_file.write(zeek_log_content)

                
            # Change to the destination directory
            os.chdir(destination_directory)

            # Run the YARA command
            yara_command = "yara -r ../yararule.yar ./"
            yara_output = subprocess.check_output(yara_command, shell=True, cwd=destination_directory, universal_newlines=True)


    # Save the YARA command output to "Alerted rules" file
    with open(os.path.join(alerted_file, "Alerted_rules.txt"), 'w') as alerted_rules_file:
        alerted_rules_file.write(yara_output)

    Alert_command = "cat Alerted_rules.txt | grep -o '\w*\.log' > log.txt"
    alerted_output = subprocess.check_output(Alert_command, shell=True, cwd=alerted_file, universal_newlines=True)

    # Define the path to the file containing strings to match log file names
    match_file = "/home/Darkshadow/Desktop/IIDS2/log.txt"

    # Read the strings to match from the match file into a list
    with open(match_file, "r") as match_file:
        match_strings = [line.strip() for line in match_file]

    # Initialize an empty list to store the content of matched log files
    matched_log_content = []

    # Iterate through files in the log folder
    for filename in os.listdir(destination_directory):
        file_path = os.path.join(destination_directory, filename)

        # Check if the file is a regular file and its name matches any of the strings
        if os.path.isfile(file_path) and any(match_string in filename for match_string in match_strings):
            with open(file_path, "r") as log_file:
                matched_log_content.append(f"Data from '{filename}':\n")
                matched_log_content.append(log_file.read())
                matched_log_content.append("\n")

    # Write the content of matched log files to the output merged log file
    with open(output_file, "w") as merged_log_file:
        merged_log_file.writelines(matched_log_content)

    print("Detected logs have been saved to 'matched.log'.")
                
if __name__ == "__main__":
    rule_file = "yararule.yar"  # Replace with the path to your YARA rule file
    zeek_log_directory = "/opt/zeek/logs/current"  # Replace with the path to your Zeek log directory

    # Load YARA rules from a YARA rule file
    yara_rules = yara.compile(filepath=rule_file)

    if yara_rules:
        print("YARA rules loaded successfully!")

        # Match YARA rules with Zeek logs
        match_yara_rules_with_logs(yara_rules, zeek_log_directory)
