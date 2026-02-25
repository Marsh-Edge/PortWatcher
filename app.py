# Import modules for system operations and program control
import os
import sys

# Define constants for user menu choices (string values for comparison with input)
ALL_PROTOCOLS = "1"
TCP_PROTOCOL = "2"
UDP_PROTOCOL = "3"
EXIT = "4"

# Define file paths for each scanning protocol script
APP_PATH = "app.py"
ALL_PROTOCOLS_PATH = "Protocols/All-Protocol.py"
TCP_PROTOCOL_PATH = "Protocols/Tcp.py"
UDP_PROTOCOL_PATH = "Protocols/Udp.py"

# Display main menu banner and welcome message
print("\n----------------------------------------")
print("\nWelcome to the Port Scanner App!")
print("\nPlease select a scanning protocol:")

# Prompt user to select a scanning option and store their choice
choose = input("\n1. All Protocols\n2. TCP\n3. UDP\n4. Exit\nEnter your choice: \n")

# Infinite loop to keep the menu active until user chooses to exit
while True:
  # Check if user selected option 1: Scan all protocols (TCP, UDP, and comprehensive)
  if choose == ALL_PROTOCOLS:
    # Execute the All-Protocol scanning script as a separate process
    os.system(f"python {ALL_PROTOCOLS_PATH}")
    # Ask user if they want to return to the main menu
    if input("\nDo want to return to the main menu? (y/n): ").lower() == 'y':
      # Restart the app to show the menu again
      os.system(f"python {APP_PATH}")
  # Check if user selected option 2: Scan TCP ports only
  elif choose == TCP_PROTOCOL:
    # Execute the TCP port scanning script as a separate process
    os.system(f"python {TCP_PROTOCOL_PATH}")
    # Ask user if they want to return to the main menu
    if input("\nDo want to return to the main menu? (y/n): ").lower() == 'y':
      # Restart the app to show the menu again
      os.system(f"python {APP_PATH}")
  # Check if user selected option 3: Scan UDP ports only
  elif choose == UDP_PROTOCOL:
    # Execute the UDP port scanning script as a separate process
    os.system(f"python {UDP_PROTOCOL_PATH}")
    # Ask user if they want to return to the main menu
    if input("\nDo want to return to the main menu? (y/n): ").lower() == 'y':
      # Restart the app to show the menu again
      os.system(f"python {APP_PATH}")
  # Check if user selected option 4: Exit the application
  elif choose == EXIT:
    # Display exit message
    print("\nExiting the Port Scanner App. Goodbye!")
    # Terminate the program immediately
    sys.exit()
  # Handle invalid user input
  else:
    # Display error message for invalid choice
    print("\nInvalid choice. Please select a valid option.")