import os
import sys
import time
import json
import logging
import datetime
from utils import clear_console, display_testcase_summary
from uds_client import UDSClient
from drivers import oled_display, button

class UDSApp:
    def __init__(self):
        self.client = UDSClient()
        self.oled = None
        self.tester_name = None
        try:
            self.oled = oled_display.OLED()
            logging.info("OLED initialized successfully.")
        except Exception as e:
            logging.warning(f"OLED initialization failed: {e}")
        self.test_cases = self.load_test_cases()

    def load_test_cases(self):
        if os.path.exists("test_cases.json"):
            with open("test_cases.json", "r") as f:
                return json.load(f)
        return []

    def save_test_cases(self):
        with open("test_cases.json", "w") as f:
            json.dump(self.test_cases, f, indent=4)

    def get_tester_name(self):
        while True:
            name = input("Enter Tester Name: ").strip()
            if name:
                self.tester_name = name
                logging.info(f"Tester: {self.tester_name}")
                with open("tester_info.txt", "w") as f:
                    f.write(f"Tester: {self.tester_name}\n")
                if self.oled:
                    self.oled.display_centered_text(f"Tester:\n{self.tester_name}")
                    time.sleep(2)
                break
            else:
                print("Name cannot be empty. Please try again.")

    def main_menu(self):
        while True:
            clear_console()
            print("UDS Diagnostic Tool")
            print("====================")
            print("1. Run UDS Test Cases")
            print("2. View Test Case Summary")
            print("3. Exit")
            choice = input("Enter your choice: ").strip()

            if choice == "1":
                self.run_test_cases()
            elif choice == "2":
                display_testcase_summary(self.test_cases)
                input("Press Enter to return to the main menu...")
            elif choice == "3":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")
                time.sleep(2)

    def run_test_cases(self):
        if not self.test_cases:
            print("No test cases found.")
            time.sleep(2)
            return

        for test_case in self.test_cases:
            print(f"Running Test Case: {test_case['id']} - {test_case['description']}")
            result = self.client.run_test_case(test_case)
            test_case['result'] = result
            print(f"Result: {result}\n")
            time.sleep(1)

        self.save_test_cases()
        print("All test cases executed.")
        time.sleep(2)

def main():
    app = UDSApp()
    app.get_tester_name()
    app.main_menu()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    main()
