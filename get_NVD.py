# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import re
import pandas as pd
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor
import time
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import random

# Function to scrape CVE details
def scrape_cve_details(cve_id):
    attempts = 0
    while attempts < 10:
        try:
            scout = 0
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            chrome_options = Options()
            chrome_options.add_argument('--headless')  # Enable headless mode
            chrome_driver_path = '/home/dell/chrome_drive/chromedriver'  # Replace with your Chromedriver path
            service = ChromeService(executable_path=chrome_driver_path)

            # Use Chrome webdriver to interact with the NVD website
            with webdriver.Chrome(service=service, options=chrome_options) as driver:
                driver.get(url)
                if driver.find_elements(By.ID, 'vulnDescriptionTitle'):
                    scout = 1
                # Find and click the "showVulnAnalysis" element to reveal additional details
                show_vuln_analysis_element = driver.find_element(By.ID, 'showVulnAnalysis')
                show_vuln_analysis_element.click()

                # Wait for the element with ID 'vulnAnalysisDescription' to be present
                element = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, 'vulnAnalysisDescription')))
                element_text = element.text

            print('======')
            print('Success:', cve_id)

            # Add a delay to avoid frequent requests
            t = random.randint(1, 6)
            time.sleep(t)  # Sleep for 3 seconds before the next request

            return element_text, cve_id

        except Exception as e:
            # Check if "cvssVulnDetailBtn" is present in the driver
            if scout == 1:
                return None

            attempts += 1
            print(f'Failed: (Attempt {attempts}/10)', e)
            t = random.randint(5, 15)
            time.sleep(t)

    return None

if __name__ == "__main__":
    # Read CVE ID list from an Excel file
    data_cve_id = pd.read_excel(r'nvd_id.xlsx', header=None)
    cid = [i for i in data_cve_id[0].tolist()[1:] if type(i) != float]
    res = []

    # Split CVE ID list into multiple chunks
    chunk_size = len(cid) // 10
    chunks = [cid[i:i + chunk_size] for i in range(0, len(cid), chunk_size)]

    # Create Chrome webdriver
    chrome_options = Options()
    chrome_options.add_argument('--headless')  # Enable headless mode
    chrome_driver_path = '/home/dell/chrome_drive/chromedriver'  # Replace with your Chromedriver path
    service = ChromeService(executable_path=chrome_driver_path)

    # Process each chunk of CVE IDs
    for chunk in chunks:
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Use ThreadPoolExecutor to parallelize the scraping process
            results = executor.map(scrape_cve_details, chunk)
            for result in results:
                if result:
                    res.append(result)

                # Check if there are 50 or more records, then save to CSV file
                # if len(res) >= 50:
                    df = pd.DataFrame()
                    df['id'] = [i[1] for i in res]
                    df['analysis'] = [i[0] for i in res]
                    df.to_csv('NVDanalysis.csv', mode='a', header=False, index=None)
                    res = []  # Clear the res list

    # Close Chrome webdriver
    service.stop()

    # Save the remaining results to CSV
    if len(res) > 0:
        df = pd.DataFrame()
        df['id'] = [i[1] for i in res]
        df['analysis'] = [i[0] for i in res]
        df.to_csv('NVDanalysis.csv', mode='a', header=False, index=None)
