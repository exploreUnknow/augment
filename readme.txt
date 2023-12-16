Experiment Setup:

    Environment Installation: The environment setup file is requirements.txt. Run the command "pip install -r requirements" to install the required packages.
    Launch ChatGPT Service: Firstly, Django needs to be installed on your computer. Start Django using the command "python manage.py runserver 0.0.0.0:8000."
    Run the Program: The main program is named "main.py" and it takes "test_data_CVE.data" as input.
    Output Results: The output results are stored in "experimental_result.xlsx."

NVD Data Crawling Code:

    Open nvd_id.xlsx to find a list of all CVE IDs for the year 2023. We default to crawling data for 2023, but you can input different IDs for other years.
    It's crucial to note that NVD has a strict anti-crawling mechanism. After multiple attempts, we found that web scraping using the request method is challenging. Therefore, we use a simulated browser approach for crawling.
    Check the data folder for the crawling results.

CVE Data Processing:

    Since CVE data is available for download, there is no need for web scraping.
    After downloading CVE data, use the code "get_cve.py" for processing CVE data.

Data Processing:

    We processed the data by replacing key information in CVE data with "unknown" and handling crucial information in NVD data's analysis and modify fields. The differential key information was then extracted as labels.
    Refer to the file "precess_nvd_cve.py" for the above operations.
    Check the data folder for the processing results.
