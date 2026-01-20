import time
import hashlib
from datetime import datetime

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

from models import db, Scheme

def run_scheme_scraper():

    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--window-size=1920,1080")

    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=options
    )

    wait = WebDriverWait(driver, 20)

    def get_scheme_id(url):
        return url.rstrip("/").split("/")[-1]

    def hash_content(text):
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    try:
        driver.get("https://www.myscheme.gov.in/search")

        search_box = wait.until(
            EC.presence_of_element_located((By.NAME, "query"))
        )
        search_box.send_keys("agriculture")
        search_box.send_keys(Keys.ENTER)
        time.sleep(4)

        page = 1

        while True:
            cards = driver.find_elements(
                By.CSS_SELECTOR, "div[role='article']"
            )

            for card in cards:
                try:
                    link = card.find_element(By.CSS_SELECTOR, "h2 a")
                    name = link.text.strip()
                    href = link.get_attribute("href")

                    if href.startswith("http"):
                        url = href
                    else:
                        url = "https://www.myscheme.gov.in" + href

                    scheme_id = get_scheme_id(url)

                    # State
                    try:
                        state = card.find_element(
                            By.XPATH, ".//h2[@role='button']"
                        ).text.strip()
                        coverage_type = "State"
                    except:
                        state = None
                        coverage_type = "Central"

                    # Description
                    try:
                        description = card.find_element(
                            By.XPATH,
                            ".//span[contains(@aria-label,'Brief description')]"
                        ).text.strip()
                    except:
                        description = None

                    # Tags
                    tags = [
                        t.text.strip()
                        for t in card.find_elements(
                            By.XPATH,
                            ".//div[contains(@aria-label,'Filter by tag')]"
                        )
                        if t.text.strip()
                    ]

                    tags_str = ",".join(tags)

                    scheme_type = "Grant" if "Grant" in tags else None
                    beneficiary_type = "Student" if "Student" in tags else None
                    category = "Agriculture"

                    content_hash = hash_content(name + (description or ""))

                    scheme = Scheme.query.filter_by(scheme_id=scheme_id).first()

                    if scheme:
                        if scheme.content_hash != content_hash:
                            scheme.name = name
                            scheme.scheme_url = url
                            scheme.state = state
                            scheme.coverage_type = coverage_type
                            scheme.description = description
                            scheme.tags = tags_str
                            scheme.scheme_type = scheme_type
                            scheme.beneficiary_type = beneficiary_type
                            scheme.category = category
                            scheme.content_hash = content_hash
                            scheme.last_scraped = datetime.utcnow()
                            scheme.scrape_status = "updated"
                    else:
                        db.session.add(Scheme(
                            scheme_id=scheme_id,
                            name=name,
                            scheme_url=url,
                            state=state,
                            coverage_type=coverage_type,
                            description=description,
                            tags=tags_str,
                            scheme_type=scheme_type,
                            beneficiary_type=beneficiary_type,
                            category=category,
                            content_hash=content_hash,
                            last_scraped=datetime.utcnow(),
                            scrape_status="inserted"
                        ))

                except:
                    continue

            db.session.commit()

            # Pagination
            try:
                page += 1
                btn = driver.find_element(
                    By.XPATH, f"//li[normalize-space()='{page}']"
                )
                driver.execute_script(
                    "arguments[0].scrollIntoView({block:'center'});", btn
                )
                time.sleep(1)
                btn.click()
                time.sleep(4)
            except:
                break

    finally:
        driver.quit()
