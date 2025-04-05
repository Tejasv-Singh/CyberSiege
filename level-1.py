import argparse
import re
import time
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException


class PriceTracker:
    def __init__(self, headless=True):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Setup Selenium for JavaScript-rendered pages
        self.chrome_options = Options()
        if headless:
            self.chrome_options.add_argument("--headless")
        self.chrome_options.add_argument("--no-sandbox")
        self.chrome_options.add_argument("--disable-dev-shm-usage")
        self.chrome_options.add_argument("--disable-gpu")
        self.chrome_options.add_argument("--window-size=1920,1080")
        
        # Site-specific extraction methods
        self.site_handlers = {
            'books.toscrape.com': self._handle_books_toscrape,
            'amazon': self._handle_amazon,
            'flipkart': self._handle_flipkart,
            'meesho': self._handle_meesho
        }

    def _needs_javascript(self, domain):
        """Determine if the site requires JavaScript rendering"""
        static_sites = ['books.toscrape.com']
        return domain not in static_sites

    def _normalize_price(self, price_text):
        """Extract and normalize price from various formats"""
        if not price_text:
            return "Not available"
        
        # Remove currency symbols and non-numeric characters except for decimal point
        price_text = price_text.strip()
        price_match = re.search(r'[\d,]+\.?\d*', price_text)
        if price_match:
            # Remove commas and convert to float for consistent formatting
            price = price_match.group().replace(',', '')
            return price
        return price_text

    def _handle_books_toscrape(self, soup, driver=None):
        """Extract product details from Books to Scrape website"""
        product_name = soup.select_one("div.product_main h1").text.strip()
        price = soup.select_one("p.price_color").text.strip()
        return product_name, self._normalize_price(price)

    def _handle_amazon(self, soup, driver):
        """Extract product details from Amazon"""
        try:
            # Wait for title to be visible
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "productTitle"))
            )
            
            product_name = driver.find_element(By.ID, "productTitle").text.strip()
            
            # Amazon uses various price selectors
            price_selectors = [
                "span.a-price span.a-offscreen",
                "#priceblock_ourprice",
                "#priceblock_dealprice",
                ".a-price .a-offscreen"
            ]
            
            price_text = None
            for selector in price_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        price_text = elements[0].text
                        break
                except:
                    continue
                    
            return product_name, self._normalize_price(price_text or "Price not found")
        except Exception as e:
            return f"Error extracting Amazon data: {str(e)}", "Not available"

    def _handle_flipkart(self, soup, driver):
        """Extract product details from Flipkart"""
        try:
            # Wait for product details to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "span._35KyD6, div._30jeq3"))
            )
            
            # Try different selectors for product name
            name_selectors = ["span._35KyD6", "h1.yhB1nd", "span.B_NuCI"]
            product_name = None
            for selector in name_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        product_name = elements[0].text.strip()
                        break
                except:
                    continue
            
            # Try different selectors for price
            price_selectors = ["div._30jeq3", "div._30jeq3._16Jk6d"]
            price_text = None
            for selector in price_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        price_text = elements[0].text
                        break
                except:
                    continue
                    
            return product_name or "Name not found", self._normalize_price(price_text or "Price not found")
        except Exception as e:
            return f"Error extracting Flipkart data: {str(e)}", "Not available"

    def _handle_meesho(self, soup, driver):
        """Extract product details from Meesho"""
        try:
            # Wait for product details to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "h1, span.sc-eDvSVe"))
            )
            
            # Get product name
            name_element = driver.find_element(By.CSS_SELECTOR, "h1")
            product_name = name_element.text.strip()
            
            # Get price - try multiple selectors
            price_selectors = [
                "span.sc-eDvSVe",
                "h4.sc-eDvSVe",
                "span[data-testid='product-discount-price']"
            ]
            price_text = None
            for selector in price_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        price_text = elements[0].text
                        break
                except:
                    continue
            
            return product_name, self._normalize_price(price_text or "Price not found")
        except Exception as e:
            return f"Error extracting Meesho data: {str(e)}", "Not available"

    def _get_domain_name(self, url):
        """Extract domain from URL"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Handle common variations
        for site in ['amazon', 'flipkart', 'meesho']:
            if site in domain:
                return site
        return domain

    def _fetch_static_page(self, url):
        """Fetch and parse static HTML pages"""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return BeautifulSoup(response.text, 'html.parser')
        except requests.exceptions.RequestException as e:
            print(f"Error fetching static page: {str(e)}")
            return None

    def _fetch_dynamic_page(self, url):
        """Fetch JavaScript-rendered pages using Selenium"""
        driver = None
        try:
            driver = webdriver.Chrome(options=self.chrome_options)
            driver.get(url)
            
            # Wait for page to load
            time.sleep(3)
            
            # Get page source after JavaScript execution
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            return soup, driver
        except WebDriverException as e:
            print(f"Error with Selenium browser: {str(e)}")
            if driver:
                driver.quit()
            return None, None

    def get_product_details(self, url):
        """Main method to get product details from any supported site"""
        domain = self._get_domain_name(url)
        
        if self._needs_javascript(domain):
            # Fetch with Selenium for JavaScript-rendered pages
            soup, driver = self._fetch_dynamic_page(url)
            if not soup:
                return "Failed to load page", "Not available"
                
            try:
                # Find appropriate handler or use generic
                handler = None
                for site_domain, site_handler in self.site_handlers.items():
                    if site_domain in domain:
                        handler = site_handler
                        break
                
                if handler:
                    product_name, price = handler(soup, driver)
                else:
                    # Generic extraction for unsupported sites
                    product_name = self._generic_extract_name(soup, driver)
                    price = self._generic_extract_price(soup, driver)
                    
                return product_name, price
            finally:
                if driver:
                    driver.quit()
        else:
            # Use requests + BeautifulSoup for static pages
            soup = self._fetch_static_page(url)
            if not soup:
                return "Failed to load page", "Not available"
                
            # Use the appropriate handler
            handler = self.site_handlers.get(domain)
            if handler:
                return handler(soup)
            else:
                # Generic extraction as fallback
                return self._generic_extract_name(soup), self._generic_extract_price(soup)

    def _generic_extract_name(self, soup, driver=None):
        """Generic product name extraction for unsupported sites"""
        if driver:
            # Try common selectors with Selenium
            name_selectors = [
                "h1", 
                'h1[class*="title"]', 
                'h1[class*="product"]',
                'div[class*="title"]',
                'span[class*="title"]'
            ]
            
            for selector in name_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        return elements[0].text.strip()
                except:
                    continue
                    
            # If we still don't have a name, try the page title
            return driver.title
        else:
            # Try with BeautifulSoup
            name_element = soup.select_one("h1")
            if name_element:
                return name_element.text.strip()
            return "Product name not found"

    def _generic_extract_price(self, soup, driver=None):
        """Generic price extraction for unsupported sites"""
        price_pattern = r'[\₹\$\€\£\¥]?\s*[0-9,]+\.?[0-9]*'
        
        if driver:
            # Try common price selectors with Selenium
            price_selectors = [
                'span[class*="price"]', 
                'div[class*="price"]',
                'p[class*="price"]',
                'span[data-price]',
                '*[itemprop="price"]'
            ]
            
            for selector in price_selectors:
                try:
                    elements = driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        price_text = elements[0].text
                        return self._normalize_price(price_text)
                except:
                    continue
        else:
            # Try with BeautifulSoup
            price_elements = soup.select('span[class*="price"], div[class*="price"], p[class*="price"]')
            if price_elements:
                return self._normalize_price(price_elements[0].text)
                
        return "Price not found"


def main():
    parser = argparse.ArgumentParser(description='E-commerce Price Tracker')
    parser.add_argument('url', help='URL of the product page to track')
    args = parser.parse_args()
    
    tracker = PriceTracker(headless=True)
    
    try:
        print(f"Fetching details for: {args.url}")
        product_name, price = tracker.get_product_details(args.url)
        print(f"Product Name: {product_name}\nPrice: {price}")
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()