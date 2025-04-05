import os
import re
import json
import shutil
import pandas as pd
import pytesseract
import pdfplumber
from PIL import Image

# Optional: Set Tesseract path if necessary.
# pytesseract.pytesseract.tesseract_cmd = r'/usr/bin/tesseract'

# ---------------------------
# Core Classes
# ---------------------------
class PDFProcessor:
    """Processes PDF files using pdfplumber with OCR fallback."""
    def process(self, file_path):
        text = ""
        try:
            with pdfplumber.open(file_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
        except Exception as e:
            print(f"Error reading PDF {file_path}: {e}")
        
        # Fallback to OCR if text seems too short.
        if len(text.strip()) < 50:
            print(f"Low text extraction for {file_path}, using OCR fallback.")
            text = self.ocr_pdf(file_path)
        return text

    def ocr_pdf(self, file_path):
        """Converts PDF pages to images and extracts text via OCR."""
        text = ""
        try:
            from pdf2image import convert_from_path
            pages = convert_from_path(file_path)
            for page in pages:
                page_text = pytesseract.image_to_string(page)
                text += page_text + "\n"
        except Exception as e:
            print(f"OCR failed for {file_path}: {e}")
        return text

class DataExtractor:
    """Extracts invoice fields from raw text using regular expressions."""
    def extract_fields(self, text):
        invoice = {
            "vendor_name": None,
            "bill_number": None,
            "billing_date": None,
            "due_date": None,
            "total_amount": None,
            "line_items": []  # Each line item: {"description": str, "quantity": int, "unit_price": float, "total_price": float}
        }
        
        # Extract main fields based on labels.
        vendor_match = re.search(r"Vendor Name:\s*(.+)", text, re.IGNORECASE)
        bill_match = re.search(r"Bill Number:\s*(\S+)", text, re.IGNORECASE)
        billing_date_match = re.search(r"Billing Date:\s*([\d/.-]+)", text, re.IGNORECASE)
        due_date_match = re.search(r"Due Date:\s*([\d/.-]+)", text, re.IGNORECASE)
        total_match = re.search(r"Total Amount:\s*\$?([\d,]+(?:\.\d{2})?)", text, re.IGNORECASE)
        
        invoice["vendor_name"] = vendor_match.group(1).strip() if vendor_match else None
        invoice["bill_number"] = bill_match.group(1).strip() if bill_match else None
        invoice["billing_date"] = billing_date_match.group(1).strip() if billing_date_match else None
        invoice["due_date"] = due_date_match.group(1).strip() if due_date_match else None
        invoice["total_amount"] = float(total_match.group(1).replace(",", "")) if total_match else None
        
        # Extract line items:
        # Process the text line by line and try to capture description, quantity, unit price, total price.
        # This regex expects:
        #  - description (any text until whitespace and quantity)
        #  - quantity (an integer)
        #  - unit price (a number, with optional commas/decimals)
        #  - total price (a number, with optional commas/decimals)
        line_item_pattern = re.compile(
            r"^(.*?)\s+(\d+)\s+\$?([\d,]+(?:\.\d{2})?)\s+\$?([\d,]+(?:\.\d{2})?)\s*$"
        )
        
        lines = text.splitlines()
        for line in lines:
            # Skip common header lines
            if re.search(r"(Item Description|Quantity|Unit Price|Total Price)", line, re.IGNORECASE):
                continue
            match = line_item_pattern.match(line.strip())
            if match:
                description = match.group(1).strip()
                try:
                    quantity = int(match.group(2))
                    unit_price = float(match.group(3).replace(",", ""))
                    total_price = float(match.group(4).replace(",", ""))
                except Exception as e:
                    continue  # Skip if conversion fails
                invoice["line_items"].append({
                    "description": description,
                    "quantity": quantity,
                    "unit_price": unit_price,
                    "total_price": total_price
                })
        return invoice

class DataValidator:
    """Validates that critical fields are present and totals are consistent."""
    def validate(self, data):
        missing_fields = []
        for field in ['vendor_name', 'bill_number', 'billing_date', 'due_date', 'total_amount']:
            if not data.get(field):
                missing_fields.append(field)
                
        result = {"is_valid": True, "missing_fields": missing_fields, "error": None}
        
        if missing_fields:
            result["is_valid"] = False
            result["error"] = "Missing critical fields."
        else:
            # Validate that the sum of line item total_prices equals the total amount (if any line items exist)
            if data["line_items"]:
                sum_line_items = sum(item["total_price"] for item in data["line_items"])
                if abs(sum_line_items - data["total_amount"]) > 0.01:
                    result["is_valid"] = False
                    result["error"] = f"Total amount mismatch: expected {data['total_amount']}, got sum {sum_line_items}."
        return result

class DuplicateChecker:
    """Checks for duplicates using a JSON file as a simple database."""
    def __init__(self, db_path):
        self.db_path = db_path
        if os.path.exists(self.db_path):
            with open(self.db_path, "r") as f:
                self.db = json.load(f)
        else:
            self.db = {}
    
    def is_duplicate(self, vendor, bill_number):
        key = f"{vendor}_{bill_number}"
        return key in self.db

    def add_invoice(self, vendor, bill_number):
        key = f"{vendor}_{bill_number}"
        self.db[key] = True
        self._save()

    def _save(self):
        with open(self.db_path, "w") as f:
            json.dump(self.db, f, indent=2)

class AutoPaySync:
    """Main class to process invoices and output validated data."""
    def __init__(self, invoice_dir, output_csv, duplicate_db="duplicates.json"):
        self.invoice_dir = invoice_dir
        self.output_csv = output_csv
        self.pdf_processor = PDFProcessor()
        self.data_extractor = DataExtractor()
        self.data_validator = DataValidator()
        self.duplicate_checker = DuplicateChecker(duplicate_db)
        self.processed_invoices = []

    def process_invoices(self):
        for filename in os.listdir(self.invoice_dir):
            file_path = os.path.join(self.invoice_dir, filename)
            print(f"\nProcessing {file_path}...")
            if filename.lower().endswith(".pdf"):
                text = self.pdf_processor.process(file_path)
            else:
                print(f"Unsupported file format for {filename}. Skipping.")
                continue

            if not text:
                print(f"No text extracted from {filename}. Skipping.")
                continue

            data = self.data_extractor.extract_fields(text)
            validation = self.data_validator.validate(data)
            if not validation["is_valid"]:
                print(f"Validation failed for {filename}: {validation['error']}")
                if validation.get("missing_fields"):
                    print(f"Missing fields: {validation['missing_fields']}")
                continue

            # Duplicate check
            vendor = data["vendor_name"]
            bill_number = data["bill_number"]
            if self.duplicate_checker.is_duplicate(vendor, bill_number):
                print(f"Duplicate invoice detected for {vendor} {bill_number}. Skipping.")
                continue

            self.duplicate_checker.add_invoice(vendor, bill_number)
            self.processed_invoices.append({"filename": filename, **data})
            print(f"Invoice {filename} processed successfully.")
        self._write_csv()

    def _write_csv(self):
        if self.processed_invoices:
            # Flatten line items into a single string for CSV output.
            for invoice in self.processed_invoices:
                if invoice.get("line_items"):
                    # Format each line item as: description (quantity x unit_price = total_price)
                    invoice["line_items"] = "; ".join(
                        [f"{item['description']} ({item['quantity']} x ${item['unit_price']:.2f} = ${item['total_price']:.2f})"
                         for item in invoice["line_items"]]
                    )
                else:
                    invoice["line_items"] = ""
            df = pd.DataFrame(self.processed_invoices)
            df.to_csv(self.output_csv, index=False)
            print(f"\nProcessed {len(self.processed_invoices)} invoices. Output written to {self.output_csv}.")
        else:
            print("\nNo valid invoices processed.")

# ---------------------------
# Test Functions
# ---------------------------
def setup_test_environment():
    """Set up test directories and copy sample bill files."""
    os.makedirs("test_output", exist_ok=True)
    os.makedirs("test_bills", exist_ok=True)
    
    source_dir = "invoices"
    if os.path.exists(source_dir):
        for file in os.listdir(source_dir):
            shutil.copy(os.path.join(source_dir, file), "test_bills")
        print("Test environment set up with sample bills.")
    else:
        print("Source invoices folder not found. Please create an 'invoices' folder with sample bills.")

def test_case_1_data_extraction_accuracy():
    """Test Case 1: Verify that all required fields are extracted from a well-formatted PDF invoice."""
    print("\n=== Running Test Case 1: Data Extraction Accuracy ===")
    pdf_processor = PDFProcessor()
    data_extractor = DataExtractor()
    
    test_file = "test_bills/Bill_1.pdf"
    if not os.path.exists(test_file):
        print(f"Test file {test_file} not found. Simulation only.")
        return

    extracted_text = pdf_processor.process(test_file)
    if extracted_text:
        data = data_extractor.extract_fields(extracted_text)
        required_fields = ['vendor_name', 'bill_number', 'billing_date', 'due_date', 'total_amount']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if not missing_fields:
            print("✓ All required fields successfully extracted:")
            for field in required_fields:
                print(f"  - {field}: {data.get(field)}")
            print(f"  - Line items extracted: {len(data.get('line_items', []))}")
        else:
            print(f"✗ Missing fields: {missing_fields}")
    else:
        print("Failed to extract text from the test file.")

def test_case_2_missing_fields():
    """Test Case 2: Ensure that invoices with missing critical fields are flagged."""
    print("\n=== Running Test Case 2: Missing Fields Validation ===")
    test_data = {
        'vendor_name': 'Test Vendor',
        # Intentionally missing 'bill_number'
        'billing_date': '01/01/2023',
        'due_date': '01/15/2023',
        'total_amount': 150.00,
        'line_items': [
            {'description': 'Test Item 1', 'quantity': 1, 'unit_price': 100.00, 'total_price': 100.00},
            {'description': 'Test Item 2', 'quantity': 1, 'unit_price': 50.00, 'total_price': 50.00}
        ]
    }
    validator = DataValidator()
    result = validator.validate(test_data)
    if not result['is_valid']:
        print("✓ Invoice with missing fields correctly identified as invalid.")
        print(f"  Missing fields: {result['missing_fields']}")
    else:
        print("✗ Invoice with missing fields was not flagged.")

def test_case_3_duplicate_detection():
    """Test Case 3: Confirm that duplicate invoices are not processed."""
    print("\n=== Running Test Case 3: Duplicate Bill Detection ===")
    test_db = "test_duplicates.json"
    if os.path.exists(test_db):
        os.remove(test_db)
    
    duplicate_checker = DuplicateChecker(test_db)
    original_bill = {
        'vendor_name': 'Acme Corp',
        'bill_number': 'INV-12345',
        'billing_date': '02/15/2023',
        'due_date': '03/15/2023',
        'total_amount': 500.00
    }
    if duplicate_checker.is_duplicate(original_bill['vendor_name'], original_bill['bill_number']):
        print("✗ Duplicate found unexpectedly.")
    else:
        duplicate_checker.add_invoice(original_bill['vendor_name'], original_bill['bill_number'])
        print("✓ Original invoice processed.")
    
    duplicate_bill = {
        'vendor_name': 'Acme Corp',
        'bill_number': 'INV-12345',  # Duplicate
        'billing_date': '02/16/2023',
        'due_date': '03/16/2023',
        'total_amount': 500.00
    }
    if duplicate_checker.is_duplicate(duplicate_bill['vendor_name'], duplicate_bill['bill_number']):
        print("✓ Duplicate invoice correctly detected.")
    else:
        print("✗ Duplicate invoice was not detected.")

# ---------------------------
# Main Execution
# ---------------------------
if __name__ == "__main__":
    # Set up test environment
    setup_test_environment()
    
    # Run test cases
    test_case_1_data_extraction_accuracy()
    test_case_2_missing_fields()
    test_case_3_duplicate_detection()
    
    # Process all invoices in the test_bills folder using AutoPaySync
    print("\n=== Running AutoPaySync on Test Bills ===")
    autopay = AutoPaySync(invoice_dir="test_bills", output_csv="test_output/processed_invoices.csv", duplicate_db="test_duplicates.json")
    autopay.process_invoices()
