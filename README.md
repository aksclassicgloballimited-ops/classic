@@ -0,0 +1,439 @@
#!/usr/bin/env python3
"""
cpycoop_api_tester.py

Improved integration test harness for CPY Cooperative API with savings, loans, and document upload tests.

Usage:
    python cpycoop_api_tester.py                # uses default base URL
    python cpycoop_api_tester.py --base-url https://example.com

Notes:
 - Adjust expected status codes or endpoints to match your API.
 - Replace the temporary admin-creation flow with a real admin or seeded credentials.
"""

from __future__ import annotations
import argparse
import requests
import sys
import uuid
import io
from datetime import datetime
from typing import Tuple, Dict, Any, Optional, Union, Iterable, List

DEFAULT_BASE_URL = "https://prosper-coop.preview.emergentagent.com"


class CPYCoopAPITester:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, request_timeout: int = 12) -> None:
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.member_token: Optional[str] = None
        self.admin_token: Optional[str] = None
        self.test_member_id: Optional[str] = None
        self.test_admin_id: Optional[str] = None
        self.test_loan_id: Optional[str] = None

        # Store created emails for potential cleanup/logging
        self.test_member_email: Optional[str] = None
        self.test_admin_email: Optional[str] = None

        self.tests_run = 0
        self.tests_passed = 0
        self.failed_tests: List[str] = []

        # Configurable constants
        self.test_password = "TestPass123!2026"
        self.request_timeout = request_timeout

    # -------------------------
    # Utilities / Logging
    # -------------------------
    def log_test(self, name: str, success: bool, details: str = "") -> None:
        """Log test results in a clean way"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"  ✅ {name}")
        else:
            msg = details if details else "Failed"
            print(f"  ❌ {name} - {msg}")
            self.failed_tests.append(f"{name}: {msg}")

    def _generate_test_email(self, prefix: str = "test") -> str:
        """Generate a unique email with low collision risk"""
        short_uuid = uuid.uuid4().hex[:8]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"{prefix}.{timestamp}.{short_uuid}@test.cpycoop.local"

    def _phone_tail(self) -> str:
        """Return a stable 4-digit tail for phone numbers using uuid4"""
        return uuid.uuid4().hex[-4:].upper()

    # -------------------------
    # HTTP wrapper
    # -------------------------
    def run_test(
        self,
        name: str,
        method: str,
        endpoint: str,
        expected_status: Union[int, Iterable[int]],
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = True,
    ) -> Tuple[bool, Any]:
        """
        Generic API call wrapper with better error handling.

        expected_status may be an int or iterable of ints (e.g., (200, 201)).
        Returns (success, parsed_json_or_text_or_response).
        """
        url = f"{self.base_url}/api/{endpoint.lstrip('/') }"
        method = method.upper()
        expected = {expected_status} if isinstance(expected_status, int) else set(expected_status)

        # Default headers only when not uploading files (requests will set multipart content-type)
        default_headers = {}
        if headers:
            default_headers.update(headers)

        try:
            resp = None
            if method == 'GET':
                resp = self.session.get(url, headers=default_headers, params=params, timeout=self.request_timeout, allow_redirects=allow_redirects)
            elif method == 'POST':
                if files:
                    # don't set Content-Type for multipart/form-data; requests handles it
                    resp = self.session.post(url, data=data or {}, files=files, headers=default_headers, timeout=self.request_timeout)
                else:
                    default_headers.setdefault('Content-Type', 'application/json')
                    resp = self.session.post(url, json=data or {}, headers=default_headers, timeout=self.request_timeout)
            elif method == 'PUT':
                default_headers.setdefault('Content-Type', 'application/json')
                resp = self.session.put(url, json=data or {}, headers=default_headers, timeout=self.request_timeout)
            elif method == 'DELETE':
                resp = self.session.delete(url, headers=default_headers, timeout=self.request_timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")

            # If we got a response, evaluate status
            if resp is None:
                self.log_test(name, False, "No response object created")
                return False, {}

            if resp.status_code in expected:
                # success: try parse json, otherwise return text
                try:
                    parsed = resp.json()
                except Exception:
                    parsed = resp.text
                self.log_test(name, True)
                return True, parsed
            else:
                # attempt to include useful body in message
                body_preview = ""
                try:
                    body = resp.json()
                    body_preview = str(body)
                except Exception:
                    body_preview = resp.text[:1000]  # limit size

                error_detail = f"Expected {sorted(expected)}, got {resp.status_code} | {body_preview}"
                self.log_test(name, False, error_detail)
                return False, {"status_code": resp.status_code, "body": body_preview}
        except requests.Timeout:
            self.log_test(name, False, "Request timed out")
            return False, {}
        except Exception as e:
            self.log_test(name, False, f"Exception: {str(e)}")
            return False, {}

    # -------------------------
    # Tests
    # -------------------------
    def test_member_registration(self) -> bool:
        email = self._generate_test_email("member")
        test_data = {
            "email": email,
            "password": self.test_password,
            "full_name": f"Test Member {datetime.now().strftime('%H%M%S')}",
            "phone": f"+2348000{self._phone_tail()}",
            "member_id": f"TST-M-{uuid.uuid4().hex[:6].upper()}"
        }

        success, response = self.run_test(
            "Member Registration",
            "POST",
            "auth/register",
            (200, 201),
            data=test_data
        )

        if success and isinstance(response, dict) and 'token' in response and 'user' in response:
            self.test_member_email = email
            self.member_token = response['token']
            self.test_member_id = response.get('user', {}).get('id')
            return True
        return False

    def test_admin_creation(self) -> bool:
        """
        Temporary admin creation flow. Replace with a seeded admin or promotion flow.
        """
        email = self._generate_test_email("admin")
        test_data = {
            "email": email,
            "password": self.test_password,
            "full_name": f"Test Admin {datetime.now().strftime('%H%M%S')}",
            "phone": f"+2349000{self._phone_tail()}"
        }

        success, response = self.run_test(
            "Admin Registration (temporary)",
            "POST",
            "auth/register",
            (200, 201),
            data=test_data
        )

        if success and isinstance(response, dict) and 'token' in response:
            self.test_admin_email = email
            self.admin_token = response['token']
            self.test_admin_id = response.get('user', {}).get('id')
            print("  ⚠️  Warning: Using regular user as admin - replace with real admin setup!")
            return True
        return False

    def test_member_login(self) -> bool:
        if not self.test_member_email:
            self.log_test("Member Login", False, "No member email available - registration failed?")
            return False

        login_data = {
            "email": self.test_member_email,
            "password": self.test_password
        }

        success, _ = self.run_test(
            "Member Login",
            "POST",
            "auth/login",
            200,
            data=login_data
        )
        return success

    def test_dashboard_stats(self) -> bool:
        if not self.member_token:
            self.log_test("Dashboard Stats", False, "No member token available")
            return False

        headers = {'Authorization': f'Bearer {self.member_token}'}
        success, response = self.run_test(
            "Dashboard Stats",
            "GET",
            "dashboard/stats",
            200,
            headers=headers
        )

        if success and isinstance(response, dict):
            required = ['total_savings', 'active_loans', 'pending_applications', 'total_loan_amount']
            all_ok = True
            for field in required:
                if field not in response:
                    self.log_test(f"Dashboard Stats - {field}", False, "Missing required field")
                    all_ok = False
                else:
                    self.log_test(f"Dashboard Stats - {field}", True)
            return all_ok
        return False

    def test_savings_operations(self) -> bool:
        """
        Tests deposit and balance retrieval for savings.
        """
        if not self.member_token:
            self.log_test("Savings Operations", False, "No member token")
            return False

        headers = {'Authorization': f'Bearer {self.member_token}'}

        # 1) Deposit
        deposit_data = {"amount": 500.0, "narration": "Test deposit"}
        success, resp = self.run_test("Savings - Deposit", "POST", "savings/deposit", (200, 201), data=deposit_data, headers=headers)
        deposit_ok = False
        if success and isinstance(resp, dict):
            if 'transaction_id' in resp or 'id' in resp:
                deposit_ok = True
            elif 'balance' in resp:
                deposit_ok = True
        if not deposit_ok:
            # already logged by run_test
            pass

        # 2) Get balance
        success, resp = self.run_test("Savings - Balance", "GET", "savings/balance", 200, headers=headers)
        balance_ok = False
        if success and isinstance(resp, dict) and ('balance' in resp or 'total' in resp):
            balance_ok = True
        return deposit_ok and balance_ok

    def test_loan_application(self) -> bool:
        """
        Test applying for a loan as a member and (optionally) approving as admin.
        """
        if not self.member_token:
            self.log_test("Loan Application", False, "No member token")
            return False

        headers = {'Authorization': f'Bearer {self.member_token}'}
        apply_data = {
            "amount": 1000.0,
            "term_months": 6,
            "reason": "Integration test loan"
        }

        success, resp = self.run_test("Loan - Apply", "POST", "loans/apply", (200, 201), data=apply_data, headers=headers)
        applied = False
        loan_id = None
        if success and isinstance(resp, dict):
            loan_id = resp.get('loan_id') or resp.get('application_id') or resp.get('id')
            if loan_id:
                applied = True
                self.test_loan_id = loan_id

        # Try to fetch member loans
        success, resp = self.run_test("Loan - List (member)", "GET", "loans", 200, headers=headers)
        list_ok = False
        if success:
            # Accept list or dict
            if isinstance(resp, list) or (isinstance(resp, dict) and ('loans' in resp or 'data' in resp)):
                list_ok = True

        # If we have an admin token and a loan_id, attempt approval (tolerant)
        approve_ok = True
        if self.admin_token and loan_id:
            admin_headers = {'Authorization': f'Bearer {self.admin_token}'}
            tried = []
            # Try common admin approval endpoints/patterns
            candidates = [f"admin/loans/{loan_id}/approve", f"admin/loans/{loan_id}/actions/approve", "admin/loans/approve"]
            approve_ok = False
            for ep in candidates:
                # some endpoints expect POST with loan_id in body
                data = {} if ep.endswith('/approve') and 'admin/loans/approve' not in ep else {"loan_id": loan_id}
                success, _ = self.run_test(f"Admin - Approve Loan ({ep})", "POST", ep, (200, 204), data=data, headers=admin_headers)
                tried.append((ep, success))
                if success:
                    approve_ok = True
                    break
            if not approve_ok:
                # already logged failures; continue
                pass

        return applied and list_ok and approve_ok

    def test_document_upload(self) -> bool:
        """
        Upload a small document file as a member.
        """
        if not self.member_token:
            self.log_test("Document Upload", False, "No member token")
            return False

        headers = {'Authorization': f'Bearer {self.member_token}'}

        # Create a small in-memory file
        file_content = b"Integration test document" 
        file_obj = io.BytesIO(file_content)
        file_obj.name = 'test_document.txt'

        files = {'file': ('test_document.txt', file_obj, 'text/plain')}

        # Try plausible endpoints
        candidates = ["documents/upload", "members/documents", "members/documents/upload"]
        uploaded = False
        for ep in candidates:
            success, resp = self.run_test(f"Document Upload ({ep})", "POST", ep, (200, 201), headers=headers, files=files)
            # requests will have consumed the file-like; recreate for next attempt if needed
            file_obj.seek(0)
            files = {'file': ('test_document.txt', file_obj, 'text/plain')}
            if success and isinstance(resp, dict):
                if 'document_id' in resp or 'id' in resp:
                    uploaded = True
                    break
        return uploaded

    def test_admin_endpoints(self) -> bool:
        """
        Basic admin endpoints check — safe and tolerant. Adjust endpoint paths to match your API.
        If admin token isn't available we skip with a warning.
        """
        if not self.admin_token:
            self.log_test("Admin Endpoints", False, "No admin token available")
            return False

        headers = {'Authorization': f'Bearer {self.admin_token}'}
        # Example admin endpoint — adapt to your API. We'll try a couple of common ones.
        endpoints = [
            ("Admin - List Users", "admin/users"),
            ("Admin - Dashboard", "admin/dashboard"),
        ]

        all_ok = True
        for name, endpoint in endpoints:
            success, _ = self.run_test(name, "GET", endpoint, (200, 204), headers=headers)
            if not success:
                # keep going but mark overall as failed
                all_ok = False

        return all_ok

    # -------------------------
    # Orchestration
    # -------------------------
    def run_all_tests(self) -> bool:
        print("\n" + "═" * 70)
        print("🚀 CPY Cooperative API Integration Tests - 2026 Edition (with savings, loans, docs)")
        print("═" * 70)

        print("\n📝 Phase 1: Authentication")
        self.test_member_registration()
        self.test_admin_creation()
        self.test_member_login()

        print("\n👤 Phase 2: Member Features")
        self.test_dashboard_stats()
        self.test_savings_operations()
        self.test_loan_application()
        self.test_document_upload()

        print("\n👮 Phase 3: Admin Features")
        self.test_admin_endpoints()

        print("\n" + "═" * 70)
        print(f"Final result: {self.tests_passed}/{self.tests_run} tests passed")
        if self.failed_tests:
            print("\nFailed tests:")
            for fail in self.failed_tests:
                print(f"  • {fail}")

        return self.tests_passed == self.tests_run


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="cpycoop_api_tester")
    parser.add_argument("--base-url", "-b", default=DEFAULT_BASE_URL, help="API base URL (default from script)")
    args = parser.parse_args(argv)

    tester = CPYCoopAPITester(base_url=args.base_url)
    success = tester.run_all_tests()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
