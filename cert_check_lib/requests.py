import requests
from requests import exceptions as requests_exceptions
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class RequestsSession:
    @staticmethod
    def get_requests_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504), session=None):
        session = session or requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        return session


    @staticmethod
    def get_issuer_cert_synchronous(ca_issuer_url, timeout):
        session = RequestsSession.get_requests_retry_session(retries=2)
        try:
            response = session.get(ca_issuer_url, timeout=timeout)
            response.raise_for_status()
        except requests_exceptions.HTTPError as exc:
            if exc.response.status_code not in [404, 500]:
                raise
            return None
        except requests_exceptions.ConnectTimeout:
            return None
        except requests_exceptions.InvalidSchema:
            # Example: ldap://
            return None
        except requests_exceptions.SSLError:
            # Weird ones.
            # Serving issuer certificate via HTTPS is.... stupid.
            return None
        except requests_exceptions.ConnectionError:
            return None

        return response

    @staticmethod
    def post_ocsp_request_synchronous(session, url, headers, ocsp_request, timeout):
        response = None
        should_retry = None
        try:
            response = session.post(url, headers=headers, data=ocsp_request, timeout=timeout)
            response.raise_for_status()
            should_retry = False
        except requests_exceptions.ConnectTimeout:
            should_retry = False
        except requests_exceptions.ConnectionError:
            # Go another round after bit of a cooldown
            should_retry = True
        except requests_exceptions.HTTPError as exc:
            # Different OCSP-servers respond with different HTTP-status codes.
            # Especially Let's Encrypt reponds with a wide variety of HTTP/5xx.
            # Global Sign OCSP will spew out HTTP/522
            if exc.response.status_code != 404 and exc.response.status_code < 500:
                raise

            # Go another round after bit of a cooldown
            should_retry = True
        except requests_exceptions.ReadTimeout:
            # Go another round after bit of a cooldown
            should_retry = True

        return response, should_retry