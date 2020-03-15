import aiohttp
import asyncio
from urllib.parse import urlparse
from aiohttp import ClientConnectorError
import socket


class RequestsSession:

    @staticmethod
    def get_requests_retry_session(retries, loop):
        timeout = aiohttp.ClientTimeout(total=600)
        session = aiohttp.ClientSession(timeout=timeout, loop=loop, raise_for_status=True)

        return session

    @staticmethod
    async def get_issuer_cert_async(loop, ca_issuer_url, timeout):
        o = urlparse(ca_issuer_url)
        if not o.scheme in ['http', 'https']:
            return None, None

        try:
            async with RequestsSession.get_requests_retry_session(retries=2, loop=loop) as session:
                async with session.get(ca_issuer_url) as response:
                    return response, await response.read()
        except (aiohttp.ClientError, ClientConnectorError, socket.gaierror):
            return None, None
        except asyncio.TimeoutError:
            return None, None

    @staticmethod
    async def post_ocsp_request_async(loop, url, headers, ocsp_request, timeout):
        o = urlparse(url)
        if not o.scheme in ['http', 'https']:
            return False, None, None

        response = None
        should_retry = None
        async with RequestsSession.get_requests_retry_session(retries=2, loop=loop) as session:
            try:
                async with session.post(url, headers=headers, data=ocsp_request, timeout=timeout) as response:
                    return False, response, await response.read()
            except (aiohttp.ClientError, ClientConnectorError, socket.gaierror) as exc:
                should_retry = False
                await session.close()
            except asyncio.TimeoutError as exc:
                should_retry = False
                await session.close()

        return should_retry, None, None
