"""Built-in OctopusJar security checks."""

from .cors import CorsCheck
from .headers import SecurityHeadersCheck
from .information_disclosure import InformationDisclosureCheck
from .methods import HttpMethodsCheck
from .redirects import RedirectsCheck

DEFAULT_CHECKS = (
    SecurityHeadersCheck,
    CorsCheck,
    HttpMethodsCheck,
    InformationDisclosureCheck,
    RedirectsCheck,
)

__all__ = [
    "CorsCheck",
    "SecurityHeadersCheck",
    "InformationDisclosureCheck",
    "HttpMethodsCheck",
    "RedirectsCheck",
    "DEFAULT_CHECKS",
]
