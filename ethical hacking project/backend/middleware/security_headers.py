def add_security_headers(response):
    """
    Applies enterprise defense-in-depth HTTP security headers to all responses.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-Security-Engine'] = 'SentinelShield-Adaptive-2.4'
    return response

