
async def list_services(app):
    """ List all services available on this node. """
    return app.health.items()
