import traceback

from geofront.server import app


@app.errorhandler(400)
def bad_request_handler_for_testing(exception: Exception):
    """Custom error handler of :http:statuscode:`400` for unit testing
    to know how it's going in the application.

    """
    traceback.print_exc(exception)
    return (
        traceback.format_exc(exception),
        400,
        {'Content-Type': 'text/plain; charset=utf-8'}
    )


@app.errorhandler(500)
def server_error_handler_for_testing(exception: Exception):
    """Custom error handler of :http:statuscode:`500` for unit testing
    to know how it's going in the application.

    """
    traceback.print_exc(exception)
    return (
        traceback.format_exc(exception),
        500,
        {'Content-Type': 'text/plain; charset=utf-8'}
    )


app.config['TESTING'] = True

# Set app.secret_key for functional testing of web app.
app.secret_key = 'test'
