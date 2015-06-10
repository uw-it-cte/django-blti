from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.cache import never_cache
from blti import BLTI, BLTIException
import json
import re


class RESTDispatchAuthorization(Exception): pass
class RESTDispatchMethod(Exception): pass


class RESTDispatch(object):
    """ A superclass for views, that handles passing on the request to the
        appropriate view method, based on the request method.
    """
    @never_cache
    def run(self, *args, **named_args):
        try:
            request = args[0]
            self.authorize(request)
            return self.dispatch(request.method)(*args, **named_args)
        except RESTDispatchAuthorization as ex:
            return self.error_response(401, "%s" % ex)
        except RESTDispatchMethod:
            return self.invalid_method_response(*args, **named_args)

    def authorize(self, request):
        self.blti_authorize(request)

    def blti_authorize(self, request):
        try:
            BLTI().get_session(request)
        except BLTIException as ex:
            if not (getattr(settings, 'BLTI_NO_AUTH', False) and
                    request.user.is_authenticated()):
                raise RESTDispatchAuthorization('%s' % ex)

    def dispatch(self, method):
        methods = dict((m,m) for m in ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH'])
        try:
            return getattr(self, methods[method])
        except (KeyError, AttributeError):
            raise RESTDispatchMethod()

    def invalid_method_response(self, *args, **named_args):
        return HttpResponse('Method not allowed', status=405)

    def error_response(self, status, message='', content={}):
        content['error'] = message
        return HttpResponse(json.dumps(content),
                            status=status,
                            content_type='application/json')

    def json_response(self, content='', status=200):
        return HttpResponse(json.dumps(content),
                            status=status,
                            content_type='application/json')
