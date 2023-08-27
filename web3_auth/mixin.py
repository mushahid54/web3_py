__author__ = 'MushahidKhan'


from collections import OrderedDict
from django.http.response import HttpResponseBase
from rest_framework.response import Response


class CustomMetaDataMixin(object):
    """
    When you Inherit from this Mixin, remember to keep it to the left of any ApiView subclass,
    else this mixin's finalize_response() method won't override ApiView's

    Created by Mushahid on 12/05/2023
    """

    def finalize_response(self, request, response, *args, **kwargs):
        """
        Returns the final response object.
        """
        # Make the error obvious if a proper response is not returned
        assert isinstance(response, HttpResponseBase), (
            'Expected a `Response`, `HttpResponse` or `HttpStreamingResponse` '
            'to be returned from the view, but received a `%s`'
            % type(response)
        )

        if isinstance(response, Response):
            if not getattr(request, 'accepted_renderer', None):
                neg = self.perform_content_negotiation(request, force=True)
                request.accepted_renderer, request.accepted_media_type = neg

            response.accepted_renderer = request.accepted_renderer
            response.accepted_media_type = request.accepted_media_type
            response.renderer_context = self.get_renderer_context()

        for key, value in self.headers.items():
            response[key] = value

        response = self.envelope_response(request, response)
        return response

    def envelope_response(self, request, response):
        if not response.exception:

            if response.data and 'meta' in response.data:
                response.data['meta'].update(self.get_response_meta(request, response))
                response_meta = response.data['meta']

                response_data = response.data['data']
            else:
                response_meta = self.get_response_meta(request, response)
                response_data = response.data

            if 'pay-using-card' in request._request.path and response_data == {}:
                response_data = {}
            elif not response_data:
                response_data = []
            elif response_data == {}:
                response_data = {}
            else:
                pass

            envelope = OrderedDict([('meta', response_meta), ('data', response_data)])
            response.data = envelope
        # response.data['meta']['header_sent'] = self.request.META.get('HTTP_AUTHORIZATION', None)
        return response

    def get_response_meta(self, request, response):
        """
        Override this method in your views
        :param request:
        :param response:
        :return:
        """
        response_meta = {
            "status": 1000,
            "is_error": True if response.exception else False,
            "message": ""
        }
        return response_meta