def prepare_from_django_request(request):
    return {
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'server_port': 443 if request.is_secure() else 80,
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy()
    }